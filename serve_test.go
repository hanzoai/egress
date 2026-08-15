package egress

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hanzoai/jwt"
	"github.com/zap-proto/zip"
)

// serving builds the whole service over a store a test controls, with a real
// issuer publishing a real key set over a real HTTP endpoint — so the gate under
// test is the one that ships, fetch included.
func serving(t *testing.T, s *store, rpm int) (*Server, jwt.Key) {
	t.Helper()
	key := issuerKey(t)
	set, err := jwt.BuildJWKS(key)
	if err != nil {
		t.Fatal(err)
	}
	keys := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(set)
	}))
	t.Cleanup(keys.Close)

	server, err := New(Config{
		Listen: ":0", Issuer: issuer, JWKS: keys.URL, Audience: audience,
		KMS: "zap://kms.invalid:9999", KMSOrg: "hanzo", KMSPath: "hanzo/egress",
		TTL: time.Minute, RPM: rpm, Deadline: 30 * time.Second,
	}, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return server, key
}

// ask drives one request through the real router.
func ask(t *testing.T, s *Server, method, path, bearer string, body any) (int, string) {
	t.Helper()
	var payload io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		payload = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, payload)
	req.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := s.App().Test(req, zip.TestConfig{Timeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp.StatusCode, string(out)
}

// call is a request the Dummy dialect answers without a network.
func call() Call {
	return Call{Provider: "Dummy", Model: "dummy", Question: "hi", Lang: "en"}
}

// TestEveryRouteRefusesAnUnidentifiedCaller is the structural check: routes are
// registered on one gated Router, so a route that forgot its gate cannot exist.
// It covers the typed ops as well as the streaming one, because the gate is
// composed around the handler rather than run from a shared stack whose order a
// later registration could get wrong.
func TestEveryRouteRefusesAnUnidentifiedCaller(t *testing.T) {
	s, _ := serving(t, newStore(nil), 100)
	for _, route := range []struct{ method, path string }{
		{http.MethodPost, "/v1/call"},
		{http.MethodPost, "/v1/enroll"},
		{http.MethodGet, "/v1/health"},
	} {
		t.Run(route.method+" "+route.path, func(t *testing.T) {
			if code, body := ask(t, s, route.method, route.path, "", call()); code != http.StatusUnauthorized {
				t.Fatalf("code = %d, want 401; body %s", code, body)
			}
		})
	}
}

func TestAnIdentifiedCallerIsServed(t *testing.T) {
	s, key := serving(t, newStore(nil), 100)
	code, body := ask(t, s, http.MethodGet, "/v1/health", token(t, key, nil), nil)
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %s", code, body)
	}
	if !strings.Contains(body, `"ready":true`) {
		t.Errorf("body = %s", body)
	}
}

func TestACallStreamsTheAnswerThenTheMeter(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "dummy", "default"): "sk-ours",
	}), 100)

	code, body := ask(t, s, http.MethodPost, "/v1/call", token(t, key, nil), call())
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %s", code, body)
	}
	if !strings.Contains(body, "event: message") {
		t.Fatalf("no answer was streamed: %s", body)
	}
	meter := lastMeter(t, body)
	if meter.Scope != ScopeOrg {
		t.Errorf("scope = %q, want %q", meter.Scope, ScopeOrg)
	}
	if meter.Provider != "Dummy" {
		t.Errorf("provider = %q", meter.Provider)
	}
	if strings.Contains(body, "sk-ours") {
		t.Fatal("the credential travelled to the caller")
	}
}

func TestACallSpendsTheTenantsOwnKeyWhenThereIsOne(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		userRef(alice, "dummy", "default"): "sk-theirs",
		orgRef(alice, "dummy", "default"):  "sk-ours",
	}), 100)

	_, body := ask(t, s, http.MethodPost, "/v1/call", token(t, key, nil), call())
	if got := lastMeter(t, body).Scope; got != ScopeUser {
		t.Errorf("scope = %q, want %q — the customer's key was not the one spent", got, ScopeUser)
	}
}

func TestACallWithNoCredentialIsRefused(t *testing.T) {
	s, key := serving(t, newStore(nil), 100)
	_, body := ask(t, s, http.MethodPost, "/v1/call", token(t, key, nil), call())
	if !strings.Contains(body, "event: error") {
		t.Fatalf("a call with no credential was not refused: %s", body)
	}
	if strings.Contains(body, "event: meter") {
		t.Fatal("something was spent without a credential")
	}
}

func TestACallCannotNameItsOwnUpstream(t *testing.T) {
	// The wire has no field for it. This pins that: a body carrying one is
	// accepted and ignored, never dialled.
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "dummy", "default"): "sk-ours",
	}), 100)

	body := map[string]any{
		"provider": "Dummy", "model": "dummy", "question": "hi",
		"providerUrl": "https://exfiltrate.example", "url": "https://exfiltrate.example",
		"org": "other", "user": "root",
	}
	code, out := ask(t, s, http.MethodPost, "/v1/call", token(t, key, nil), body)
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %s", code, out)
	}
	// The org named in the body was ignored: the credential came from acme's
	// shared path, which is the only one the token could reach.
	if got := lastMeter(t, out).Scope; got != ScopeOrg {
		t.Fatalf("scope = %q", got)
	}
}

func TestEnrollingSealsTheKeyAndAnswersWithoutIt(t *testing.T) {
	s, key := serving(t, newStore(nil), 100)
	secret := "sk-a-customers-own-key"

	code, body := ask(t, s, http.MethodPost, "/v1/enroll", token(t, key, nil),
		Enroll{Provider: "OpenAI", Key: secret})
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %s", code, body)
	}
	if strings.Contains(body, secret) {
		t.Fatalf("the key came back: %s", body)
	}
	if got := s.custody.store.(*store).at(userRef(alice, "openai", "default")); got != secret {
		t.Errorf("sealed %q at the customer's path", got)
	}
}

func TestEnrollingCannotNameAnotherTenantsPath(t *testing.T) {
	st := newStore(nil)
	s, key := serving(t, st, 100)

	for _, bad := range []Enroll{
		{Provider: "../../other", Key: "sk-x"},
		{Provider: "openai/../../other", Key: "sk-x"},
		{Provider: "OpenAI", Label: "../../other", Key: "sk-x"},
		{Provider: "OpenAI", Label: "a/b", Key: "sk-x"},
		{Provider: "", Key: "sk-x"},
		{Provider: "OpenAI", Key: ""},
	} {
		code, body := ask(t, s, http.MethodPost, "/v1/enroll", token(t, key, nil), bad)
		if code == http.StatusOK {
			t.Errorf("%+v was accepted: %s", bad, body)
		}
	}
	for ref, v := range st.held {
		if !strings.HasPrefix(ref, "orgs/acme/users/u-7/") {
			t.Errorf("a key was written outside the enroller's custody: %s = %q", ref, v)
		}
	}
}

func TestTheCeilingIsPerPrincipal(t *testing.T) {
	s, key := serving(t, newStore(nil), 2)
	mine := token(t, key, nil)
	theirs := token(t, key, func(c *jwt.Claims) { c.Owner = "other"; c.Id = "u-9" })

	for i := 0; i < 2; i++ {
		if code, body := ask(t, s, http.MethodGet, "/v1/health", mine, nil); code != http.StatusOK {
			t.Fatalf("call %d refused early: %d %s", i, code, body)
		}
	}
	if code, _ := ask(t, s, http.MethodGet, "/v1/health", mine, nil); code != http.StatusTooManyRequests {
		t.Fatalf("code = %d, want 429", code)
	}
	if code, _ := ask(t, s, http.MethodGet, "/v1/health", theirs, nil); code != http.StatusOK {
		t.Fatalf("one principal's ceiling refused another: %d", code)
	}
}

// lastMeter reads the meter frame off a call's stream.
func lastMeter(t *testing.T, body string) Meter {
	t.Helper()
	i := strings.LastIndex(body, "event: meter\ndata: ")
	if i < 0 {
		t.Fatalf("no meter frame in: %s", body)
	}
	line := body[i+len("event: meter\ndata: "):]
	if j := strings.Index(line, "\n"); j >= 0 {
		line = line[:j]
	}
	var m Meter
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("meter frame is not a meter: %v (%s)", err, line)
	}
	return m
}

// TestACallGivenUpOnDoesNotInterleaveWithItsOwnRefusal exercises the deadline.
// A dialect takes no context, so a call past its deadline is abandoned, not
// stopped, and its goroutine is still writing while this process writes the
// refusal. Under -race an unsealed stream shows that as what it is.
func TestACallGivenUpOnDoesNotInterleaveWithItsOwnRefusal(t *testing.T) {
	st := newStore(map[string]string{orgRef(alice, "dummy", "default"): "sk-ours"})
	s, key := serving(t, st, 100)
	s.cfg.Deadline = time.Millisecond

	in := call()
	in.Question = "a question long enough that the dialect is still streaming it when the deadline passes"

	code, body := ask(t, s, http.MethodPost, "/v1/call", token(t, key, nil), in)
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %s", code, body)
	}
	if !strings.Contains(body, "event: error") {
		t.Fatalf("a call past its deadline was not refused: %s", body)
	}
	if strings.Contains(body, "event: meter") {
		t.Error("an abandoned call reported a spend")
	}
	// Give the abandoned goroutine time to try to write into the sealed stream.
	time.Sleep(300 * time.Millisecond)
}
