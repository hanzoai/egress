package egress

import (
	"crypto/tls"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hanzoai/egress/spend"
	"github.com/hanzoai/jwt"
)

// upstream stands in for a cloud API. It is served over TLS, because that is
// what egress will dial and refusing anything else is a property worth keeping
// in the test rather than configuring away. Only this server's certificate is
// trusted, and nothing else about the shipped client is touched — the redirect
// policy and the nil proxy under test are the ones that ship.
func upstream(t *testing.T, s *Server, provider string, h http.HandlerFunc) *httptest.Server {
	t.Helper()
	server := httptest.NewTLSServer(h)
	t.Cleanup(server.Close)
	trust(s, server.Client().Transport.(*http.Transport).TLSClientConfig)
	if s.cfg.URLs == nil {
		s.cfg.URLs = map[string]string{}
	}
	s.cfg.URLs[provider] = server.URL
	return server
}

func trust(s *Server, cfg *tls.Config) {
	s.fetcher.Transport.(*http.Transport).TLSClientConfig = cfg
}

// fetched is one cloud call through the real router.
func fetched(t *testing.T, s *Server, key jwt.Key, in spend.Fetch) (int, string) {
	t.Helper()
	return ask(t, s, http.MethodPost, "/v1/fetch", token(t, key, nil), in)
}

// A cloud call reaches the configured upstream carrying the credential, and the
// credential does not come back.
func TestAFetchSpendsTheKeyUpstreamAndNeverReturnsIt(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 100)

	var saw string
	var method, path atomic.Value
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, r *http.Request) {
		saw = r.Header.Get("Authorization")
		method.Store(r.Method)
		path.Store(r.URL.RequestURI())
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"droplets":[]}`))
	})

	code, body := fetched(t, s, key, spend.Fetch{
		Provider: "DigitalOcean", Method: "GET", Path: "/v2/droplets?page=2",
	})
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %s", code, body)
	}
	if saw != "Bearer dop_v1_secret" {
		t.Errorf("upstream got Authorization %q — the credential was not carried", saw)
	}
	if got := method.Load(); got != "GET" {
		t.Errorf("method = %v", got)
	}
	if got := path.Load(); got != "/v2/droplets?page=2" {
		t.Errorf("path = %v — the query was lost", got)
	}
	if strings.Contains(body, "dop_v1_secret") {
		t.Fatal("the credential travelled to the caller")
	}

	var out spend.Fetched
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("answer is not a spend.Fetched: %v — %s", err, body)
	}
	if out.Status != http.StatusOK {
		t.Errorf("status = %d", out.Status)
	}
	if string(out.Body) != `{"droplets":[]}` {
		t.Errorf("body = %s", out.Body)
	}
	if out.Scope != ScopeOrg {
		t.Errorf("scope = %q", out.Scope)
	}
}

// The one that matters most: a caller cannot name the far end. Whatever it puts
// in Path, the request goes to the configured upstream or nowhere — so a caller
// that has compromised nothing but its own token still cannot have the
// credential delivered to a host it controls.
func TestAFetchCannotBeAimedAtAnotherHost(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 1000)

	var reached atomic.Bool
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		reached.Store(true)
	}))
	defer elsewhere.Close()
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	// Trust BOTH, so that if a path did escape it would succeed loudly rather
	// than be stopped by a certificate and read as if the guard had worked.
	trust(s, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test only

	for _, path := range []string{
		elsewhere.URL + "/x", // an absolute URL
		"//" + strings.TrimPrefix(elsewhere.URL, "https://") + "/x", // scheme-relative: parses as a host
		"https://evil.example/x",
		"http://evil.example/x",
		"https://user:pw@evil.example/x",
		"/\\evil.example/x",
		"v2/droplets", // not rooted at all
		"",
	} {
		t.Run(path, func(t *testing.T) {
			code, body := fetched(t, s, key, spend.Fetch{
				Provider: "DigitalOcean", Method: "GET", Path: path,
			})
			if code == http.StatusOK {
				t.Fatalf("path %q was served; body %s", path, body)
			}
			if strings.Contains(body, "dop_v1_secret") {
				t.Fatal("the credential travelled to the caller")
			}
		})
	}
	if reached.Load() {
		t.Fatal("a caller-supplied path reached a host of its own choosing WITH the credential")
	}
}

// A redirect is the other way the far end could choose the next far end.
func TestAFetchDoesNotFollowARedirect(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 100)

	var followed atomic.Bool
	elsewhere := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		followed.Store(true)
	}))
	defer elsewhere.Close()
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, elsewhere.URL+"/x", http.StatusFound)
	})
	trust(s, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test only

	code, body := fetched(t, s, key, spend.Fetch{Provider: "DigitalOcean", Method: "GET", Path: "/v2/droplets"})
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %s", code, body)
	}
	if followed.Load() {
		t.Fatal("the redirect was followed — the upstream chose where the next request went")
	}
	var out spend.Fetched
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatal(err)
	}
	if out.Status != http.StatusFound {
		t.Errorf("status = %d, want the 302 handed back as itself", out.Status)
	}
}

// A cloud egress cannot pay for is refused, not sent upstream with a header it
// will reject — and never with one it might accept.
func TestAFetchRefusesACloudItCannotCarry(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "aws", "default"): "AKIA-secret",
	}), 100)
	s.cfg.URLs = map[string]string{"aws": "https://ec2.amazonaws.com"}

	code, body := fetched(t, s, key, spend.Fetch{Provider: "AWS", Method: "GET", Path: "/"})
	if code == http.StatusOK {
		t.Fatalf("AWS was served: %s", body)
	}
	if !strings.Contains(body, "cannot be carried") {
		t.Errorf("refusal does not say why: %s", body)
	}
	if strings.Contains(body, "AKIA-secret") {
		t.Fatal("the credential travelled to the caller")
	}
}

// A cloud's address is a fact about that cloud, so egress knows it and an
// operator does not type it. Asserted on what upstream() resolves rather than by
// making a call, because the real address is a real host and a test must not
// reach one.
func TestACloudsAddressIsKnownWithoutConfiguration(t *testing.T) {
	s, _ := serving(t, newStore(nil), 100)
	if s.cfg.URLs != nil {
		t.Fatalf("this test is only meaningful with nothing configured: %v", s.cfg.URLs)
	}
	for provider, want := range map[string]string{
		"digitalocean": "https://api.digitalocean.com",
		"hetzner":      "https://api.hetzner.cloud",
	} {
		got, ok := s.upstream(clouds, provider)
		if !ok || got != want {
			t.Errorf("upstream(%q) = %q, %v; want %q", provider, got, ok, want)
		}
	}
	// And membership is the allowlist: a cloud egress cannot pay for has no
	// address here either, so there is one table and not two to disagree.
	if got, ok := s.upstream(clouds, "aws"); ok {
		t.Errorf("upstream(\"aws\") = %q — AWS signs its requests and cannot be paid with a header", got)
	}
}

// An override moves a cloud egress already carries — a regional endpoint, a
// sovereign one, a test's own server. It cannot admit a cloud that is absent,
// because the address is not what makes a cloud payable.
func TestAnOverrideMovesACloudButCannotAdmitOne(t *testing.T) {
	s, _ := serving(t, newStore(nil), 100)
	s.cfg.URLs = map[string]string{
		"digitalocean": "https://api.digitalocean.example",
		"aws":          "https://ec2.amazonaws.com",
	}
	if got, _ := s.upstream(clouds, "digitalocean"); got != "https://api.digitalocean.example" {
		t.Errorf("the override was ignored: %q", got)
	}
	if got, ok := s.upstream(clouds, "aws"); ok {
		t.Errorf("an override admitted a cloud egress cannot pay for: %q", got)
	}
}

// Absent a credential the call ends. It never falls back to this process's
// environment, which is exactly where a provider key used to live.
func TestAFetchWithNoCredentialIsRefused(t *testing.T) {
	s, key := serving(t, newStore(nil), 100)
	upstream(t, s, "digitalocean", func(http.ResponseWriter, *http.Request) {
		t.Error("an upstream call was made with no credential")
	})

	if code, body := fetched(t, s, key, spend.Fetch{
		Provider: "DigitalOcean", Method: "GET", Path: "/v2/droplets",
	}); code == http.StatusOK {
		t.Fatalf("served with no credential: %s", body)
	}
}

// The customer's own key wins over the platform's, same rule as a model call.
func TestAFetchSpendsTheTenantsOwnKeyWhenThereIsOne(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		ownRef(alice, "digitalocean", "default"): "dop_theirs",
		orgRef(alice, "digitalocean", "default"):  "dop_ours",
	}), 100)

	var saw string
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, r *http.Request) {
		saw = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	})

	_, body := fetched(t, s, key, spend.Fetch{Provider: "DigitalOcean", Method: "GET", Path: "/v2/droplets"})
	if saw != "Bearer dop_theirs" {
		t.Errorf("spent %q — not the customer's own key", saw)
	}
	var out spend.Fetched
	_ = json.Unmarshal([]byte(body), &out)
	if out.Scope != ScopeUser {
		t.Errorf("scope = %q, want %q", out.Scope, ScopeUser)
	}
}

// A label names one of several accounts on one cloud, which is what lets an org
// run resources across two DigitalOcean accounts without a second deployment.
func TestALabelPicksTheAccount(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_default",
		orgRef(alice, "digitalocean", "spare"):   "dop_spare",
	}), 100)

	var saw string
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, r *http.Request) {
		saw = r.Header.Get("Authorization")
		_, _ = w.Write([]byte(`{}`))
	})

	for label, want := range map[string]string{"": "Bearer dop_default", "spare": "Bearer dop_spare"} {
		fetched(t, s, key, spend.Fetch{Provider: "DigitalOcean", Label: label, Method: "GET", Path: "/v2/droplets"})
		if saw != want {
			t.Errorf("label %q spent %q, want %q", label, saw, want)
		}
	}
}

// Only the methods a cloud API uses. A caller cannot reach for CONNECT, which is
// useful for exactly one thing and it is not calling an API.
func TestAFetchRefusesAMethodNoCloudUses(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 100)
	upstream(t, s, "digitalocean", func(http.ResponseWriter, *http.Request) {
		t.Error("an upstream call was made with a refused method")
	})

	for _, method := range []string{"CONNECT", "TRACE", "OPTIONS", "", "GET /x"} {
		if code, body := fetched(t, s, key, spend.Fetch{
			Provider: "DigitalOcean", Method: method, Path: "/v2/droplets",
		}); code == http.StatusOK {
			t.Errorf("method %q was served: %s", method, body)
		}
	}
}

// An answer bigger than the cap ends the call rather than this process's memory.
func TestAFetchWillNotReadAnUnboundedAnswer(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 100)
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, mostBody+1))
	})

	code, body := fetched(t, s, key, spend.Fetch{Provider: "DigitalOcean", Method: "GET", Path: "/v2/droplets"})
	if code == http.StatusOK {
		t.Fatalf("an oversized answer was served: %d bytes", len(body))
	}
}

// Whatever a cloud answers with, what leaves here is JSON — so a proxy's HTML
// error page breaks at this boundary, where it can be explained, rather than at
// the caller's unmarshal.
func TestAnAnswerThatIsNotJSONStillLeavesAsJSON(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 100)
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("<html>502 Bad Gateway</html>"))
	})

	_, body := fetched(t, s, key, spend.Fetch{Provider: "DigitalOcean", Method: "GET", Path: "/v2/droplets"})
	var out spend.Fetched
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("answer is not a spend.Fetched: %v — %s", err, body)
	}
	if out.Status != http.StatusBadGateway {
		t.Errorf("status = %d", out.Status)
	}
	var text string
	if err := json.Unmarshal(out.Body, &text); err != nil {
		t.Fatalf("body is not JSON: %v — %s", err, out.Body)
	}
	if !strings.Contains(text, "Bad Gateway") {
		t.Errorf("what the cloud said was lost: %q", text)
	}
}

// A body reaches the upstream as it was written.
func TestAFetchCarriesTheBody(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 100)

	var sent, kind string
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, r.ContentLength)
		_, _ = r.Body.Read(b)
		sent, kind = string(b), r.Header.Get("Content-Type")
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"droplet":{"id":1}}`))
	})

	code, body := fetched(t, s, key, spend.Fetch{
		Provider: "DigitalOcean", Method: "POST", Path: "/v2/droplets",
		Body: json.RawMessage(`{"name":"web-1","size":"s-1vcpu-1gb"}`),
	})
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %s", code, body)
	}
	if sent != `{"name":"web-1","size":"s-1vcpu-1gb"}` {
		t.Errorf("upstream got %q", sent)
	}
	if kind != "application/json" {
		t.Errorf("content type = %q", kind)
	}
}

// reference is the guard, tested directly as well as through the router: the
// table above proves the refusals reach a caller, this proves the rule itself
// and is where a new shape gets added.
func TestReference(t *testing.T) {
	const base = "https://api.digitalocean.com"
	for path, want := range map[string]string{
		"/v2/droplets":          base + "/v2/droplets",
		"/v2/droplets?page=2":   base + "/v2/droplets?page=2",
		"/v2/a%2Fb":             base + "/v2/a%2Fb",
		"/":                     base + "/",
		"/v2/../v2/droplets":    base + "/v2/droplets",
		"/v2/droplets#fragment": base + "/v2/droplets#fragment",
	} {
		got, err := reference(base, path)
		if err != nil {
			t.Errorf("reference(%q) = %v", path, err)
			continue
		}
		if got != want {
			t.Errorf("reference(%q) = %q, want %q", path, got, want)
		}
	}
	// These would leave the configured host, which is the security rule.
	for _, path := range []string{
		"//evil.example/x", "https://evil.example/x", "http://evil.example/x",
		"https://user:pw@evil.example/x", "//evil.example",
	} {
		got, err := reference(base, path)
		if err == nil {
			t.Errorf("reference(%q) = %q, want a refusal", path, got)
			continue
		}
		// And refused for the right reason. Nothing gets past `rooted` to reach
		// `resolve` today, so this calls resolve directly — the way a future
		// edit loosening `rooted` would — and checks it still sees the escape.
		// Without this, resolve could be deleted and every other test here
		// would pass.
		if got, err := resolve(base, path); err == nil {
			t.Errorf("resolve(%q) = %q: with the path rule loosened this would be served", path, got)
		}
	}
	// These are not paths. Refusing them is hygiene, not the security rule —
	// each of them stays on the configured host either way.
	for _, path := range []string{"v2/droplets", "", `/\evil.example/x`, "///evil.example"} {
		if got, err := reference(base, path); err == nil {
			t.Errorf("reference(%q) = %q, want a refusal", path, got)
		}
	}
	// A base that is not an https URL is refused, so a misconfigured host does
	// not become a cleartext leg carrying a credential.
	for _, b := range []string{"", "http://api.digitalocean.com", "api.digitalocean.com", "://"} {
		if got, err := reference(b, "/v2/droplets"); err == nil {
			t.Errorf("reference with base %q = %q, want a refusal", b, got)
		}
	}
}
