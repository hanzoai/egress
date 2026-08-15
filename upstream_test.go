package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hanzoai/ai/model"
	"github.com/hanzoai/ai/proxy"
)

// TestAPanickingDialectIsOneRefusedCall pins the goroutine. A dialect runs on
// one of its own and takes no context, so a vendor client that falls over
// takes this process with it unless the fall is caught where it happens. Every
// replica serves every tenant, so that is the whole service, not one call.
func TestAPanickingDialectIsOneRefusedCall(t *testing.T) {
	result, err := run(context.Background(), func() (*model.ModelResult, error) {
		panic("the vendor client fell over")
	})
	if err == nil {
		t.Fatalf("a panicking dialect was reported as an answer: %+v", result)
	}
	if result != nil {
		t.Errorf("result = %+v, want nil", result)
	}
}

// TestTheUpstreamCallIsMadeWithThisProcessOwnClient drives a real dialect at a
// server this test controls and counts what arrives. hanzoai/ai holds the
// outbound client in a package variable that starts empty, so a process that
// does not fill it dereferences nothing on its first call.
func TestTheUpstreamCallIsMadeWithThisProcessOwnClient(t *testing.T) {
	var arrived atomic.Int64
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		arrived.Add(1)
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer upstream.Close()

	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "openai", "default"): "sk-ours",
	}), 100)
	s.cfg.URLs = map[string]string{"openai": upstream.URL}

	_, body := ask(t, s, http.MethodPost, "/v1/call", token(t, key, nil),
		Call{Provider: "OpenAI", Model: "gpt-3.5-turbo", Question: "hi", Lang: "en"})

	if arrived.Load() == 0 {
		t.Fatalf("the call never reached an upstream: %s", body)
	}
}

// TestAnUpstreamThatCannotProveWhoItIsIsRefused pins certificate verification
// on the leg that carries the credential. The server here presents a
// certificate no root vouches for, which is what an interception looks like
// from inside this process.
func TestAnUpstreamThatCannotProveWhoItIsIsRefused(t *testing.T) {
	var arrived atomic.Int64
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		arrived.Add(1)
		w.WriteHeader(http.StatusOK)
	}))
	defer upstream.Close()

	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "openai", "default"): "sk-ours",
	}), 100)
	s.cfg.URLs = map[string]string{"openai": upstream.URL}

	_, body := ask(t, s, http.MethodPost, "/v1/call", token(t, key, nil),
		Call{Provider: "OpenAI", Model: "gpt-3.5-turbo", Question: "hi", Lang: "en"})

	if arrived.Load() != 0 {
		t.Fatalf("the credential was sent to an upstream that proved nothing: %s", body)
	}
	if !strings.Contains(body, "certificate") {
		t.Fatalf("the refusal was not about the certificate: %s", body)
	}
}

// TestAPanickingDialectCannotEchoTheCredential covers what the caught fall
// says. A panic carries whatever the vendor client was holding, which on this
// path is a request with the key in its header, and the error that replaces it
// travels to the caller and into a log.
func TestAPanickingDialectCannotEchoTheCredential(t *testing.T) {
	const key = "sk-ours"
	_, err := run(context.Background(), func() (*model.ModelResult, error) {
		panic("POST https://api.openai.com: Authorization: Bearer " + key)
	})
	if err == nil {
		t.Fatal("a panicking dialect was reported as an answer")
	}
	if got := scrub(err, key); strings.Contains(got.Error(), key) {
		t.Fatalf("the credential survived the fall: %s", got)
	}
}

// TestTheCredentialDoesNotReachTheCallerThroughAnUpstreamError drives the
// whole path: a provider rejects the key and quotes it back the way OpenAI
// does, and the refusal travels through the dialect, through spend, into the
// error frame the caller reads and the line the log keeps. Scrub is a unit
// test elsewhere; this is the one that fails if a return path ever stops
// going through it.
func TestTheCredentialDoesNotReachTheCallerThroughAnUpstreamError(t *testing.T) {
	const key = "sk-proj-4tHhQ2vLm8XnPqRs7WdYbGjK1cZeUfAz9q7x"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"message":"Incorrect API key provided: ` +
			`sk-proj-****************************9q7x. You can find your API key at ` +
			`https://platform.openai.com/account/api-keys.","type":"invalid_request_error",` +
			`"code":"invalid_api_key"}}`))
	}))
	defer upstream.Close()

	s, tok := serving(t, newStore(map[string]string{
		orgRef(alice, "openai", "default"): key,
	}), 100)
	s.cfg.URLs = map[string]string{"openai": upstream.URL}

	_, body := ask(t, s, http.MethodPost, "/v1/call", token(t, tok, nil),
		Call{Provider: "OpenAI", Model: "gpt-3.5-turbo", Question: "hi", Lang: "en"})

	for _, piece := range []string{key, "sk-proj-", "9q7x"} {
		if strings.Contains(body, piece) {
			t.Errorf("a piece of the credential reached the caller: %q is in %s", piece, body)
		}
	}
}

// TestTheRouteToAProviderIsNotSetFromTheEnvironment pins where a credential
// goes. Go's default transport reads HTTP_PROXY, HTTPS_PROXY and ALL_PROXY,
// so a client that leaves Transport nil lets whoever writes the process
// environment choose the far end of the connection carrying a key — the same
// choice the certificate check exists to take away from them. Egress dials
// the upstream named in its config and nothing else.
//
// This reads the transport rather than staging a proxy and watching, because
// Go resolves the proxy environment once per process and caches the result:
// an env-driven version of this test would pass or fail on which test ran
// first, which is worse than no test.
func TestTheRouteToAProviderIsNotSetFromTheEnvironment(t *testing.T) {
	serving(t, newStore(nil), 100)

	client := proxy.ProxyHttpClient
	if client == nil {
		t.Fatal("no outbound client was installed")
	}
	if client.Transport == http.DefaultTransport {
		t.Fatal("the outbound leg rides the process-wide transport, which reads the environment")
	}
	transport, ok := client.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("the outbound client has no transport of its own: %T", client.Transport)
	}
	if transport.Proxy != nil {
		t.Error("the environment can choose where a credential-bearing call goes")
	}
}
