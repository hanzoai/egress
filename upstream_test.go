package egress

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/hanzoai/ai/model"
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
