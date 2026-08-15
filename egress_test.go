package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// ── harness ──────────────────────────────────────────────────────────────────

const (
	callerSub = "system:serviceaccount:hanzo:cloud"
	otherSub  = "system:serviceaccount:hanzo:chat"
	audience  = "egress"
)

// cluster is a stand-in Kubernetes API server answering TokenReview, so the
// caller boundary is exercised through the same call it makes in production.
//
// A token is spelled "<subject>|<audience>"; anything else is a token the
// cluster does not recognise.
type cluster struct {
	server  *httptest.Server
	reviews atomic.Int32
}

func newCluster(t *testing.T) *cluster {
	t.Helper()
	c := &cluster{}
	c.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		c.reviews.Add(1)
		var in struct {
			Spec struct {
				Token     string   `json:"token"`
				Audiences []string `json:"audiences"`
			} `json:"spec"`
		}
		_ = json.NewDecoder(r.Body).Decode(&in)

		subject, aud, ok := strings.Cut(in.Spec.Token, "|")
		if !ok {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status": map[string]any{"authenticated": false, "error": "unknown token"},
			})
			return
		}
		// The real API server echoes only the audiences it validated, which is
		// how a token minted for another service is told apart.
		var echoed []string
		for _, want := range in.Spec.Audiences {
			if want == aud {
				echoed = append(echoed, want)
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": map[string]any{
				"authenticated": true,
				"audiences":     echoed,
				"user":          map[string]any{"username": subject},
			},
		})
	}))
	t.Cleanup(c.server.Close)
	return c
}

func token(subject, aud string) string { return subject + "|" + aud }

// vault is a stand-in secrets plane serving the embedded KMS grammar.
type vault struct {
	server *httptest.Server
	value  atomic.Value // string
	env    atomic.Value // string: the env the last read asked for
	ref    atomic.Value // string: the reference the last read asked for
}

func newVault(t *testing.T, initial string) *vault {
	t.Helper()
	v := &vault{}
	v.value.Store(initial)
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/kms/auth/login", func(w http.ResponseWriter, r *http.Request) {
		var body struct{ ClientId, ClientSecret string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.ClientId != "egress" || body.ClientSecret != "shh" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": "kms-token", "expiresIn": 3600})
	})
	mux.HandleFunc("/v1/kms/secrets/", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer kms-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		v.ref.Store(strings.TrimPrefix(r.URL.Path, "/v1/kms/secrets/"))
		v.env.Store(r.URL.Query().Get("env"))
		_ = json.NewEncoder(w).Encode(map[string]string{"value": v.value.Load().(string)})
	})
	v.server = httptest.NewServer(mux)
	t.Cleanup(v.server.Close)
	return v
}

// seen is what the upstream vendor actually received.
type seen struct {
	auth   string
	path   string
	query  string
	header http.Header
}

func newUpstream(t *testing.T, got *atomic.Value, body func(w http.ResponseWriter)) *httptest.Server {
	t.Helper()
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.Store(seen{
			auth: r.Header.Get("Authorization"), path: r.URL.Path,
			query: r.URL.RawQuery, header: r.Header.Clone(),
		})
		body(w)
	}))
	t.Cleanup(s.Close)
	return s
}

func quiet() Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

// only replaces the upstream table for one test.
func only(t *testing.T, table map[string]Upstream) {
	t.Helper()
	prev := upstreams
	upstreams = table
	t.Cleanup(func() { upstreams = prev })
}

// build wires a Server whose single upstream points at target.
func build(t *testing.T, c *cluster, v *vault, target string, refresh time.Duration) *Server {
	t.Helper()
	only(t, map[string]Upstream{"openrouter": {
		Base: mustURL(target + "/api"), Secret: "ai/OPENROUTER_API_KEY", Auth: bearer,
		Ops: ops("GET /v1/models", "POST /v1/chat/completions"),
	}})
	return assemble(t, c, v, refresh, map[string][]string{callerSub: {"openrouter"}})
}

func assemble(t *testing.T, c *cluster, v *vault, refresh time.Duration, grants map[string][]string) *Server {
	t.Helper()
	kms, err := NewKMS(v.server.URL, "egress", "shh", "prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	cred, err := NewCredential(context.Background(), kms, refresh, quiet())
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewIdentity(c.server.URL, audience, grants, c.server.Client())
	if err != nil {
		t.Fatal(err)
	}
	return New(id, cred, quiet())
}

func call(t *testing.T, s *Server, method, path, tok string, headers map[string]string) *http.Response {
	t.Helper()
	req := httptest.NewRequest(method, path, nil)
	if tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	s.ServeHTTP(w, req)
	return w.Result()
}

// ── routing: the caller names a provider, never a destination ────────────────

func TestRoute(t *testing.T) {
	for _, tc := range []struct {
		path, tail string
		ok         bool
	}{
		{"/openrouter/v1/models", "/v1/models", true},
		{"/openrouter/v1/chat/completions", "/v1/chat/completions", true},
		{"/openrouter", "/", true},
		{"/openai/v1/models", "", false},
		{"/", "", false},
		{"/../openrouter/v1/models", "", false},
	} {
		_, _, tail, ok := route(tc.path)
		if ok != tc.ok || (ok && tail != tc.tail) {
			t.Errorf("route(%q) = (%q, %v), want (%q, %v)", tc.path, tail, ok, tc.tail, tc.ok)
		}
	}
}

// No request field may reach the destination. This is what separates a broker
// from an authenticated open proxy.
func TestCallerCannotNameDestination(t *testing.T) {
	for _, path := range []string{
		"/https://evil.test/v1",
		"//evil.test/v1",
		"/openrouter.evil.test/v1",
		"/OPENROUTER/v1/models", // the table is exact, not case-folded
	} {
		if _, _, _, ok := route(path); ok {
			t.Errorf("route(%q) resolved; a caller must not name a destination", path)
		}
	}
	_, up, _, ok := route("/openrouter/v1/models")
	if !ok || up.Base.Host != "openrouter.ai" {
		t.Errorf("openrouter resolved to %v, want the compiled-in vendor", up.Base)
	}
}

// ── the credential reaches the vendor, and only the vendor ───────────────────

func TestCredentialInjected(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{"data":[]}`)) })
	s := build(t, c, v, up.URL, time.Hour)

	resp := call(t, s, "GET", "/openrouter/v1/models?limit=5", token(callerSub, audience), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	saw := got.Load().(seen)
	if saw.auth != "Bearer vendor-key-1" {
		t.Errorf("upstream Authorization = %q, want the vendor credential", saw.auth)
	}
	if saw.path != "/api/v1/models" {
		t.Errorf("upstream path = %q, want /api/v1/models", saw.path)
	}
	if saw.query != "limit=5" {
		t.Errorf("query = %q, want it preserved", saw.query)
	}

	body, _ := io.ReadAll(resp.Body)
	if strings.Contains(string(body), "vendor-key-1") {
		t.Error("credential echoed to caller")
	}
	for k, vals := range resp.Header {
		for _, val := range vals {
			if strings.Contains(val, "vendor-key-1") {
				t.Errorf("credential in response header %s", k)
			}
		}
	}
}

// A vendor that wants its credential in its own header gets it there, and does
// not also get a bearer.
func TestVendorAuthScheme(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{}`)) })

	only(t, map[string]Upstream{"anthropic": {
		Base:   mustURL(up.URL + "/api"),
		Secret: "ai/OPENROUTER_API_KEY",
		Auth:   Auth{Header: "x-api-key"},
		Extra:  map[string]string{"anthropic-version": "2023-06-01"},
		Ops:    ops("POST /v1/messages"),
	}})
	s := assemble(t, c, v, time.Hour, map[string][]string{callerSub: {"anthropic"}})

	if resp := call(t, s, "POST", "/anthropic/v1/messages", token(callerSub, audience), nil); resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	saw := got.Load().(seen)
	if saw.header.Get("x-api-key") != "vendor-key-1" {
		t.Errorf("x-api-key = %q, want the credential", saw.header.Get("x-api-key"))
	}
	if saw.auth != "" {
		t.Errorf("Authorization = %q, want it unset for this vendor", saw.auth)
	}
	if saw.header.Get("anthropic-version") != "2023-06-01" {
		t.Error("vendor's required header was not sent")
	}
}

// A caller's own token proves it may spend here. It must never be offered to the
// vendor, and must not survive as any other credential header either.
func TestCallerCredentialStripped(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{}`)) })
	s := build(t, c, v, up.URL, time.Hour)

	tok := token(callerSub, audience)
	call(t, s, "GET", "/openrouter/v1/models", tok, map[string]string{
		"X-Api-Key":          "caller-key",
		"Cookie":             "session=abc",
		"X-Org-Id":           "acme",
		"X-User-Id":          "u-1",
		"X-Hanzo-Fronted-By": "ai",
		"X-Forwarded-For":    "10.0.0.1",
	})

	saw := got.Load().(seen)
	if strings.Contains(saw.auth, tok) {
		t.Error("caller token forwarded to vendor")
	}
	for _, h := range []string{"X-Api-Key", "Cookie", "X-Org-Id", "X-User-Id", "X-Hanzo-Fronted-By", "X-Forwarded-For"} {
		if saw.header.Get(h) != "" {
			t.Errorf("%s leaked to vendor: %q", h, saw.header.Get(h))
		}
	}
}

// ── nobody spends without proving who they are ───────────────────────────────

func TestRefusals(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	reached := atomic.Bool{}
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) { reached.Store(true) })
	s := build(t, c, v, up.URL, time.Hour)

	for _, tc := range []struct {
		name, tok string
	}{
		{"no token", ""},
		{"token the cluster does not know", "garbage"},
		{"ungranted workload", token(otherSub, audience)},
		{"token minted for another service", token(callerSub, "some-other-service")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reached.Store(false)
			resp := call(t, s, "GET", "/openrouter/v1/models", tc.tok, nil)
			if resp.StatusCode != 403 {
				t.Errorf("status = %d, want 403", resp.StatusCode)
			}
			if reached.Load() {
				t.Error("refused request still reached the vendor")
			}
			body, _ := io.ReadAll(resp.Body)
			if strings.Contains(string(body), "vendor-key-1") {
				t.Error("credential disclosed in a refusal")
			}
		})
	}
}

// A vendor's API is wider than the part we use. Our credential must never
// authenticate a call to the vendor's account, billing or key-management
// surface, however the caller spells it.
func TestOnlyListedOperations(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	reached := atomic.Bool{}
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) { reached.Store(true) })
	s := build(t, c, v, up.URL, time.Hour)
	tok := token(callerSub, audience)

	for _, tc := range []struct{ method, path string }{
		{"GET", "/openrouter/v1/key"},       // names and limits of the key in use
		{"GET", "/openrouter/v1/credits"},   // account balance
		{"GET", "/openrouter/v1/keys"},      // key management
		{"POST", "/openrouter/v1/keys"},     // minting more keys
		{"DELETE", "/openrouter/v1/models"}, // right path, wrong method
		{"GET", "/openrouter/v1/generation"},
	} {
		reached.Store(false)
		resp := call(t, s, tc.method, tc.path, tok, nil)
		if resp.StatusCode != 404 {
			t.Errorf("%s %s = %d, want 404", tc.method, tc.path, resp.StatusCode)
		}
		if reached.Load() {
			t.Errorf("%s %s reached the vendor with our credential", tc.method, tc.path)
		}
	}

	// The calls we do make still work.
	if resp := call(t, s, "GET", "/openrouter/v1/models", tok, nil); resp.StatusCode != 200 {
		t.Errorf("GET /v1/models = %d, want 200", resp.StatusCode)
	}
	if resp := call(t, s, "POST", "/openrouter/v1/chat/completions", tok, nil); resp.StatusCode != 200 {
		t.Errorf("POST /v1/chat/completions = %d, want 200", resp.StatusCode)
	}
}

// A workload may be granted one provider and not another. Authentication says
// who; this says on what.
func TestGrantIsPerProvider(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{}`)) })

	only(t, map[string]Upstream{
		"openrouter": {Base: mustURL(up.URL + "/api"), Secret: "ai/OPENROUTER_API_KEY", Auth: bearer, Ops: ops("GET /v1/models")},
		"anthropic":  {Base: mustURL(up.URL + "/an"), Secret: "ai/OPENROUTER_API_KEY", Auth: bearer, Ops: ops("GET /v1/models")},
	})
	s := assemble(t, c, v, time.Hour, map[string][]string{callerSub: {"openrouter"}})

	tok := token(callerSub, audience)
	if resp := call(t, s, "GET", "/openrouter/v1/models", tok, nil); resp.StatusCode != 200 {
		t.Errorf("granted provider = %d, want 200", resp.StatusCode)
	}
	if resp := call(t, s, "GET", "/anthropic/v1/models", tok, nil); resp.StatusCode != 403 {
		t.Errorf("ungranted provider = %d, want 403", resp.StatusCode)
	}
}

func TestGrantForUnknownUpstreamRefused(t *testing.T) {
	c := newCluster(t)
	if _, err := NewIdentity(c.server.URL, audience,
		map[string][]string{callerSub: {"nosuchvendor"}}, c.server.Client()); err == nil {
		t.Fatal("accepted a grant for an unknown upstream")
	}
}

// A deployment that never said who may spend must not default to anyone.
func TestNoGrantsRefused(t *testing.T) {
	c := newCluster(t)
	if _, err := NewIdentity(c.server.URL, audience, nil, c.server.Client()); err == nil {
		t.Fatal("built a boundary that allows everyone")
	}
}

func TestUnknownUpstream(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) {})
	s := build(t, c, v, up.URL, time.Hour)

	if resp := call(t, s, "GET", "/openai/v1/models", token(callerSub, audience), nil); resp.StatusCode != 404 {
		t.Errorf("status = %d, want 404", resp.StatusCode)
	}
}

// Only proven identities are remembered, and the answer is reused rather than
// asked again on every call.
func TestProofIsCached(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{}`)) })
	s := build(t, c, v, up.URL, time.Hour)

	tok := token(callerSub, audience)
	for range 5 {
		call(t, s, "GET", "/openrouter/v1/models", tok, nil)
	}
	if n := c.reviews.Load(); n != 1 {
		t.Errorf("asked the cluster %d times for one token, want 1", n)
	}

	// A refusal is not cached: a workload granted a token a moment ago must not
	// stay refused.
	before := c.reviews.Load()
	call(t, s, "GET", "/openrouter/v1/models", "garbage", nil)
	call(t, s, "GET", "/openrouter/v1/models", "garbage", nil)
	if c.reviews.Load() != before+2 {
		t.Error("a refusal was cached")
	}
}

// ── the platform surface says nothing it should not ──────────────────────────

func TestPlatformSurface(t *testing.T) {
	c, v := newCluster(t), newVault(t, "sk-or-v1-secret-value")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) {})
	s := build(t, c, v, up.URL, time.Hour)

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		resp := call(t, s, "GET", path, "", nil) // no credential: probes carry none
		if resp.StatusCode != 200 {
			t.Errorf("%s = %d, want 200", path, resp.StatusCode)
		}
		body, _ := io.ReadAll(resp.Body)
		if strings.Contains(string(body), "sk-or-v1-secret-value") {
			t.Errorf("%s disclosed the credential", path)
		}
	}
}

// ── rotation is a value change, not a deploy ─────────────────────────────────

func TestRotationWithoutRestart(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{}`)) })
	s := build(t, c, v, up.URL, 50*time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.cred.Watch(ctx)

	tok := token(callerSub, audience)
	call(t, s, "GET", "/openrouter/v1/models", tok, nil)
	if saw := got.Load().(seen); saw.auth != "Bearer vendor-key-1" {
		t.Fatalf("before rotation: %q", saw.auth)
	}

	// The operator rewrites the value in KMS. Nothing is redeployed.
	v.value.Store("vendor-key-2")

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		call(t, s, "GET", "/openrouter/v1/models", tok, nil)
		if got.Load().(seen).auth == "Bearer vendor-key-2" {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("credential did not rotate; vendor still saw %q", got.Load().(seen).auth)
}

// A KMS that goes away must not take paid traffic with it.
func TestOutageKeepsLastCredential(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) { _, _ = w.Write([]byte(`{}`)) })
	s := build(t, c, v, up.URL, 25*time.Millisecond)

	v.server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go s.cred.Watch(ctx)
	time.Sleep(150 * time.Millisecond)

	resp := call(t, s, "GET", "/openrouter/v1/models", token(callerSub, audience), nil)
	if resp.StatusCode != 200 {
		t.Fatalf("status %d during a KMS outage", resp.StatusCode)
	}
	if saw := got.Load().(seen); saw.auth != "Bearer vendor-key-1" {
		t.Errorf("lost the credential during an outage: %q", saw.auth)
	}
}

// The full coordinate is always sent: a bare name reaches a different partition
// than the one records are written to, and a missing environment reaches a
// different environment. Both return "not found" for a secret that exists.
func TestSecretReadSendsFullCoordinate(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	var got atomic.Value
	up := newUpstream(t, &got, func(w http.ResponseWriter) {})
	build(t, c, v, up.URL, time.Hour)

	if env, _ := v.env.Load().(string); env != "prod" {
		t.Errorf("read asked for env %q, want prod", env)
	}
	ref, _ := v.ref.Load().(string)
	if ref != "ai/OPENROUTER_API_KEY" {
		t.Errorf("read asked for %q, want the org-qualified reference", ref)
	}
	if !strings.Contains(ref, "/") {
		t.Error("read used a bare name, which resolves to a different partition")
	}
}

// Boot must fail when no credential can be resolved, rather than opening a
// listener that can only refuse.
func TestBootFailsWithoutCredential(t *testing.T) {
	v := newVault(t, "x")
	v.server.Close()
	kms, err := NewKMS(v.server.URL, "egress", "shh", "prod", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewCredential(context.Background(), kms, time.Minute, quiet()); err == nil {
		t.Fatal("boot succeeded with no credential")
	}
}

// ── streaming passes through as it arrives ───────────────────────────────────

func TestStreamIsNotBuffered(t *testing.T) {
	c, v := newCluster(t), newVault(t, "vendor-key-1")
	release := make(chan struct{})
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(200)
		f := w.(http.Flusher)
		_, _ = fmt.Fprint(w, "data: first\n\n")
		f.Flush()
		<-release // hold the connection open; the first event must already be out
		_, _ = fmt.Fprint(w, "data: [DONE]\n\n")
		f.Flush()
	}))
	defer up.Close()
	s := build(t, c, v, up.URL, time.Hour)

	front := httptest.NewServer(s)
	defer front.Close()

	req, _ := http.NewRequest("POST", front.URL+"/openrouter/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer "+token(callerSub, audience))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { close(release); _ = resp.Body.Close() }()

	if ct := resp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Fatalf("content type = %q", ct)
	}
	line := make(chan string, 1)
	go func() {
		r := bufio.NewReader(resp.Body)
		s, _ := r.ReadString('\n')
		line <- s
	}()
	select {
	case got := <-line:
		if !strings.HasPrefix(got, "data: first") {
			t.Errorf("first event = %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("first event was buffered; it never arrived while the stream was open")
	}
}

// ── the log names a rotation without naming the credential ───────────────────

func TestFingerprintHidesCredential(t *testing.T) {
	const secret = "sk-or-v1-abcdefghijklmnop"
	fp := fingerprint(secret)
	if strings.Contains(fp, secret) || strings.Contains(secret, fp) {
		t.Error("fingerprint discloses the credential")
	}
	if len(fp) != 12 {
		t.Errorf("fingerprint length %d", len(fp))
	}
	if fp == fingerprint(secret+"x") {
		t.Error("fingerprint does not distinguish credentials")
	}
	if fp != fingerprint(secret) {
		t.Error("fingerprint is not stable within a process")
	}

	// The mark is per-process and never leaves it, so a log line cannot be used
	// to confirm a guessed credential: the same value marks differently
	// elsewhere.
	elsewhere := hmacHex(secret)
	if fp == elsewhere {
		t.Error("fingerprint is reproducible outside this process; it is an oracle")
	}
}

// hmacHex recomputes a fingerprint under a DIFFERENT mark, standing in for
// anyone holding a candidate credential and a log line.
func hmacHex(v string) string {
	saved := mark
	mark = []byte("a different process")
	defer func() { mark = saved }()
	return fingerprint(v)
}
