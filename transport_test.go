package egress

import (
	"context"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/valyala/fasthttp"
	zaphttp "github.com/zap-proto/http"
	"github.com/zap-proto/zip"
)

// TestTheProjectedSurfaceIsGatedToo is the regression this service exists to
// not have. A typed op is reachable at more addresses than the one it was
// declared at: the framework projects it onto an op-call plane, an MCP tool and
// an OpenAPI document, and installs those routes itself. A gate wrapped around
// each handler covers the declared path only — proven by measurement, not
// argued — so the gate goes ahead of every route instead.
func TestTheProjectedSurfaceIsGatedToo(t *testing.T) {
	st := newStore(nil)
	s, _ := serving(t, st, 100)

	for _, r := range []struct {
		method, path string
		body         any
	}{
		{http.MethodGet, "/.well-known/openapi.json", nil},
		{http.MethodPost, "/mcp", map[string]any{"method": "tools/list"}},
		{http.MethodPost, "/mcp", map[string]any{"method": "tools/call", "params": map[string]any{
			"name": "egress_enroll", "arguments": map[string]any{"provider": "OpenAI", "key": "sk-taken"}}}},
	} {
		code, body := ask(t, s, r.method, r.path, "", r.body)
		if code != http.StatusUnauthorized {
			t.Errorf("%s %s answered an unidentified caller: %d %s", r.method, r.path, code, body)
		}
	}
	for ref, v := range st.held {
		t.Errorf("an unauthenticated write landed: %s = %q", ref, v)
	}
}

// TestTheGateHoldsOverZAP drives the inbound transport that actually ships. The
// op-call plane is how one service calls another over ZAP, and it is the road
// that was open.
func TestTheGateHoldsOverZAP(t *testing.T) {
	s, key := serving(t, newStore(nil), 100)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	go func() { _ = s.App().Listen(addr) }()
	t.Cleanup(func() { _ = s.App().Shutdown() })
	waitFor(t, addr)

	c, err := zip.Dial(addr)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()

	if out, err := zip.Call[Nothing, Ready](context.Background(), c, "egress_health", &Nothing{}); err == nil {
		t.Fatalf("an unidentified ZAP caller was served: %+v", out)
	}

	// The by-name op plane cannot carry a bearer: zip.Call forwards the
	// gateway's X-* identity assertions and nothing else, and those are exactly
	// what this service must not believe. A caller reaches egress at its ROUTE
	// over the same ZAP transport, which carries a whole request, headers
	// included.
	zap := zaphttp.Dial("tcp", addr)
	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://egress/v1/health")
	req.Header.SetMethod("GET")
	if err := zap.Do(req, resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusUnauthorized {
		t.Fatalf("an unidentified caller was served over ZAP: %d %s", resp.StatusCode(), resp.Body())
	}

	req.Header.Set("Authorization", "Bearer "+token(t, key, nil))
	if err := zap.Do(req, resp); err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode() != http.StatusOK {
		t.Fatalf("an identified ZAP caller was refused: %d %s", resp.StatusCode(), resp.Body())
	}
	if !strings.Contains(string(resp.Body()), `"ready":true`) {
		t.Errorf("body = %s", resp.Body())
	}
}

func waitFor(t *testing.T, addr string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond); err == nil {
			_ = c.Close()
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s never accepted", addr)
}
