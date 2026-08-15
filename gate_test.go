package egress

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// TestTheGateStopsAnAnonymousCallerBeforeTheHandler isolates the door. The
// route tests observe a 401, which two independent checks can produce; this one
// asserts the gate itself refuses and, crucially, passes no principal onward —
// so nothing downstream can read a credential for a caller nobody could name.
// The other half, that a verified caller does reach the handler, is what the
// route tests show: health answers, and an enrolled key lands under the
// enroller's own path.
func TestTheGateStopsAnAnonymousCallerBeforeTheHandler(t *testing.T) {
	s, key := serving(t, newStore(nil), 100)

	c := s.App().TestCtx(http.MethodPost, "/v1/call")
	if err := s.gate(c); err == nil {
		t.Fatal("the gate admitted a caller with no token")
	}
	if p, ok := principalOf(c.Context()); ok {
		t.Fatalf("an anonymous request carried a principal onward: %+v", p)
	}
	_ = key
}

// TestACallerCannotNameATenantOrAnUpstream pins the shape of the wire rather
// than one behaviour of it. Both fields would be catastrophic in different
// ways — a tenant field spends somebody else's key, an upstream field has the
// credential delivered to whoever asked — and both are the kind of field that
// gets added later for a good local reason. The wire says no.
func TestACallerCannotNameATenantOrAnUpstream(t *testing.T) {
	banned := []string{"url", "endpoint", "host", "base", "org", "owner", "tenant", "user", "path", "ref", "secret", "credential"}
	for _, wire := range []any{Call{}, Enroll{}, Turn{}} {
		typ := reflect.TypeOf(wire)
		for i := 0; i < typ.NumField(); i++ {
			name := strings.ToLower(typ.Field(i).Name)
			for _, bad := range banned {
				if strings.Contains(name, bad) {
					t.Errorf("%s.%s: a caller must not be able to name %q — it comes from the token or from this host",
						typ.Name(), typ.Field(i).Name, bad)
				}
			}
		}
	}
}

// TestTheUpstreamComesFromTheHost pins the other half: the only source of an
// upstream address is this host's configuration.
func TestTheUpstreamComesFromTheHost(t *testing.T) {
	cfg := Config{
		Listen: ":0", Issuer: issuer, JWKS: "https://hanzo.id/jwks", Audience: audience,
		KMS: "zap://kms:9999", KMSOrg: "hanzo", KMSPath: "hanzo/egress",
		RPM: 1, Deadline: 1,
		URLs: map[string]string{"digitalocean": "http://exfiltrate.example"},
	}
	if err := cfg.Check(); err == nil {
		t.Fatal("a plaintext upstream was accepted")
	}
	cfg.URLs["digitalocean"] = "https://inference.do-ai.run/v1"
	if err := cfg.Check(); err != nil {
		t.Fatalf("a configured upstream was refused: %v", err)
	}
}

func TestAnIncoherentConfigurationIsRefused(t *testing.T) {
	for name, edit := range map[string]func(*Config){
		"no audience": func(c *Config) { c.Audience = "" },
		"no issuer":   func(c *Config) { c.Issuer = "" },
		"no jwks":     func(c *Config) { c.JWKS = "" },
		"no kms":      func(c *Config) { c.KMS = "" },
		"no ceiling":  func(c *Config) { c.RPM = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			cfg := Config{
				Listen: ":0", Issuer: issuer, JWKS: "https://hanzo.id/jwks", Audience: audience,
				KMS: "zap://kms:9999", KMSOrg: "hanzo", KMSPath: "hanzo/egress",
				RPM: 1, Deadline: 1,
			}
			edit(&cfg)
			if err := cfg.Check(); err == nil {
				t.Fatal("served with a hole in the configuration")
			}
			if _, err := New(cfg, newStore(nil), nil); err == nil {
				t.Fatal("New built a server from it anyway")
			}
		})
	}
}

// TestEveryHandlerRefusesWithoutAPrincipal is the backstop, tested on its own
// because while the perimeter holds it is invisible. It is not hypothetical
// cover: the framework's projected surface turned out to be exactly such a
// road, and this is what refused an enrol arriving down it.
func TestEveryHandlerRefusesWithoutAPrincipal(t *testing.T) {
	st := newStore(nil)
	s, _ := serving(t, st, 100)
	bare := context.Background()

	if out, err := s.health(bare, &Nothing{}); err == nil {
		t.Errorf("health answered a caller with no principal: %+v", out)
	}
	if out, err := s.enroll(bare, &Enroll{Provider: "OpenAI", Key: "sk-taken"}); err == nil {
		t.Errorf("enroll sealed a key for a caller with no principal: %+v", out)
	}
	// A well-formed body, so the refusal can only come from the missing
	// principal and not from a parse failure standing in for it.
	c := s.App().TestCtx(http.MethodPost, "/v1/call")
	body, err := json.Marshal(call())
	if err != nil {
		t.Fatal(err)
	}
	c.Fiber().Request().SetBody(body)
	if err := s.call(c); err == nil {
		t.Error("call spent for a caller with no principal")
	}
	for ref, v := range st.held {
		t.Errorf("a principal-less request wrote %s = %q", ref, v)
	}
}
