package egress

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hanzoai/jwt"
)

// While the platform's issuer moves from hanzo.id to hanzo.ai the verifier trusts both
// spellings, each exactly, and never an organization's own issuer, which sits one path
// segment under hanzo.ai.
func TestBothPlatformIssuersAreTrustedAndAnOrgsIsNot(t *testing.T) {
	key := issuerKey(t)
	set, err := jwt.BuildJWKS(key)
	if err != nil {
		t.Fatal(err)
	}
	for _, configured := range []string{"https://hanzo.id", "https://hanzo.ai"} {
		v := NewVerifier(configured, audience, "", time.Minute)
		v.fetch = func(context.Context) ([]byte, error) { return set, nil }
		for _, iss := range []string{"https://hanzo.id", "https://hanzo.ai"} {
			tok := token(t, key, func(c *jwt.Claims) { c.Issuer = iss })
			if _, err := v.Verify(context.Background(), "Bearer "+tok); err != nil {
				t.Errorf("configured %s refused iss %s: %v", configured, iss, err)
			}
		}
		for _, iss := range []string{"https://hanzo.ai/acme", "https://hanzo.ai.evil.test", "http://hanzo.ai", "https://evil.example"} {
			tok := token(t, key, func(c *jwt.Claims) { c.Issuer = iss })
			if _, err := v.Verify(context.Background(), "Bearer "+tok); !errors.Is(err, ErrAnonymous) {
				t.Errorf("configured %s trusted iss %s: %v", configured, iss, err)
			}
		}
	}
}
