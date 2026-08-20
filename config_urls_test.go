package egress

import (
	"flag"
	"os"
	"strings"
	"testing"
)

// A cloud provider has no built-in endpoint to fall back to, so EGRESS_URLS is
// the only way one gets an upstream — and this host is configured by a systemd
// unit with no command line.
func TestUpstreamsComeFromTheEnvironment(t *testing.T) {
	t.Setenv("EGRESS_URLS", "digitalocean=https://api.digitalocean.com,hetzner=https://api.hetzner.cloud")
	var c Config
	c.Flags(flag.NewFlagSet("t", flag.ContinueOnError))

	for provider, want := range map[string]string{
		"digitalocean": "https://api.digitalocean.com",
		"hetzner":      "https://api.hetzner.cloud",
	} {
		if c.URLs[provider] != want {
			t.Errorf("URLs[%q] = %q, want %q", provider, c.URLs[provider], want)
		}
	}
}

// A typo refuses to start. Silently dropping it would surface later as "no
// upstream is configured", which points at an operator who did configure it.
func TestAnUnreadableUpstreamRefusesToStart(t *testing.T) {
	t.Setenv("EGRESS_URLS", "digitalocean=https://api.digitalocean.com,hetzner-https://api.hetzner.cloud")
	var c Config
	c.Flags(flag.NewFlagSet("t", flag.ContinueOnError))
	c.JWKS, c.Audience, c.KMS, c.Recipient = "j", "a", "k", "age1pq1test"

	err := c.Check()
	if err == nil {
		t.Fatal("a malformed EGRESS_URLS entry was accepted")
	}
	if !strings.Contains(err.Error(), "hetzner-https") {
		t.Errorf("the refusal does not name the entry: %v", err)
	}
}

// And with nothing set, nothing is configured — no default upstream appears.
func TestNoUpstreamsByDefault(t *testing.T) {
	_ = os.Unsetenv("EGRESS_URLS")
	var c Config
	c.Flags(flag.NewFlagSet("t", flag.ContinueOnError))
	if len(c.URLs) != 0 {
		t.Errorf("URLs = %v, want none — an upstream must be written by an operator", c.URLs)
	}
}
