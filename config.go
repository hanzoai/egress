// Package egress is the outbound trust boundary: callers ask for a metered
// upstream call, the provider credential stays in KMS and is never handed back.
//
// It runs as one process on a host we provision — not in the managed cluster —
// so everything it needs arrives from the host (flags, environment) and nothing
// is read from an orchestrator. Inbound is ZAP; outbound is HTTPS to the
// provider and ZAP to KMS.
package egress

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

// Config is everything the process needs to run. Every field either has a safe
// default or is required; there is no third state where a missing value is
// quietly tolerated, because the values without defaults are the ones that
// decide who may spend.
type Config struct {
	// Listen is the inbound ZAP address callers reach. A bare host:port is ZAP
	// over TCP, which is what a caller inside the cluster dials across the
	// network.
	Listen string

	// Issuer is the IAM issuer every access token must name in `iss`.
	Issuer string

	// JWKS is where the issuer publishes its signing keys.
	JWKS string

	// Audience is the `aud` a token must carry to spend here. Required and
	// unguessable-by-default on purpose: a service that accepts any audience
	// accepts a token minted for a different app.
	Audience string

	// KMS is the credential store endpoint, e.g. "zap://kms.hanzo.ai:9999".
	KMS string

	// KMSOrg is the KMS tenant the custody tree lives under. It is NOT the
	// caller's org — the caller's org is a path segment inside this tenant, put
	// there by the validated principal.
	KMSOrg string

	// KMSPath is this service's own identity path, the name its signing key is
	// derived at and the name KMS authorizes.
	KMSPath string

	// Recipient is this host's public sealing key, `age1pq1…`. Every credential
	// in KMS is sealed to it, and it can only seal — the half that opens is the
	// identity, which never leaves the TPM. So this is public by construction: a
	// flag, a manifest, a commit are all fine places for it, and that is the
	// point. Whoever enrols a credential does not thereby become able to read
	// one.
	Recipient string

	// IAM is the identity server the HTTP transport exchanges client
	// credentials at. Required when KMS is an http(s) endpoint, unused when it
	// is zap:// — the two transports authenticate differently and the store SDK
	// takes the same struct for both.
	IAM string

	// ClientID names this service's machine identity on the HTTP transport. It
	// is an identifier, not a secret; the matching secret is sealed to the TPM
	// and never appears here, in the environment, or in a file this process can
	// be asked to print.
	ClientID string

	// RPM is how many calls one principal may make per minute.
	RPM int

	// Deadline bounds one upstream call.
	Deadline time.Duration

	// URLs maps a provider to the upstream base URL to dial for it. An entry
	// exists only because an operator wrote it on this host. A provider absent
	// here gets the dialect's own built-in endpoint.
	//
	// This is deliberately NOT a request field. A caller that could name the
	// upstream could name its own, and egress would hand it the credential.
	URLs map[string]string
}

// Flags binds cfg to fs and returns cfg, so a caller can add flags of its own
// before parsing. Every flag falls back to the environment, which is how a
// systemd unit supplies configuration without putting it in a command line.
func (c *Config) Flags(fs *flag.FlagSet) {
	fs.StringVar(&c.Listen, "listen", env("EGRESS_LISTEN", ":9653"), "inbound ZAP address")
	fs.StringVar(&c.Issuer, "issuer", env("EGRESS_ISSUER", "https://hanzo.id"), "IAM issuer tokens must name")
	fs.StringVar(&c.JWKS, "jwks", env("EGRESS_JWKS", ""), "issuer JWKS document URL")
	fs.StringVar(&c.Audience, "audience", env("EGRESS_AUDIENCE", ""), "audience a token must carry")
	fs.StringVar(&c.KMS, "kms", env("EGRESS_KMS", ""), "KMS endpoint, zap://host:port")
	fs.StringVar(&c.KMSOrg, "kms-org", env("EGRESS_KMS_ORG", "hanzo"), "KMS tenant holding the custody tree")
	fs.StringVar(&c.KMSPath, "kms-path", env("EGRESS_KMS_PATH", "hanzo/egress"), "this service's identity path")
	fs.StringVar(&c.Recipient, "recipient", env("EGRESS_RECIPIENT", ""), "this host's public sealing key, age1pq1...")
	fs.StringVar(&c.IAM, "iam", env("EGRESS_IAM", ""), "IAM endpoint for the http transport")
	fs.StringVar(&c.ClientID, "client-id", env("EGRESS_CLIENT_ID", ""), "machine identity for the http transport")
	fs.IntVar(&c.RPM, "rpm", envInt("EGRESS_RPM", 600), "calls per minute per principal")
	fs.DurationVar(&c.Deadline, "deadline", envDuration("EGRESS_DEADLINE", 5*time.Minute), "upstream call deadline")
	fs.Var(urls{&c.URLs}, "url", "upstream base URL for one provider, provider=url (repeatable)")
}

// Check reports why this configuration cannot be served. It refuses rather than
// filling in a default for anything that decides who may spend or where a
// credential may be sent.
func (c *Config) Check() error {
	var missing []string
	for name, v := range map[string]string{
		"listen": c.Listen, "issuer": c.Issuer, "jwks": c.JWKS,
		"audience": c.Audience, "kms": c.KMS, "kms-org": c.KMSOrg, "kms-path": c.KMSPath,
		"recipient": c.Recipient,
	} {
		if strings.TrimSpace(v) == "" {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("egress: %s must be set", strings.Join(sorted(missing), ", "))
	}
	if c.RPM <= 0 || c.Deadline <= 0 {
		return errors.New("egress: rpm and deadline must be positive")
	}
	for provider, u := range c.URLs {
		if !strings.HasPrefix(u, "https://") {
			return fmt.Errorf("egress: url for %q must be https", provider)
		}
	}
	return nil
}

// urls collects the repeatable -url flag into a map.
type urls struct{ into *map[string]string }

func (u urls) String() string { return "" }

func (u urls) Set(v string) error {
	provider, target, ok := strings.Cut(v, "=")
	if !ok || strings.TrimSpace(provider) == "" || strings.TrimSpace(target) == "" {
		return fmt.Errorf("want provider=url, got %q", v)
	}
	if *u.into == nil {
		*u.into = map[string]string{}
	}
	(*u.into)[strings.TrimSpace(provider)] = strings.TrimSpace(target)
	return nil
}

func env(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if d, err := time.ParseDuration(env(key, "")); err == nil && d > 0 {
		return d
	}
	return fallback
}

func envInt(key string, fallback int) int {
	var n int
	if _, err := fmt.Sscanf(env(key, ""), "%d", &n); err == nil && n > 0 {
		return n
	}
	return fallback
}

// sorted returns s ordered, so a refusal reads the same every time.
func sorted(s []string) []string {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
	return s
}
