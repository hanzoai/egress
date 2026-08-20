package egress

import (
	"context"
	"errors"
	"fmt"
	"strings"

	kms "github.com/hanzoai/kms/sdk/go"
	"github.com/luxfi/kms/pkg/zapclient"
)

// Secrets is where credentials are kept. It is the same read/write pair
// hanzoai/ai declares as object.SecretStore, method for method, so one value
// satisfies both interfaces and there is one seam in the estate rather than
// two. What differs is what sits behind it: in ai the store is in-process,
// here it is KMS across the network.
//
// ref is a flat reference, path segments then the name:
//
//	orgs/acme/users/u-7/connectors/openai/default
type Secrets interface {
	GetSecret(ctx context.Context, ref string) ([]byte, error)
	PutSecret(ctx context.Context, ref string, value []byte) error
}

// ErrNoCredential means no credential is enrolled for this principal and
// provider. It is a refusal, never a fallback: reading a key out of this
// process's environment is the exposure egress exists to remove, so an absent
// credential ends the call.
var ErrNoCredential = errors.New("egress: no credential")

// Custody scopes. A call reports which one paid, because that is the difference
// between a customer's vendor bill and ours.
const (
	// ScopeUser is the customer's own key, enrolled by them, spent only for
	// them.
	ScopeUser = "user"
	// ScopeOrg is the platform key the tenant shares.
	ScopeOrg = "org"
)

// userRef is where a customer's own key lives. Built from the validated
// principal — this line is the tenant boundary.
func userRef(p Principal, provider, label string) string {
	return "orgs/" + p.Org + "/users/" + p.User + "/connectors/" + provider + "/" + label
}

// orgRef is where the tenant's shared platform key lives.
func orgRef(p Principal, provider, label string) string {
	return "orgs/" + p.Org + "/cloud/" + provider + "/" + label
}

// segment reports whether s may be one segment of a custody path. The rule is
// an allowlist rather than a search for bad input: a separator or a parent
// reference cannot be spelled with these characters at all, so a path built
// from segments that pass cannot leave the tenant it was built for.
func segment(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case (c == '-' || c == '_') && i > 0:
		default:
			return false
		}
	}
	return true
}

// slug is the one mapping from a provider as ai spells it ("Amazon Bedrock") to
// the segment its credential lives under ("amazon-bedrock"). It rejects
// anything it cannot spell rather than dropping it, because two provider names
// that differ only in a dropped character would share one credential.
func slug(provider string) (string, bool) {
	var b strings.Builder
	for i := 0; i < len(provider); i++ {
		c := provider[i]
		switch {
		case c >= 'A' && c <= 'Z':
			b.WriteByte(c + ('a' - 'A'))
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9':
			b.WriteByte(c)
		case c == ' ' && i > 0:
			b.WriteByte('-')
		default:
			return "", false
		}
	}
	s := b.String()
	if !segment(s) {
		return "", false
	}
	return s, true
}

// custody resolves credentials and keeps none. A value read lives for the call
// that read it and nowhere else — there is no map to find one in, so there is
// nothing for a core dump, a heap profile or another tenant's call to reach.
//
// Reading every time is also what makes rotation a KMS write rather than a
// deploy: a key rewritten there is in use on the next call, not the next
// window.
type custody struct {
	store Secrets
}

func newCustody(store Secrets) *custody {
	return &custody{store: store}
}

// resolve returns the credential to spend for this principal and provider, and
// which custody paid. The customer's own key wins over the platform's: a tenant
// that brought a key expects it to be the one spent.
//
// It never returns the credential to a caller — only to the call that is about
// to make an upstream request with it. There is no other reader.
func (c *custody) resolve(ctx context.Context, p Principal, provider, label string) (string, string, error) {
	own, err := c.read(ctx, userRef(p, provider, label))
	if err != nil {
		return "", "", err
	}
	if own != "" {
		return own, ScopeUser, nil
	}
	shared, err := c.read(ctx, orgRef(p, provider, label))
	if err != nil {
		return "", "", err
	}
	if shared != "" {
		return shared, ScopeOrg, nil
	}
	return "", "", ErrNoCredential
}

// enroll seals a customer's own key. It is write-only: nothing in this package
// reads a credential back out to a caller, so a key that goes in here can be
// spent and never shown — not to the customer who supplied it, not to an
// operator.
func (c *custody) enroll(ctx context.Context, p Principal, provider, label, key string) error {
	if err := c.store.PutSecret(ctx, userRef(p, provider, label), []byte(key)); err != nil {
		return fmt.Errorf("egress: seal: %w", err)
	}
	return nil
}

// read returns the value at ref. An absent secret is ("", nil) — the normal
// state of a tenant that brought no key of its own, and the reason the caller
// falls through to the shared one. A store that cannot answer is an error and
// ends the call: an unreachable KMS must not become a reason to look somewhere
// less guarded.
func (c *custody) read(ctx context.Context, ref string) (string, error) {
	value, err := c.store.GetSecret(ctx, ref)
	if err != nil {
		if !absent(err) {
			return "", fmt.Errorf("egress: read credential: %w", err)
		}
		return "", nil
	}
	return strings.TrimSpace(string(value)), nil
}

// absent reports whether an error means "no such secret" rather than "the store
// could not answer". The two are opposite signals: the first is the ordinary
// state of a tenant with no key of its own and sends the caller on to the shared
// key, the second is a fault that must end the call.
//
// Asked by identity, never by wording. The store reports a fault by echoing the
// response body into the error, so a 500 whose body happens to contain "not
// found" — an authorization failure, a proxy's error page, a tenant that no
// longer exists — used to read as absence. That is the one misreading whose cost
// is a customer's own key being passed over in favour of the platform's while
// theirs was merely unreadable, and the meter then recording it as intended.
func absent(err error) bool {
	return errors.Is(err, kms.ErrSecretNotFound) || errors.Is(err, zapclient.ErrNotFound)
}
