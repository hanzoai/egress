package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/hanzoai/jwt"
)

// Principal is the identity a call spends under: the tenant that owns the
// credential and the person or program inside it.
//
// It is only ever built from a token this process verified. Nothing a caller
// writes in a request body reaches these fields, because they become the
// custody path — a caller that could name its own path could name another
// tenant's.
type Principal struct {
	// Org is the tenant, the `owner` claim.
	//
	// It is read from that claim and from nowhere else. A program's subject
	// reads `admin/hanzo-egress`, and the half before the slash is the org the
	// APPLICATION ROW is filed under — the reserved `admin` org, for every
	// application in the estate — while the tenant it acts for is `hanzo`.
	// Splitting the subject to find a tenant therefore roots every program's
	// credentials in the one org that means platform sudo.
	Org string
	// Kind is which of the two custody namespaces this principal lives in:
	// [Persons] or [Programs].
	//
	// This is the whole defence against one principal reaching another's
	// credentials, so it is worth saying why it is a namespace and not an
	// encoding. A person and a program are named by different things — an
	// opaque id, a client id — drawn from registries that never agreed to stay
	// out of each other's way. Any scheme that flattens both into one path
	// segment has to make them not collide, and the value that collides is one
	// an attacker CHOOSES: register the account or the app whose name, once
	// flattened, lands on the path already holding somebody's key.
	//
	// So they are not flattened. Each class gets its own namespace, spelled by
	// one of two constants in this package. No claim reaches this field, so no
	// name a caller picks can move it into the other class's half.
	Kind string
	// Name is the principal within that namespace: an opaque subject for a
	// person, a client id for a program. Both are unique to the issuer.
	//
	// For a person it is the subject, NOT the username. A username can be given
	// up and taken by somebody else, and a custody path keyed on one would hand
	// that somebody the previous holder's credentials.
	Name string
}

// The two custody namespaces. They are constants rather than anything derived
// because a namespace a token could name is not a boundary.
const (
	// Persons holds credentials belonging to people.
	Persons = "users"
	// Programs holds credentials belonging to applications.
	Programs = "apps"
)

// ErrAnonymous is what an unidentifiable caller gets. It carries no detail
// about why: the difference between "no token", "wrong audience" and "expired"
// is an oracle for somebody assembling a token, and none of it helps a caller
// that legitimately holds one.
var ErrAnonymous = errors.New("egress: caller is not identified")

// Verifier turns a bearer token into the principal that will be spending. It
// verifies against the issuer's published keys — egress checks IAM's signature,
// it never mints or holds an identity of its own.
type Verifier struct {
	issuer   string
	audience string
	ttl      time.Duration

	// fetch reads the JWKS document. A field so a test can supply one without
	// a network.
	fetch func(context.Context) ([]byte, error)

	mu   sync.Mutex
	keys []byte
	at   time.Time
}

// NewVerifier returns a Verifier that reads the issuer's key set from jwksURL
// and holds it for ttl.
func NewVerifier(issuer, audience, jwksURL string, ttl time.Duration) *Verifier {
	return &Verifier{
		issuer:   issuer,
		audience: audience,
		ttl:      ttl,
		fetch:    func(ctx context.Context) ([]byte, error) { return get(ctx, jwksURL) },
	}
}

// Verify returns the principal behind an Authorization header value, or
// ErrAnonymous. A token must name this issuer, carry this audience and carry an
// expiry — an audience-blind verifier accepts a token minted for a different
// app, and a token with no expiry never stops being spendable.
func (v *Verifier) Verify(ctx context.Context, authorization string) (Principal, error) {
	raw := bearer(authorization)
	if raw == "" {
		return Principal{}, ErrAnonymous
	}
	keys, err := v.keySet(ctx)
	if err != nil {
		return Principal{}, fmt.Errorf("%w: keys unavailable", ErrAnonymous)
	}
	claims, err := jwt.ParseJWKS(raw, keys,
		jwt.WithIssuer(v.issuer),
		jwt.WithAudience(v.audience),
		jwt.WithExpiryRequired(),
	)
	if err != nil || claims == nil {
		return Principal{}, ErrAnonymous
	}
	return identify(claims)
}

// identify reads the verified claims into the identity a call spends under.
//
// The class comes from the issuer's own `type`, which it resolves from the grant
// it answered. Reading it rather than inferring it is the point: the inference
// within reach here is the subject's shape, and a program's subject and a
// person's take the SAME `owner/name` form whenever a token names an account
// instead of its id. That inference files those people as programs, under a
// namespace where an application's name is what addresses a credential.
func identify(c *jwt.Claims) (Principal, error) {
	p := Principal{Kind: Persons}
	if c.User != nil {
		p.Org = c.Owner
		// The subject, or the `id` spelling of it from an issuer that mints
		// that instead. Both name the same thing; neither is the username.
		p.Name = c.Subject
		if p.Name == "" {
			p.Name = c.Id
		}
	}
	if c.Type == jwt.Program {
		// A program is addressed by the client id it authenticated as, which is
		// how the issuer told it apart from every other client. Its subject
		// carries the same name behind a slash it cannot be asked to lose.
		p.Kind, p.Name = Programs, c.Azp
	}
	// The claims are signed, so this is not a check on the caller — it is a
	// check on what may become a path segment. A credential's location must not
	// depend on an issuer never emitting a slash. A person whose subject names
	// the account rather than its id fails here, which is the right answer
	// twice over: the slash would leave the tenant, and the username would move
	// the credential the next time somebody else took the name.
	if !segment(p.Org) || !segment(p.Name) {
		return Principal{}, ErrAnonymous
	}
	return p, nil
}

// keySet returns the issuer's keys, refreshed at most once per ttl. A refresh
// that fails keeps the keys already held: they are still the issuer's keys, and
// refusing every call because a key endpoint blinked would be an outage we
// inflicted on ourselves. Keys that were never fetched are a different case —
// there is nothing to verify against, so the caller is anonymous.
func (v *Verifier) keySet(ctx context.Context) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	if v.keys != nil && time.Since(v.at) < v.ttl {
		return v.keys, nil
	}
	keys, err := v.fetch(ctx)
	if err != nil || len(keys) == 0 {
		if v.keys != nil {
			return v.keys, nil
		}
		if err == nil {
			err = errors.New("empty key set")
		}
		return nil, err
	}
	v.keys, v.at = keys, time.Now()
	return v.keys, nil
}

// bearer extracts the token from an Authorization header value.
func bearer(authorization string) string {
	const prefix = "bearer "
	if len(authorization) <= len(prefix) || !strings.EqualFold(authorization[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(authorization[len(prefix):])
}

// get reads a document over HTTPS, bounded in both time and size.
func get(ctx context.Context, url string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("get %s: %s", url, resp.Status)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// principalKey addresses the verified principal on a request context.
type principalKey struct{}

// with attaches the verified principal to ctx.
func with(ctx context.Context, p Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// principalOf recovers the verified principal. It reports absence rather than a
// zero value, so a handler reached without the gate refuses instead of spending
// under an empty tenant.
func principalOf(ctx context.Context) (Principal, bool) {
	p, ok := ctx.Value(principalKey{}).(Principal)
	return p, ok && p.Org != "" && p.Kind != "" && p.Name != ""
}
