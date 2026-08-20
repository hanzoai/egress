package egress

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/hanzoai/jwt"
)

const (
	issuer   = "https://hanzo.id"
	audience = "hanzo-egress"
)

// issuerKey is a signing key with a published certificate, the shape IAM's own
// key rows have.
func issuerKey(t *testing.T) jwt.Key {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return jwt.Key{
		Name:            "test",
		Certificate:     cert(t, priv, &priv.PublicKey),
		PrivateKey:      string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})),
		CryptoAlgorithm: "ES256",
	}
}

func cert(t *testing.T, signer crypto.Signer, pub any) string {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signer)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// token mints an access token the way IAM does, so the verifier under test
// meets the real claim shape.
func token(t *testing.T, key jwt.Key, edit func(*jwt.Claims)) string {
	t.Helper()
	now := time.Now()
	claims := &jwt.Claims{
		// No `id`. IAM does not mint one — it states the subject and nothing
		// else — and a fixture that carries one tests a token the issuer never
		// sends.
		User: &jwt.User{Owner: "acme", Name: "alice", Email: "alice@acme.example"},
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "u-7",
			Audience:  jwt.ClaimStrings{audience},
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			IssuedAt:  jwt.NewNumericDate(now),
		},
	}
	if edit != nil {
		edit(claims)
	}
	raw, err := jwt.Sign(key, claims)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// verifier returns a Verifier reading a key set held in memory.
func verifier(t *testing.T, keys ...jwt.Key) *Verifier {
	t.Helper()
	set, err := jwt.BuildJWKS(keys...)
	if err != nil {
		t.Fatal(err)
	}
	v := NewVerifier(issuer, audience, "", time.Minute)
	v.fetch = func(context.Context) ([]byte, error) { return set, nil }
	return v
}

func TestTheTenantAndUserComeFromTheToken(t *testing.T) {
	key := issuerKey(t)
	p, err := verifier(t, key).Verify(context.Background(), "Bearer "+token(t, key, nil))
	if err != nil {
		t.Fatal(err)
	}
	if p.Org != "acme" {
		t.Errorf("org = %q, want acme", p.Org)
	}
	// The subject, not the username: a username can be given up and taken by
	// somebody else, and the custody path must not move with it.
	if p.Name != "u-7" {
		t.Errorf("name = %q, want the subject u-7", p.Name)
	}
	if p.Kind != Persons {
		t.Errorf("kind = %q, want %q", p.Kind, Persons)
	}
}

func TestAnUnidentifiableCallerIsRefused(t *testing.T) {
	key := issuerKey(t)
	other := issuerKey(t)
	v := verifier(t, key)

	headers := map[string]string{
		"no header":    "",
		"not a bearer": "Basic abc",
		"empty bearer": "Bearer ",
		"not a token":  "Bearer not.a.token",
	}
	tokens := map[string]func(*jwt.Claims){
		"another issuer":  func(c *jwt.Claims) { c.Issuer = "https://evil.example" },
		"another app":     func(c *jwt.Claims) { c.Audience = jwt.ClaimStrings{"hanzo-console"} },
		"no audience":     func(c *jwt.Claims) { c.Audience = nil },
		"no expiry":       func(c *jwt.Claims) { c.ExpiresAt = nil },
		"expired":         func(c *jwt.Claims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) },
		"no owner":        func(c *jwt.Claims) { c.Owner = "" },
		"no subject":      func(c *jwt.Claims) { c.Subject, c.Id = "", "" },
		"path in owner":   func(c *jwt.Claims) { c.Owner = "acme/../admin" },
		"path in subject": func(c *jwt.Claims) { c.Subject, c.Id = "../../root", "" },
		// A person whose subject names the account rather than its id. IAM
		// resolves that form to a person, so it is not a program — and it must
		// not become a custody key either, because the next holder of the name
		// would inherit the credentials filed under it.
		"named subject": func(c *jwt.Claims) { c.Subject, c.Id = "acme/alice", "" },
		// A program with no client id has nothing to be addressed by.
		"program with no client": func(c *jwt.Claims) { c.Type, c.Azp = jwt.Program, "" },
		"path in client":         func(c *jwt.Claims) { c.Type, c.Azp = jwt.Program, "../../root" },
	}
	for name, edit := range tokens {
		headers[name] = "Bearer " + token(t, key, edit)
	}
	headers["another key"] = "Bearer " + token(t, other, nil)

	for name, header := range headers {
		t.Run(name, func(t *testing.T) {
			p, err := v.Verify(context.Background(), header)
			if err == nil {
				t.Fatalf("verified %+v", p)
			}
			if !errors.Is(err, ErrAnonymous) {
				t.Fatalf("err = %v, want ErrAnonymous", err)
			}
		})
	}
}

func TestKeysAlreadyHeldSurviveAnIssuerThatBlinks(t *testing.T) {
	key := issuerKey(t)
	set, err := jwt.BuildJWKS(key)
	if err != nil {
		t.Fatal(err)
	}
	up := true
	v := NewVerifier(issuer, audience, "", time.Nanosecond)
	v.fetch = func(context.Context) ([]byte, error) {
		if !up {
			return nil, errors.New("dial: connection refused")
		}
		return set, nil
	}

	if _, err := v.Verify(context.Background(), "Bearer "+token(t, key, nil)); err != nil {
		t.Fatal(err)
	}
	up = false
	if _, err := v.Verify(context.Background(), "Bearer "+token(t, key, nil)); err != nil {
		t.Fatalf("a blinking key endpoint refused a good token: %v", err)
	}
}

func TestWithNoKeysAtAllEveryCallerIsAnonymous(t *testing.T) {
	key := issuerKey(t)
	v := NewVerifier(issuer, audience, "", time.Minute)
	v.fetch = func(context.Context) ([]byte, error) { return nil, errors.New("dial: connection refused") }

	if _, err := v.Verify(context.Background(), "Bearer "+token(t, key, nil)); !errors.Is(err, ErrAnonymous) {
		t.Fatalf("err = %v, want ErrAnonymous", err)
	}
}

func TestAPrincipalIsNeverRecoveredFromAnUngatedContext(t *testing.T) {
	if p, ok := principalOf(context.Background()); ok {
		t.Fatalf("a bare context yielded %+v", p)
	}
	if _, ok := principalOf(with(context.Background(), Principal{Org: "acme"})); ok {
		t.Fatal("a half-built principal was accepted")
	}
	if p, ok := principalOf(with(context.Background(), alice)); !ok || p != alice {
		t.Fatalf("principalOf = %+v,%v", p, ok)
	}
}
