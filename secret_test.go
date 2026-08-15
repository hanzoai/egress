package egress

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

// store is a credential store a test controls completely. The seam is the same
// two methods the real KMS client implements, which is the whole reason egress
// can be exercised without one.
type store struct {
	mu    sync.Mutex
	held  map[string]string
	fail  error
	reads int
}

func newStore(pairs map[string]string) *store {
	s := &store{held: map[string]string{}}
	for k, v := range pairs {
		s.held[k] = v
	}
	return s
}

func (s *store) GetSecret(_ context.Context, ref string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.fail != nil {
		return nil, s.fail
	}
	v, ok := s.held[ref]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return []byte(v), nil
}

func (s *store) PutSecret(_ context.Context, ref string, value []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fail != nil {
		return s.fail
	}
	s.held[ref] = string(value)
	return nil
}

func (s *store) at(ref string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.held[ref]
}

func (s *store) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reads
}

var alice = Principal{Org: "acme", User: "u-7"}

func TestSegmentAdmitsOnlyWhatCannotLeaveATenant(t *testing.T) {
	for _, ok := range []string{"acme", "u-7", "u_7", "openai", "default", "a1", strings.Repeat("a", 64)} {
		if !segment(ok) {
			t.Errorf("segment(%q) = false, want true", ok)
		}
	}
	for _, bad := range []string{
		"", "..", ".", "/", "a/b", "../etc", "..%2f", "a b", "a.b", "-lead", "_lead",
		"acme/users/root", "acme\\evil", "é", strings.Repeat("a", 65), "a\x00b", "a\nb",
	} {
		if segment(bad) {
			t.Errorf("segment(%q) = true, want false", bad)
		}
	}
}

func TestSlugNamesTheCredentialOrRefuses(t *testing.T) {
	for in, want := range map[string]string{
		"OpenAI": "openai", "OpenRouter": "openrouter", "Claude": "claude",
		"Fireworks": "fireworks", "DigitalOcean": "digitalocean", "Amazon Bedrock": "amazon-bedrock",
	} {
		got, ok := slug(in)
		if !ok || got != want {
			t.Errorf("slug(%q) = %q,%v; want %q,true", in, got, ok, want)
		}
	}
	for _, bad := range []string{"", "../../etc", "a/b", " OpenAI", "Open/AI", "open.ai", "открытый"} {
		if got, ok := slug(bad); ok {
			t.Errorf("slug(%q) = %q,true; want refusal", bad, got)
		}
	}
}

func TestCustodyPathIsBuiltFromThePrincipal(t *testing.T) {
	bob := Principal{Org: "other", User: "u-9"}
	if got, want := userRef(alice, "openai", "default"), "orgs/acme/users/u-7/connectors/openai/default"; got != want {
		t.Errorf("userRef = %q, want %q", got, want)
	}
	if got, want := orgRef(alice, "openai", "default"), "orgs/acme/cloud/openai/default"; got != want {
		t.Errorf("orgRef = %q, want %q", got, want)
	}
	if userRef(alice, "openai", "default") == userRef(bob, "openai", "default") {
		t.Error("two principals share one custody path")
	}
	if !strings.HasPrefix(userRef(bob, "openai", "default"), "orgs/other/") {
		t.Error("a principal's path escaped its tenant")
	}
}

func TestTheTenantsOwnKeyOutranksTheSharedOne(t *testing.T) {
	s := newStore(map[string]string{
		userRef(alice, "openai", "default"): "sk-theirs",
		orgRef(alice, "openai", "default"):  "sk-ours",
	})
	key, scope, err := newCustody(s, time.Minute).resolve(context.Background(), alice, "openai", "default")
	if err != nil {
		t.Fatal(err)
	}
	if key != "sk-theirs" || scope != ScopeUser {
		t.Errorf("resolved %q/%s, want sk-theirs/%s", key, scope, ScopeUser)
	}
}

func TestTheSharedKeyServesATenantThatBroughtNone(t *testing.T) {
	s := newStore(map[string]string{orgRef(alice, "openai", "default"): "sk-ours"})
	key, scope, err := newCustody(s, time.Minute).resolve(context.Background(), alice, "openai", "default")
	if err != nil {
		t.Fatal(err)
	}
	if key != "sk-ours" || scope != ScopeOrg {
		t.Errorf("resolved %q/%s, want sk-ours/%s", key, scope, ScopeOrg)
	}
}

// An absent credential must end the call. The environment of this process is
// exactly where a provider key used to live, so a resolver that reads one on
// the way past would put the exposure back.
func TestAnAbsentCredentialIsRefusedRatherThanFoundElsewhere(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "sk-from-the-environment")
	t.Setenv("OPENAI", "sk-from-the-environment")
	t.Setenv("openai", "sk-from-the-environment")

	key, scope, err := newCustody(newStore(nil), time.Minute).resolve(context.Background(), alice, "openai", "default")
	if !errors.Is(err, ErrNoCredential) {
		t.Fatalf("err = %v, want ErrNoCredential", err)
	}
	if key != "" || scope != "" {
		t.Fatalf("resolved %q/%s from nowhere", key, scope)
	}
	if strings.Contains(key, os.Getenv("OPENAI_API_KEY")) {
		t.Fatal("the environment answered")
	}
}

func TestAStoreThatCannotAnswerEndsTheCall(t *testing.T) {
	s := newStore(map[string]string{orgRef(alice, "openai", "default"): "sk-ours"})
	s.fail = errors.New("cek: message authentication failed")

	_, _, err := newCustody(s, time.Minute).resolve(context.Background(), alice, "openai", "default")
	if err == nil {
		t.Fatal("a broken store served a call")
	}
	if errors.Is(err, ErrNoCredential) {
		t.Fatal("a fault was reported as an absence")
	}
}

func TestACredentialIsHeldOnlyForItsWindow(t *testing.T) {
	s := newStore(map[string]string{userRef(alice, "openai", "default"): "sk-theirs"})
	c := newCustody(s, 40*time.Millisecond)

	for i := 0; i < 3; i++ {
		if _, _, err := c.resolve(context.Background(), alice, "openai", "default"); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.count(); got != 1 {
		t.Errorf("%d reads inside the window, want 1", got)
	}

	time.Sleep(60 * time.Millisecond)
	if _, _, err := c.resolve(context.Background(), alice, "openai", "default"); err != nil {
		t.Fatal(err)
	}
	if got := s.count(); got != 2 {
		t.Errorf("%d reads after the window, want 2 — a rotated key would not be picked up", got)
	}
}

func TestEnrollingReplacesWhatWasHeld(t *testing.T) {
	s := newStore(map[string]string{userRef(alice, "openai", "default"): "sk-old"})
	c := newCustody(s, time.Hour)

	if key, _, _ := c.resolve(context.Background(), alice, "openai", "default"); key != "sk-old" {
		t.Fatalf("first resolve = %q", key)
	}
	if err := c.enroll(context.Background(), alice, "openai", "default", "sk-new"); err != nil {
		t.Fatal(err)
	}
	key, _, err := c.resolve(context.Background(), alice, "openai", "default")
	if err != nil {
		t.Fatal(err)
	}
	if key != "sk-new" {
		t.Errorf("resolved %q after enrolling, want sk-new — the old key outlived its replacement", key)
	}
}

func TestEnrollingWritesUnderTheEnrollersOwnPath(t *testing.T) {
	s := newStore(nil)
	if err := newCustody(s, time.Minute).enroll(context.Background(), alice, "openai", "default", "sk-theirs"); err != nil {
		t.Fatal(err)
	}
	if got := s.at(userRef(alice, "openai", "default")); got != "sk-theirs" {
		t.Errorf("key landed at %q", got)
	}
	if got := s.at(orgRef(alice, "openai", "default")); got != "" {
		t.Error("a customer's key was written to the shared path")
	}
}

func TestTheCredentialIsRemovedFromAnError(t *testing.T) {
	key := "sk-live-9f3c"
	err := errors.New(`401 invalid api key: sk-live-9f3c`)
	got := scrub(err, key)
	if strings.Contains(got.Error(), key) {
		t.Fatalf("the credential travelled in an error: %q", got)
	}
	if !strings.Contains(got.Error(), "[redacted]") {
		t.Errorf("scrubbed error lost its shape: %q", got)
	}
	if scrub(nil, key) != nil {
		t.Error("scrub invented an error")
	}
}
