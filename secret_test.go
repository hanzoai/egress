package egress

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"

	kms "github.com/hanzoai/kms/sdk/go"
)

// store is a credential store a test controls completely. The seam is the same
// two methods the real KMS client implements, which is the whole reason egress
// can be exercised without one.
type store struct {
	mu sync.Mutex
	// held is what the store has. A ref that is not here is absent, and the
	// store says so the way the real one does — with the sentinel, not with a
	// phrase — so a test cannot pass on wording the store never promised.
	held map[string]string
	// fail is returned instead of answering. failOn narrows it to a single
	// ref, which is what makes it possible to break one custody and watch
	// whether the other one still gets spent.
	fail   error
	failOn string
	reads  int
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
	if s.fail != nil && (s.failOn == "" || s.failOn == ref) {
		return nil, s.fail
	}
	v, ok := s.held[ref]
	if !ok {
		return nil, fmt.Errorf("kmsclient: secret %s: %w", ref, kms.ErrSecretNotFound)
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

var alice = Principal{Org: "acme", Kind: Persons, Name: "u-7"}

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
	bob := Principal{Org: "other", Kind: Persons, Name: "u-9"}
	if got, want := ownRef(alice, "openai", "default"), "orgs/acme/users/u-7/connectors/openai/default"; got != want {
		t.Errorf("userRef = %q, want %q", got, want)
	}
	if got, want := orgRef(alice, "openai", "default"), "orgs/acme/cloud/openai/default"; got != want {
		t.Errorf("orgRef = %q, want %q", got, want)
	}
	if ownRef(alice, "openai", "default") == ownRef(bob, "openai", "default") {
		t.Error("two principals share one custody path")
	}
	if !strings.HasPrefix(ownRef(bob, "openai", "default"), "orgs/other/") {
		t.Error("a principal's path escaped its tenant")
	}
}

func TestTheTenantsOwnKeyOutranksTheSharedOne(t *testing.T) {
	s := newStore(map[string]string{
		ownRef(alice, "openai", "default"): "sk-theirs",
		orgRef(alice, "openai", "default"):  "sk-ours",
	})
	key, scope, err := newCustody(s).resolve(context.Background(), alice, "openai", "default")
	if err != nil {
		t.Fatal(err)
	}
	if key != "sk-theirs" || scope != ScopeUser {
		t.Errorf("resolved %q/%s, want sk-theirs/%s", key, scope, ScopeUser)
	}
}

func TestTheSharedKeyServesATenantThatBroughtNone(t *testing.T) {
	s := newStore(map[string]string{orgRef(alice, "openai", "default"): "sk-ours"})
	key, scope, err := newCustody(s).resolve(context.Background(), alice, "openai", "default")
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

	key, scope, err := newCustody(newStore(nil)).resolve(context.Background(), alice, "openai", "default")
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

	_, _, err := newCustody(s).resolve(context.Background(), alice, "openai", "default")
	if err == nil {
		t.Fatal("a broken store served a call")
	}
	if errors.Is(err, ErrNoCredential) {
		t.Fatal("a fault was reported as an absence")
	}
}

// The store reports a fault by echoing the response body, so its text is written
// by whatever failed — an authorization refusal, a proxy's error page, a tenant
// that no longer exists. Any of them can contain the words "not found" while
// meaning the opposite of an absent secret.
//
// The cost of confusing them is specific: alice brought her own key, the read of
// it stuttered, and the fallthrough spends the platform's key instead — then the
// meter records scope "org", which is the difference between her vendor bill and
// ours. So the fault must end the call, and it must do so while her key is
// present and the shared one is sitting right there, resolvable.
func TestAFaultWordedLikeAnAbsenceDoesNotSpendTheSharedKey(t *testing.T) {
	s := newStore(map[string]string{
		ownRef(alice, "openai", "default"): "sk-hers",
		orgRef(alice, "openai", "default"):  "sk-ours",
	})
	s.fail = errors.New("kmsclient: status 500: {\"error\":\"upstream tenant not found\"}")
	s.failOn = ownRef(alice, "openai", "default")

	key, scope, err := newCustody(s).resolve(context.Background(), alice, "openai", "default")
	if err == nil {
		t.Fatalf("a store fault served a call: resolved %s custody", scope)
	}
	if key == "sk-ours" {
		t.Fatal("her key was unreadable, so ours was spent and billed as intended")
	}
	if errors.Is(err, ErrNoCredential) {
		t.Fatal("a fault was reported as an absence")
	}
}

// A credential must not outlive the call that read it. There is no window in
// which one is resident here, so every call reads it again — which is also why
// a key rewritten in KMS is spent on the next call rather than the next minute.
func TestACredentialIsNotKeptBetweenCalls(t *testing.T) {
	s := newStore(map[string]string{ownRef(alice, "openai", "default"): "sk-theirs"})
	c := newCustody(s)

	for i := 1; i <= 3; i++ {
		if _, _, err := c.resolve(context.Background(), alice, "openai", "default"); err != nil {
			t.Fatal(err)
		}
		if got := s.count(); got != i {
			t.Fatalf("%d reads after %d calls — a call spent a credential this process was keeping", got, i)
		}
	}
}

func TestEnrollingReplacesWhatWasHeld(t *testing.T) {
	s := newStore(map[string]string{ownRef(alice, "openai", "default"): "sk-old"})
	c := newCustody(s)

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
	if err := newCustody(s).enroll(context.Background(), alice, "openai", "default", "sk-theirs"); err != nil {
		t.Fatal(err)
	}
	if got := s.at(ownRef(alice, "openai", "default")); got != "sk-theirs" {
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

// TestTheCredentialIsRemovedFromAnErrorInPieces covers what providers
// actually send back. A rejected key is rarely quoted whole: OpenAI answers
// with the first segment and the last four characters joined by asterisks,
// others truncate after a prefix, and a key carried in a basic-auth header
// comes back base64. Each of those is a piece of the credential, and a piece
// is worth having.
func TestTheCredentialIsRemovedFromAnErrorInPieces(t *testing.T) {
	const key = "sk-proj-4tHhQ2vLm8XnPqRs7WdYbGjK1cZeUfAz9q7x"
	cases := []struct {
		name string
		text string
		gone []string
	}{
		{
			"masked, as OpenAI sends it",
			`401 Incorrect API key provided: sk-proj-****************************9q7x. ` +
				`You can find your API key at https://platform.openai.com/account/api-keys.`,
			[]string{"sk-proj-", "9q7x"},
		},
		{
			"truncated after a prefix",
			`invalid api key: sk-proj-4tHhQ2vLm8...`,
			[]string{"sk-proj-4tHhQ2vLm8"},
		},
		{
			"the last characters alone",
			`the key ending 9q7x was revoked`,
			[]string{"9q7x"},
		},
		{
			"whole",
			`401 invalid api key: ` + key,
			[]string{key},
		},
		{
			"base64, as a basic-auth header carries it",
			`401 rejected credential ` + base64.StdEncoding.EncodeToString([]byte(key+":")),
			[]string{base64.StdEncoding.EncodeToString([]byte(key + ":"))[:24]},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := scrub(errors.New(c.text), key).Error()
			for _, piece := range c.gone {
				if strings.Contains(got, piece) {
					t.Errorf("a piece of the credential travelled in an error: %q is still in %q", piece, got)
				}
			}
			if !strings.Contains(got, "[redacted]") {
				t.Errorf("scrubbed error lost its shape: %q", got)
			}
		})
	}
}

// TestAnErrorThatSharesNothingWithTheCredentialIsLeftAlone is the other half.
// Redacting by what two strings have in common only works if it stops at what
// they have in common — an error that says nothing about the key has to reach
// the caller intact, or the scrub has traded a leak for a service nobody can
// debug.
func TestAnErrorThatSharesNothingWithTheCredentialIsLeftAlone(t *testing.T) {
	const key = "sk-proj-4tHhQ2vLm8XnPqRs7WdYbGjK1cZeUfAz9q7x"
	for _, text := range []string{
		"429 rate limit exceeded, please retry after 20 seconds",
		"model gpt-5-turbo does not exist or you do not have access to it",
		"400 this model's maximum context length is 128000 tokens",
		"context deadline exceeded",
		"upstream returned nothing",
	} {
		got := scrub(errors.New(text), key)
		if got.Error() != text {
			t.Errorf("an error with nothing of the credential in it was changed:\n  before %q\n  after  %q", text, got.Error())
		}
	}
}
