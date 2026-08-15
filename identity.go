package egress

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Identity is the caller boundary: it decides whether a request may spend, and
// on what.
//
// A caller proves itself with a projected service-account token — minted by the
// kubelet for this service, rotated under the caller, and never written to a
// Secret or an environment variable. Egress does not verify it itself; it asks
// the cluster, which is the authority on what its own tokens mean. That keeps
// revocation instant and leaves no signature checking here to get wrong.
//
// Two questions, kept apart:
//
//	which workload is this        — the cluster's answer, bound to an audience so
//	                                a token minted for another service cannot be
//	                                replayed here
//	may it spend on this provider — its grant
//
// A valid token is not a right to spend: every workload in the cluster has one.
type Identity struct {
	api      string
	audience string
	grants   map[string]map[string]bool
	client   *http.Client

	mu     sync.Mutex
	proven map[string]proof
}

type proof struct {
	subject string
	until   time.Time
}

// Caller is what a token proved, and what it may do with it.
type Caller struct {
	// Subject is the workload: `system:serviceaccount:<namespace>:<name>`.
	Subject string
	// granted is the caller's grant, keyed "provider:kind", held here so the
	// authorization decision travels with the identity that earned it.
	granted map[string]bool
}

// May reports whether this caller may make this kind of call on an upstream.
// Buying inference and reading the account behind it are granted separately.
func (c Caller) May(upstream string, k Kind) bool {
	return c.granted[upstream+":"+string(k)]
}

// proofTTL bounds how long the cluster's answer is reused. Short enough that a
// revoked workload stops spending promptly, long enough that a busy caller does
// not turn every call into a second call.
const proofTTL = time.Minute

// NewIdentity builds the boundary. api is the cluster API server, audience the
// value callers must have their token minted for, and grants the table of which
// workload may make which kind of call on which upstream.
//
// A grant is written `provider:kind` — `openrouter:inference` is not
// `openrouter:account`. An empty table is refused rather than read as "anyone":
// a deployment that forgot to say who may spend must not discover it by paying.
func NewIdentity(api, audience string, grants map[string][]string, client *http.Client) (*Identity, error) {
	api = strings.TrimRight(strings.TrimSpace(api), "/")
	if api == "" {
		return nil, fmt.Errorf("identity: empty cluster address")
	}
	if strings.TrimSpace(audience) == "" {
		return nil, fmt.Errorf("identity: empty audience")
	}
	if client == nil {
		return nil, fmt.Errorf("identity: no cluster client")
	}

	table := map[string]map[string]bool{}
	for subject, providers := range grants {
		subject = strings.TrimSpace(subject)
		if subject == "" {
			continue
		}
		allowed := map[string]bool{}
		for _, g := range providers {
			g = strings.TrimSpace(g)
			if g == "" {
				continue
			}
			provider, kind, ok := strings.Cut(g, ":")
			if !ok {
				return nil, fmt.Errorf("identity: grant %q must name a kind, as provider:kind", g)
			}
			if _, known := upstreams[provider]; !known {
				return nil, fmt.Errorf("identity: grant names unknown upstream %q", provider)
			}
			switch Kind(kind) {
			case Inference, Account:
			default:
				return nil, fmt.Errorf("identity: grant %q names unknown kind %q", g, kind)
			}
			allowed[provider+":"+kind] = true
		}
		if len(allowed) > 0 {
			table[subject] = allowed
		}
	}
	if len(table) == 0 {
		return nil, fmt.Errorf("identity: no workload is allowed to spend")
	}

	return &Identity{
		api: api, audience: strings.TrimSpace(audience),
		grants: table, client: client, proven: map[string]proof{},
	}, nil
}

// Check authenticates a request and returns the caller it proved.
//
// Every failure is one error to the caller — "forbidden" — because the
// difference between a bad token, a wrong audience and an ungranted workload is
// useful only to someone probing which of those they got right.
func (i *Identity) Check(r *http.Request) (Caller, error) {
	token := presented(r)
	if token == "" {
		return Caller{}, fmt.Errorf("no token")
	}

	subject, err := i.subject(r.Context(), token)
	if err != nil {
		return Caller{}, err
	}
	granted, ok := i.grants[subject]
	if !ok {
		return Caller{}, fmt.Errorf("workload holds no grant")
	}
	return Caller{Subject: subject, granted: granted}, nil
}

// subject asks the cluster who a token belongs to, reusing a recent answer.
//
// Only proven identities are remembered. Caching a refusal would let a token
// that has just been granted stay refused, and the refusal path is not the one
// under load.
func (i *Identity) subject(ctx context.Context, token string) (string, error) {
	sum := sha256.Sum256([]byte(token))
	key := string(sum[:])

	i.mu.Lock()
	if p, ok := i.proven[key]; ok && time.Now().Before(p.until) {
		i.mu.Unlock()
		return p.subject, nil
	}
	i.mu.Unlock()

	subject, err := i.review(ctx, token)
	if err != nil {
		return "", err
	}

	i.mu.Lock()
	// Sweep before inserting so a stream of distinct tokens cannot grow this
	// without bound.
	if len(i.proven) > 1024 {
		now := time.Now()
		for k, p := range i.proven {
			if now.After(p.until) {
				delete(i.proven, k)
			}
		}
	}
	i.proven[key] = proof{subject: subject, until: time.Now().Add(proofTTL)}
	i.mu.Unlock()
	return subject, nil
}

// review asks the cluster to authenticate one token for this service.
func (i *Identity) review(ctx context.Context, token string) (string, error) {
	body, err := json.Marshal(map[string]any{
		"apiVersion": "authentication.k8s.io/v1",
		"kind":       "TokenReview",
		"spec":       map[string]any{"token": token, "audiences": []string{i.audience}},
	})
	if err != nil {
		return "", fmt.Errorf("review: encode: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		i.api+"/apis/authentication.k8s.io/v1/tokenreviews", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("review: build: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := i.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("review: %w", err)
	}
	defer drain(resp)
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return "", fmt.Errorf("review: status %d", resp.StatusCode)
	}

	var out struct {
		Status struct {
			Authenticated bool     `json:"authenticated"`
			Audiences     []string `json:"audiences"`
			User          struct {
				Username string `json:"username"`
			} `json:"user"`
			Error string `json:"error"`
		} `json:"status"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("review: decode: %w", err)
	}
	if !out.Status.Authenticated {
		return "", fmt.Errorf("cluster refused the token")
	}
	// The cluster echoes the audiences it actually validated. A token minted for
	// another service authenticates fine but comes back without ours, and that
	// is exactly the replay this check exists to stop — so the answer is only
	// accepted when our audience is in it.
	if !contains(out.Status.Audiences, i.audience) {
		return "", fmt.Errorf("token was not minted for this service")
	}
	if out.Status.User.Username == "" {
		return "", fmt.Errorf("cluster named no workload")
	}
	return out.Status.User.Username, nil
}

func contains(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

func presented(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// ParseGrants reads the authorization table from its configured form:
//
//	system:serviceaccount:hanzo:cloud=openrouter:inference;system:serviceaccount:hanzo:treasury=openrouter:account
//
// Written out rather than inferred, because who may spend our money is a thing
// a reader should be able to see in full.
func ParseGrants(spec string) map[string][]string {
	out := map[string][]string{}
	for _, entry := range strings.Split(spec, ";") {
		subject, providers, ok := strings.Cut(strings.TrimSpace(entry), "=")
		if !ok {
			continue
		}
		subject = strings.TrimSpace(subject)
		if subject == "" {
			continue
		}
		out[subject] = append(out[subject], strings.Split(providers, ",")...)
	}
	return out
}
