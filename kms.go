package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// KMS reads sealed credentials from the Hanzo KMS secrets plane.
//
// Egress is a callerless consumer — it refreshes on a timer, not inside anyone's
// request — so it authenticates with its own client_credentials identity, the
// same standing-identity path the KMS operator uses. That identity is a MEMBER
// of the org holding the credential and nothing more: the plane requires admin
// scope to write, so egress can read its credential and cannot change it.
type KMS struct {
	base   string // secrets plane root, e.g. https://kms.hanzo.ai
	id     string // IAM client id
	secret string // IAM client secret
	env    string // secret environment, e.g. prod

	client *http.Client

	mu      sync.Mutex
	token   string
	expires time.Time
}

// NewKMS builds a client against the secrets plane at base. Every argument is
// required: a KMS client that cannot prove who it is has nothing to offer.
func NewKMS(base, id, secret, env string, client *http.Client) (*KMS, error) {
	base = strings.TrimRight(strings.TrimSpace(base), "/")
	switch {
	case base == "":
		return nil, fmt.Errorf("kms: empty address")
	case id == "" || secret == "":
		return nil, fmt.Errorf("kms: empty identity")
	case env == "":
		return nil, fmt.Errorf("kms: empty environment")
	}
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	return &KMS{base: base, id: id, secret: secret, env: env, client: client}, nil
}

// Get resolves one secret by its reference and returns the plaintext.
//
// A reference is the secret's coordinate WITHIN the reading identity's org —
// `ai/OPENROUTER_API_KEY`, not `OPENROUTER_API_KEY`. Both halves matter and both
// are easy to get wrong in the same silent way:
//
//	the path, because a bare name resolves to the org root while records are
//	written under a subpath, and the store answers a different partition rather
//	than an error
//	the environment, because omitting it falls back to a default environment
//	while the fleet writes `prod`
//
// Either mistake returns "not found" for a secret that plainly exists, so the
// full coordinate is always sent.
func (k *KMS) Get(ctx context.Context, ref string) (string, error) {
	token, err := k.bearer(ctx)
	if err != nil {
		return "", err
	}
	// Escape each segment, never the whole reference: escaping the separators
	// would ask for one secret whose name contains slashes.
	segments := strings.Split(strings.Trim(ref, "/"), "/")
	for i, s := range segments {
		segments[i] = url.PathEscape(s)
	}
	name := strings.Join(segments, "/")
	addr := k.base + "/v1/kms/secrets/" + name + "?env=" + url.QueryEscape(k.env)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	if err != nil {
		return "", fmt.Errorf("kms: build request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("kms: get %s: %w", ref, err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		// The status alone is the diagnosis; the body may quote the record.
		return "", fmt.Errorf("kms: get %s: status %d", ref, resp.StatusCode)
	}
	var out struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("kms: decode %s: %w", ref, err)
	}
	if out.Value == "" {
		return "", fmt.Errorf("kms: %s is empty", ref)
	}
	return out.Value, nil
}

// bearer returns a valid access token, exchanging the client credential for a
// new one when the cached token is within a minute of expiry.
func (k *KMS) bearer(ctx context.Context) (string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.token != "" && time.Now().Add(time.Minute).Before(k.expires) {
		return k.token, nil
	}

	body, err := json.Marshal(map[string]string{"clientId": k.id, "clientSecret": k.secret})
	if err != nil {
		return "", fmt.Errorf("kms: encode login: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, k.base+"/v1/kms/auth/login", bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("kms: build login: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := k.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("kms: login: %w", err)
	}
	defer drain(resp)

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("kms: login: status %d", resp.StatusCode)
	}
	var out struct {
		AccessToken string `json:"accessToken"`
		ExpiresIn   int    `json:"expiresIn"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("kms: decode login: %w", err)
	}
	if out.AccessToken == "" {
		return "", fmt.Errorf("kms: login returned no token")
	}
	ttl := time.Duration(out.ExpiresIn) * time.Second
	if ttl <= 0 {
		ttl = 30 * time.Minute
	}
	k.token, k.expires = out.AccessToken, time.Now().Add(ttl)
	return k.token, nil
}
