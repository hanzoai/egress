package egress

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// self is this service's own identity at IAM: the client id it is configured
// with (-client-id) and the client secret sealed on this host, the same pair the
// https store transport signs in with. There is no second identity. An AWS role
// that egress may assume trusts this one — its issuer, its audience, its
// subject — so it is what egress presents to STS, and a caller's token never is.
type self struct {
	iam string
	id  string
	// secret reads the sealed client secret. It is read for each exchange and
	// dropped after it, so no copy outlives the request that needed it.
	secret func() (string, error)
	client *http.Client
}

// token mints an access token for this service with IAM's client_credentials
// grant. The client credential is form-encoded under Basic (RFC 6749 §2.3.1),
// so a secret carrying '+' or '%' authenticates. It is minted for each role
// exchange and not kept: what the exchange buys is what is kept.
func (s *self) token(ctx context.Context) (string, error) {
	if s.iam == "" || s.id == "" {
		return "", errors.New("egress: no IAM identity of its own: set -iam and -client-id")
	}
	secret, err := s.secret()
	if err != nil {
		return "", fmt.Errorf("egress: %w", err)
	}
	form := url.Values{"grant_type": {"client_credentials"}}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.iam+"/v1/iam/oauth/token",
		strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.SetBasicAuth(url.QueryEscape(s.id), url.QueryEscape(secret))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := s.client.Do(req)
	if err != nil {
		return "", scrub(fmt.Errorf("egress: iam: %w", err), secret)
	}
	defer func() { _ = resp.Body.Close() }()
	var out struct {
		AccessToken string `json:"access_token"`
		Error       string `json:"error"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<16)).Decode(&out); err != nil {
		return "", fmt.Errorf("egress: iam answered %d with no readable body", resp.StatusCode)
	}
	if resp.StatusCode != http.StatusOK || out.AccessToken == "" {
		return "", fmt.Errorf("egress: iam refused client %q: %d %s", s.id, resp.StatusCode, out.Error)
	}
	return out.AccessToken, nil
}
