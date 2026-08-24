package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/hanzoai/egress/spend"
	"github.com/zap-proto/zip"
	"strings"
	"time"
)

// clouds are the clouds egress can spend on, and where each one's API answers.
//
// Where DigitalOcean's API lives is a fact about DigitalOcean, not a choice this
// deployment makes, so it is stated here once rather than typed into every host's
// configuration. That an operator does not name it costs nothing: the rule that
// matters is that the CALLER cannot, and the caller has no field for it either
// way. It is the same shape as a model dialect, which carries its vendor's
// endpoint and is asked for a fallback only when a deployment overrides one.
//
// Membership is also the allowlist. A cloud here carries its credential as a
// bearer token; a cloud that signs its requests instead — AWS, and anything else
// on SigV4 — cannot be served by attaching a header, so it is absent and refused
// rather than sent upstream with a header it will reject. Adding a cloud is
// therefore one line written by someone who worked out both halves, and there is
// no second table to agree with.
var clouds = map[string]string{
	"digitalocean": "https://api.digitalocean.com",
	"hetzner":      "https://api.hetzner.cloud",
}

// ErrNotCarried is what a cloud egress cannot pay for gets.
var ErrNotCarried = errors.New("egress: credential cannot be carried for this provider")

// upstream is where a cloud's API answers: what egress knows, unless this host
// overrode it. An override serves a regional or sovereign endpoint, and a test
// pointing at a server of its own; it can only move a cloud egress already
// carries, never admit one it cannot pay for.
func (s *Server) upstream(provider string) (string, bool) {
	api, ok := clouds[provider]
	if !ok {
		return "", false
	}
	if override := s.cfg.URLs[provider]; override != "" {
		return override, true
	}
	return api, true
}

// verbs are the methods a cloud call may use. CONNECT and TRACE are absent
// because no cloud API uses them and both are useful only for reaching something
// other than the API.
var verbs = map[string]bool{
	http.MethodGet: true, http.MethodHead: true, http.MethodPost: true,
	http.MethodPut: true, http.MethodPatch: true, http.MethodDelete: true,
}

// mostBody is the largest answer egress will read from a cloud. A list of every
// droplet in a large account is tens of kilobytes; a megabyte is generous. The
// cap exists because the far end decides how much it sends, and an unbounded
// read makes that a decision about this process's memory.
const mostBody = 1 << 20

// fetch makes one cloud call on the caller's behalf and returns what came back.
func (s *Server) fetch(ctx context.Context, in *spend.Fetch) (*spend.Fetched, error) {
	p, ok := principalOf(ctx)
	if !ok {
		return nil, zip.ErrUnauthorized("not identified")
	}

	provider, ok := slug(in.Provider)
	if !ok {
		return nil, zip.ErrBadRequest("unknown provider")
	}

	label := in.Label
	if label == "" {
		label = "default"
	}
	if !segment(label) {
		return nil, zip.ErrBadRequest("label is not a name")
	}
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	if !verbs[method] {
		return nil, zip.ErrBadRequest("method is not one a cloud API uses")
	}
	api, ok := s.upstream(provider)
	if !ok {
		return nil, zip.ErrBadRequest(ErrNotCarried.Error())
	}
	target, err := reference(api, in.Path)
	if err != nil {
		return nil, zip.ErrBadRequest(err.Error())
	}

	key, scope, err := s.custody.resolve(ctx, p, provider, label)
	if err != nil {
		return nil, err
	}

	breaker := s.breaker(provider)
	if !breaker.Allow() {
		return nil, fmt.Errorf("egress: %s is not answering", in.Provider)
	}

	started := time.Now()
	out, err := s.send(ctx, method, target, key, in.Body)
	breaker.Report(err, 0)
	if err != nil {
		s.log.Warn("refused",
			"org", p.Org, "name", p.Name, "kind", p.Kind, "provider", in.Provider,
			"method", method, "path", in.Path, "error", scrub(err, key).Error())
		return nil, scrub(err, key)
	}

	out.Scope = scope
	out.Millis = time.Since(started).Milliseconds()
	s.log.Info("spend",
		"org", p.Org, "name", p.Name, "kind", p.Kind, "provider", in.Provider, "scope", scope,
		"method", method, "path", in.Path, "status", out.Status, "millis", out.Millis)
	return out, nil
}

// send makes the upstream request. The credential exists only inside this
// function and on the request it builds; it is not returned, not logged, and
// scrubbed out of anything that is.
func (s *Server) send(ctx context.Context, method, target, key string, sent []byte) (*spend.Fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Deadline)
	defer cancel()

	var payload io.Reader
	if len(sent) > 0 {
		payload = bytes.NewReader(sent)
	}
	req, err := http.NewRequestWithContext(ctx, method, target, payload)
	if err != nil {
		return nil, err
	}
	// Egress writes every header, and there is no request field that adds one.
	// The credential is one of them, so a caller able to set headers could
	// replace it — or send it somewhere else by setting Host.
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("Accept", "application/json")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := s.fetcher.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	read, err := io.ReadAll(io.LimitReader(resp.Body, mostBody+1))
	if err != nil {
		return nil, err
	}
	if len(read) > mostBody {
		return nil, fmt.Errorf("egress: answer is larger than %d bytes", mostBody)
	}
	return &spend.Fetched{Status: resp.StatusCode, Body: body(read)}, nil
}

// body makes what came back safe to hand a caller expecting JSON. A cloud
// answering with an HTML error page — a proxy's, not its own — would otherwise
// travel as a JSON field that is not JSON, and break at the caller's unmarshal
// rather than here where it can be explained.
func body(read []byte) json.RawMessage {
	trimmed := bytes.TrimSpace(read)
	if len(trimmed) == 0 {
		return json.RawMessage("null")
	}
	if json.Valid(trimmed) {
		return json.RawMessage(trimmed)
	}
	quoted, err := json.Marshal(string(trimmed))
	if err != nil {
		return json.RawMessage("null")
	}
	return json.RawMessage(quoted)
}

// reference turns a caller's path into the URL to request. Two rules apply and
// they answer different questions, so they are two functions: rooted asks
// whether this is a path, resolve asks whether the request stayed.
func reference(base, path string) (string, error) {
	if err := rooted(path); err != nil {
		return "", err
	}
	return resolve(base, path)
}

// rooted reports whether path is a path. It must begin with exactly one slash,
// which refuses "https://evil.example/x" — that begins with an "h" — and
// "//evil.example/x", which has no scheme, reads as a path to anyone skimming,
// and parses as a host.
func rooted(path string) error {
	if !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return errors.New("path must begin with a single /")
	}
	// A backslash is not a separator to Go and is one to several other parsers,
	// so "/\evil.example/x" resolves here to a path on the upstream host and
	// reads elsewhere as a host of its own. It stays on the configured host
	// either way — resolve sees to that — but a request whose meaning depends on
	// who is reading it is not one to forward, and no cloud API has a backslash
	// in a path. Percent-encoded (%5C) in a query value is untouched, which is
	// where one legitimately occurs.
	if strings.Contains(path, `\`) {
		return errors.New("path must not contain a backslash")
	}
	return nil
}

// resolve joins path onto the cloud's upstream and refuses anything that does
// not stay there.
//
// Nothing reaches the comparison while rooted runs ahead of it: a reference
// beginning with a single slash cannot carry an authority, because an authority
// appears only after two. It is here anyway, and separate, because it states the
// property directly instead of deriving it from how references parse. That is
// what holds if rooted is ever loosened — the next person to allow a relative
// path for convenience does not also, without noticing, allow a host — and being
// its own function is what lets a test reach it to prove it.
func resolve(base, path string) (string, error) {
	root, err := url.Parse(base)
	if err != nil || root.Scheme != "https" || root.Host == "" {
		return "", errors.New("the upstream is not an https URL")
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", errors.New("path is not a path")
	}
	target := root.ResolveReference(ref)
	if target.Scheme != root.Scheme || target.Host != root.Host {
		return "", errors.New("path must not leave the upstream")
	}
	return target.String(), nil
}
