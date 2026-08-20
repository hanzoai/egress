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

// carried lists the clouds egress knows how to pay for, and how.
//
// Every entry here carries its credential as a bearer token, which is why the
// value is nothing more than membership. A cloud that signs its requests instead
// — AWS, and anything else using SigV4 — cannot be served by attaching a header,
// and is refused rather than sent upstream with a header it will reject. The
// refusal is the honest answer: egress cannot spend that credential yet.
//
// This is an allowlist, so a cloud arrives here by someone adding it, having
// worked out how its credential is carried. A denylist would serve every cloud
// nobody had thought about.
var carried = map[string]bool{
	"digitalocean": true,
	"hetzner":      true,
}

// ErrNotCarried is what a cloud egress cannot pay for gets.
var ErrNotCarried = errors.New("egress: credential cannot be carried for this provider")

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
	if !carried[provider] {
		return nil, zip.ErrBadRequest(ErrNotCarried.Error())
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
	target, err := reference(s.cfg.URLs[provider], in.Path)
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
			"org", p.Org, "user", p.User, "provider", in.Provider,
			"method", method, "path", in.Path, "error", scrub(err, key).Error())
		return nil, scrub(err, key)
	}

	out.Scope = scope
	out.Millis = time.Since(started).Milliseconds()
	s.log.Info("spend",
		"org", p.Org, "user", p.User, "provider", in.Provider, "scope", scope,
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
	// so "/\evil.example/x" resolves here to a path on the configured host and
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

// resolve joins path onto the upstream this host configured and refuses anything
// that does not stay there.
//
// Nothing reaches the comparison while rooted runs ahead of it: a reference
// beginning with a single slash cannot carry an authority, because an authority
// appears only after two. It is here anyway, and separate, because it states the
// property directly instead of deriving it from how references parse. That is
// what holds if rooted is ever loosened — the next person to allow a relative
// path for convenience does not also, without noticing, allow a host — and being
// its own function is what lets a test reach it to prove it.
func resolve(base, path string) (string, error) {
	if base == "" {
		return "", errors.New("no upstream is configured for this provider")
	}
	root, err := url.Parse(base)
	if err != nil || root.Scheme != "https" || root.Host == "" {
		return "", errors.New("the configured upstream is not a URL")
	}
	ref, err := url.Parse(path)
	if err != nil {
		return "", errors.New("path is not a path")
	}
	target := root.ResolveReference(ref)
	if target.Scheme != root.Scheme || target.Host != root.Host {
		return "", errors.New("path must not leave the configured upstream")
	}
	return target.String(), nil
}
