package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/hanzoai/egress/spend"
	"github.com/zap-proto/zip"
)

// clouds are the clouds egress pays for with a bearer, and where each one's API
// answers.
//
// Where DigitalOcean's API lives is a fact about DigitalOcean, not a choice this
// deployment makes, so it is stated here once rather than typed into every host's
// configuration. That an operator does not name it costs nothing: the rule that
// matters is that the CALLER cannot, and the caller has no field for it either
// way. It is the same shape as a model dialect, which carries its vendor's
// endpoint and is asked for a fallback only when a deployment overrides one.
//
// Membership is also the allowlist for a bearer. AWS is absent because it does
// not take one: its API is one host per service and region, a request is signed
// rather than carrying its credential, and the endpoints egress signs for are
// this host's -aws list (aws.go). Every other cloud is refused.
var clouds = map[string]string{
	"digitalocean": "https://api.digitalocean.com",
	"hetzner":      "https://api.hetzner.cloud",
}

// ErrNotCarried is what a cloud egress cannot pay for gets.
var ErrNotCarried = errors.New("egress: credential cannot be carried for this provider")

// upstream is where one of the upstreams egress carries answers: what egress
// knows, unless this host overrode it. An override serves a regional or
// sovereign endpoint, and a test pointing at a server of its own; it can only
// move an upstream egress already carries, never admit one it cannot pay for.
//
// The table is a parameter because there are two — `clouds` for an API egress
// spends a bearer at, `bases` for a data service that is ours — and the rule
// about overrides is one rule, not one per table.
func (s *Server) upstream(known map[string]string, name string) (string, bool) {
	at, ok := known[name]
	if !ok {
		return "", false
	}
	if override := s.cfg.URLs[name]; override != "" {
		return override, true
	}
	return at, true
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
	out, err := outbound(method, in)
	if err != nil {
		return nil, zip.ErrBadRequest(err.Error())
	}

	// Where the request goes is decided here and nowhere else: for a bearer
	// cloud from the one table, for AWS from the endpoints this host admits.
	var at endpoint
	var base string
	if provider == amazon {
		at, ok = s.amazon[strings.ToLower(in.Host)]
		if !ok {
			return nil, zip.ErrBadRequest("egress does not sign for that AWS endpoint")
		}
		base = "https://" + at.host
	} else {
		if in.Host != "" {
			return nil, zip.ErrBadRequest("a host is named only for an AWS endpoint")
		}
		base, ok = s.upstream(clouds, provider)
		if !ok {
			return nil, zip.ErrBadRequest(ErrNotCarried.Error())
		}
		if !out.raw {
			out.accept = "application/json"
		}
	}
	target, err := reference(base, in.Path)
	if err != nil {
		return nil, zip.ErrBadRequest(err.Error())
	}

	// The credential, and how it goes on the request. Neither leaves this call.
	var (
		attach func(*http.Request, []byte) error
		hidden []string
		scope  string
		form   string
		signer aws.Credentials
	)
	if provider == amazon {
		d, paid, err := s.resolveAWS(ctx, p, label)
		if err != nil {
			return nil, err
		}
		signer, err = s.credentials(ctx, p, label, d, at)
		if err != nil {
			return nil, err
		}
		attach, hidden, scope, form = signed(signer, at), secrets(signer), paid, d.form()
	} else {
		key, paid, err := s.custody.resolve(ctx, p, provider, label)
		if err != nil {
			return nil, err
		}
		attach, hidden, scope = authorize(key), []string{key}, paid
	}

	breaker := s.breaker(provider)
	if !breaker.Allow() {
		return nil, fmt.Errorf("egress: %s is not answering", in.Provider)
	}

	started := time.Now()
	got, err := s.send(ctx, target, out, attach)
	if err == nil && provider == amazon && (quoted(got.Raw, signer) || quoted(got.Body, signer)) {
		err = errors.New("egress: the answer quoted the credential, so it is not returned")
	}
	breaker.Report(err, 0)
	if err != nil {
		err = hide(err, hidden)
		s.log.Warn("refused",
			"org", p.Org, "name", p.Name, "kind", p.Kind, "provider", in.Provider, "host", at.host,
			"method", method, "path", in.Path, "action", action(out.kind, out.body), "error", err.Error())
		return nil, err
	}

	got.Scope = scope
	got.Millis = time.Since(started).Milliseconds()
	s.log.Info("spend",
		"org", p.Org, "name", p.Name, "kind", p.Kind, "provider", in.Provider, "scope", scope,
		"form", form, "host", at.host, "method", method, "path", in.Path,
		"action", action(out.kind, out.body), "status", got.Status, "millis", got.Millis)
	return got, nil
}

// request is one upstream request as egress will send it, less where it goes
// and the credential.
type request struct {
	method string
	body   []byte
	kind   string // the body's Content-Type
	accept string // the Accept header, when egress states one
	raw    bool   // the caller described the body as bytes, and reads the answer so
}

// outbound checks what a caller described and turns it into a request. A body
// arrives as JSON (Body) or as bytes with their Content-Type (Raw, Type), never
// both, and a Type describes a Raw and nothing else.
func outbound(method string, in *spend.Fetch) (request, error) {
	out := request{method: method}
	json := present(in.Body)
	switch {
	case json && len(in.Raw) > 0:
		return out, errors.New("a fetch carries body or raw, not both")
	case in.Type != "" && len(in.Raw) == 0:
		return out, errors.New("type describes a raw body, and there is none")
	case len(in.Raw) > 0:
		if len(in.Type) > 256 {
			return out, errors.New("type is not a content type")
		}
		if _, _, err := mime.ParseMediaType(in.Type); err != nil {
			return out, errors.New("type is not a content type")
		}
		out.body, out.kind, out.raw = in.Raw, in.Type, true
	case json:
		out.body, out.kind = in.Body, "application/json"
	}
	return out, nil
}

// present reports whether a JSON body says anything. An absent body arrives as
// the literal null, and a request with no body must not be sent one.
func present(b json.RawMessage) bool {
	t := bytes.TrimSpace(b)
	return len(t) > 0 && !bytes.Equal(t, []byte("null"))
}

// authorize puts a key on a request as the bearer every cloud in `clouds` takes.
func authorize(key string) func(*http.Request, []byte) error {
	return func(r *http.Request, _ []byte) error {
		r.Header.Set("Authorization", "Bearer "+key)
		return nil
	}
}

// hide takes every credential out of an error, in each form a provider might
// quote it.
func hide(err error, hidden []string) error {
	for _, h := range hidden {
		err = scrub(err, h)
	}
	return err
}

// send makes the upstream request. The credential exists only inside attach and
// on the request it signs; it is not returned, not logged, and scrubbed out of
// anything that is.
func (s *Server) send(ctx context.Context, target string, out request, attach func(*http.Request, []byte) error) (*spend.Fetched, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.Deadline)
	defer cancel()

	var payload io.Reader
	if len(out.body) > 0 {
		payload = bytes.NewReader(out.body)
	}
	req, err := http.NewRequestWithContext(ctx, out.method, target, payload)
	if err != nil {
		return nil, err
	}
	// Egress writes every header, and there is no request field that adds one.
	// The credential is one of them, so a caller able to set headers could
	// replace it — or send it somewhere else by setting Host.
	if payload != nil {
		req.Header.Set("Content-Type", out.kind)
	}
	if out.accept != "" {
		req.Header.Set("Accept", out.accept)
	}
	if err := attach(req, out.body); err != nil {
		return nil, err
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
	return answered(resp.StatusCode, resp.Header.Get("Content-Type"), read, out.raw), nil
}

// answered is what came back, in the shape the caller asked in. A caller that
// sent bytes reads bytes. A caller that sent JSON reads JSON in Body exactly as
// it always has, and an answer that is not JSON also arrives as bytes beside it,
// so a caller that knows how can read what the cloud really said.
func answered(status int, kind string, read []byte, raw bool) *spend.Fetched {
	out := &spend.Fetched{Status: status}
	if raw {
		out.Raw, out.Type = read, typed(kind)
		return out
	}
	out.Body = body(read)
	if t := bytes.TrimSpace(read); len(t) > 0 && !json.Valid(t) {
		out.Raw, out.Type = read, typed(kind)
	}
	return out
}

// typed is an answer's Content-Type as a caller will be handed it: the cloud's
// own when it is one, and bytes when it is not.
func typed(kind string) string {
	if _, _, err := mime.ParseMediaType(kind); err != nil || len(kind) > 256 {
		return "application/octet-stream"
	}
	return kind
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
