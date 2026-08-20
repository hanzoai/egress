// Package spend is the contract for asking egress to spend a cloud credential,
// and the client that asks.
//
// It is separate from the service for one reason: a caller should link the
// contract, not the custody. Importing the egress package to reach these two
// structs would bring the KMS client, the provider dialects and the key library
// into a process whose whole point is that it holds no key.
package spend

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/valyala/fasthttp"
	zap "github.com/zap-proto/http"
)

// Fetch is one request to spend a cloud credential upstream.
//
// Notice what is absent. There is no org and no user: those come from the
// verified token, because a caller that could name a tenant could spend another
// tenant's key. There is no host: that comes from the egress host's own
// configuration, because a caller that could name the far end could have the
// credential delivered to it. And there are no headers, because a caller that
// could write a header could write the one carrying the credential.
type Fetch struct {
	// Provider is the cloud, spelled as the estate spells it: "DigitalOcean",
	// "Hetzner". It selects the credential and the upstream, so a key enrolled
	// for one cloud cannot be spent against another.
	Provider string `json:"provider" url:"-" validate:"required"`
	// Label picks between several accounts on one cloud. Empty means "default".
	// This is what lets an org hold two DigitalOcean accounts and spend the one
	// it means to.
	Label string `json:"label" url:"-"`
	// Method is the HTTP method.
	Method string `json:"method" url:"-" validate:"required"`
	// Path is the request path, query included: "/v2/droplets?page=2". It is a
	// path and never a URL.
	Path string `json:"path" url:"-" validate:"required"`
	// Body is the request body, and it is JSON because every cloud API egress
	// carries speaks JSON.
	Body json.RawMessage `json:"body" url:"-"`
}

// Fetched is what the upstream answered: its status, and its body.
//
// The status is returned rather than translated. A 404 from a cloud is a fact
// about the caller's request, not a failure of egress, and flattening the two
// would leave a caller unable to tell "your cluster is gone" from "the credential
// store is down" — which are opposite instructions.
type Fetched struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Scope  string          `json:"scope"`
	Millis int64           `json:"millis"`
}

// Config is what a caller needs to reach egress for one cloud account.
type Config struct {
	// Network and Address are where egress listens: "tcp" and a host:port, or
	// "unix" and a socket path. Empty Network means tcp.
	Network string
	Address string
	// Token identifies the CALLER — this service, to egress. It is not a cloud
	// credential and buys nothing upstream on its own.
	Token string
	// Provider and Account name the cloud account to spend on.
	Provider string
	Account  string
	// Deadline bounds one call. Zero means a minute, which is long for a cloud
	// API and short enough that a stuck call surfaces.
	Deadline time.Duration
}

// Client returns an http.Client that makes its requests through egress.
//
// Every SDK worth using takes an http.Client — godo.NewClient(c),
// hcloud.WithHTTPClient(c) — so handing it this one is a transport swap and not
// an SDK rewrite. What changes underneath is that the request is described to
// egress rather than sent: egress holds the credential, attaches it, and returns
// what the cloud said. Nothing in this process ever holds a key.
//
// The request's host is discarded, which is worth saying out loud. An SDK builds
// a full URL from a base it was configured with; only the path and query travel,
// and egress decides the host from its own configuration. Configure the SDK's
// base URL to whatever it likes.
func Client(cfg Config) *http.Client {
	deadline := cfg.Deadline
	if deadline <= 0 {
		deadline = time.Minute
	}
	to := zap.Dial(cfg.Network, cfg.Address)
	to.SetReadTimeout(deadline)
	return &http.Client{
		Timeout:   deadline,
		Transport: &carrier{to: to, cfg: cfg},
	}
}

// carrier turns one outbound request into one Fetch.
type carrier struct {
	to  *zap.Transport
	cfg Config
}

// ErrRefused means egress would not make the call. It is separate from the
// upstream's own answer, which arrives as a status: this is "the call did not
// happen", that is "the cloud said no".
var ErrRefused = errors.New("egress refused the call")

func (c *carrier) RoundTrip(r *http.Request) (*http.Response, error) {
	body, err := payload(r)
	if err != nil {
		return nil, err
	}
	asked, err := json.Marshal(Fetch{
		Provider: c.cfg.Provider,
		Label:    c.cfg.Account,
		Method:   r.Method,
		Path:     r.URL.RequestURI(),
		Body:     body,
	})
	if err != nil {
		return nil, err
	}

	req, resp := fasthttp.AcquireRequest(), fasthttp.AcquireResponse()
	defer fasthttp.ReleaseRequest(req)
	defer fasthttp.ReleaseResponse(resp)

	req.SetRequestURI("http://egress/v1/fetch")
	req.Header.SetMethod(http.MethodPost)
	req.Header.SetContentType("application/json")
	req.Header.Set("Authorization", "Bearer "+c.cfg.Token)
	req.SetBody(asked)

	if err := c.to.Do(req, resp); err != nil {
		return nil, fmt.Errorf("egress at %s: %w", c.cfg.Address, err)
	}
	if resp.StatusCode() != http.StatusOK {
		return nil, fmt.Errorf("%w: %d %s", ErrRefused, resp.StatusCode(), resp.Body())
	}
	var out Fetched
	if err := json.Unmarshal(resp.Body(), &out); err != nil {
		return nil, fmt.Errorf("egress answered something that is not a fetch: %w", err)
	}
	return answer(r, out), nil
}

// payload reads the request body, which must be JSON. A cloud API egress
// carries speaks JSON, so anything else is a caller building a request egress
// cannot describe — said here, where the SDK call site is still in view, rather
// than as a refusal from the far end.
func payload(r *http.Request) (json.RawMessage, error) {
	if r.Body == nil {
		return nil, nil
	}
	read, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(read)) == 0 {
		return nil, nil
	}
	if !json.Valid(read) {
		return nil, errors.New("egress carries JSON, and this request body is not JSON")
	}
	return read, nil
}

// answer rebuilds what the SDK expects to receive. The status and body are the
// cloud's own, so an SDK reads its own errors and its own pagination out of them
// exactly as it would have.
func answer(r *http.Request, out Fetched) *http.Response {
	read := []byte(out.Body)
	return &http.Response{
		Status:        http.StatusText(out.Status),
		StatusCode:    out.Status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{"application/json"}},
		Body:          io.NopCloser(bytes.NewReader(read)),
		ContentLength: int64(len(read)),
		Request:       r,
	}
}
