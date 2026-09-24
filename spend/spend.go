// Package spend is the contract for asking egress to spend on a caller's
// behalf, and the client that asks: [Client] for a cloud API, [Session] for a
// database.
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
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/valyala/fasthttp"
	zap "github.com/zap-proto/http"
)

// Fetch is one request to spend a cloud credential upstream.
//
// Notice what is absent. There is no org and no user: those come from the
// verified token, because a caller that could name a tenant could spend another
// tenant's key. There is no free choice of host: a cloud that takes a bearer
// answers at one address egress already knows, and an AWS endpoint is only
// selected from the ones the egress host admits (see Host). And there are no
// headers, because a caller that could write a header could write the one
// carrying the credential.
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
	// Body is a JSON request body. A request whose body is JSON, or that has
	// none, is described exactly as it always has been.
	Body json.RawMessage `json:"body" url:"-"`
	// Raw is a request body that is not JSON, as bytes: EC2's Query API posts a
	// form. A Fetch carries Body or Raw, never both, and Raw always travels with
	// Type.
	Raw []byte `json:"raw,omitempty" url:"-"`
	// Type is Raw's Content-Type, sent upstream as written.
	Type string `json:"type,omitempty" url:"-"`
	// Host is the AWS endpoint the request was addressed to, such as
	// "ec2.us-east-1.amazonaws.com". An AWS API answers at one host per service
	// and region, so which one is part of the request, and its service and region
	// are what egress scopes the signature to. It SELECTS and never supplies:
	// egress refuses a host its own configuration does not list, and it never
	// sends a credential anywhere, because SigV4 sends a signature and keeps the
	// key. It is empty for every other cloud, whose one address egress
	// already knows.
	Host string `json:"host,omitempty" url:"-"`
}

// Fetched is what the upstream answered: its status, and its body.
//
// The status is returned rather than translated. A 404 from a cloud is a fact
// about the caller's request, not a failure of egress, and flattening the two
// would leave a caller unable to tell "your cluster is gone" from "the credential
// store is down" — which are opposite instructions.
//
// A JSON answer arrives in Body. An answer carried as bytes arrives in Raw with
// its Content-Type in Type: every answer to a Fetch that carried Raw, and any
// answer that is not JSON. Type is set whenever Raw is meant, so an empty Raw
// with a Type is an empty answer and not a missing one.
type Fetched struct {
	Status int             `json:"status"`
	Body   json.RawMessage `json:"body"`
	Scope  string          `json:"scope"`
	Millis int64           `json:"millis"`
	Raw    []byte          `json:"raw,omitempty"`
	Type   string          `json:"type,omitempty"`
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
	// Provider and Account name the cloud account to spend on. For a session,
	// Provider names the base instead and Account is unused: a base is one
	// coordinate, and a second credential for one is a second name.
	Provider string
	Account  string
	// Database is the database within a base, for Session. Unused by Fetch.
	Database string
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
// base URL to whatever it likes. AWS is the one exception: its host names the
// service and region, so it travels as Fetch.Host, and egress refuses it unless
// its own configuration admits that endpoint.
//
// A JSON body travels as JSON and any other body as bytes with its
// Content-Type, so an SDK that posts a form (EC2) or reads XML back works
// unchanged. Hand an AWS SDK anonymous credentials: it signs nothing, and
// egress signs the request it sends.
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
	in, err := describe(c.cfg, r)
	if err != nil {
		return nil, err
	}
	asked, err := json.Marshal(in)
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

	if err := c.to.DoContext(r.Context(), req, resp); err != nil {
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

// describe turns an outbound request into the Fetch that asks egress to make it.
//
// A body that is JSON and says so — or says nothing — travels as Body, which is
// the Fetch every JSON cloud has always sent. Any other body travels as Raw with
// its own Content-Type, byte for byte.
func describe(cfg Config, r *http.Request) (Fetch, error) {
	in := Fetch{
		Provider: cfg.Provider,
		Label:    cfg.Account,
		Method:   r.Method,
		Path:     r.URL.RequestURI(),
	}
	if addressed(cfg.Provider) {
		in.Host = strings.ToLower(r.URL.Hostname())
	}
	read, err := payload(r)
	if err != nil || len(read) == 0 {
		return in, err
	}
	kind := r.Header.Get("Content-Type")
	if plainJSON(kind) && json.Valid(read) {
		in.Body = read
		return in, nil
	}
	if plainJSON(kind) && len(bytes.TrimSpace(read)) == 0 {
		return in, nil
	}
	if kind == "" {
		kind = "application/octet-stream"
	}
	in.Raw, in.Type = read, kind
	return in, nil
}

// addressed reports whether a provider's API answers at one host per service
// and region, so that the host an SDK addressed is part of what it asked. AWS
// is the one such cloud egress carries.
func addressed(provider string) bool {
	return strings.EqualFold(strings.TrimSpace(provider), "aws")
}

// plainJSON reports whether a Content-Type describes a body as JSON, or does not
// describe it at all — the two cases a JSON cloud's SDK produces.
func plainJSON(kind string) bool {
	if kind == "" {
		return true
	}
	media, _, err := mime.ParseMediaType(kind)
	return err == nil && media == "application/json"
}

// payload reads the request body.
func payload(r *http.Request) ([]byte, error) {
	if r.Body == nil {
		return nil, nil
	}
	read, err := io.ReadAll(r.Body)
	_ = r.Body.Close()
	return read, err
}

// answer rebuilds what the SDK expects to receive. The status and body are the
// cloud's own, so an SDK reads its own errors and its own pagination out of them
// exactly as it would have.
func answer(r *http.Request, out Fetched) *http.Response {
	read, kind := []byte(out.Body), "application/json"
	if out.Type != "" {
		read, kind = out.Raw, out.Type
	}
	return &http.Response{
		Status:        http.StatusText(out.Status),
		StatusCode:    out.Status,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        http.Header{"Content-Type": []string{kind}},
		Body:          io.NopCloser(bytes.NewReader(read)),
		ContentLength: int64(len(read)),
		Request:       r,
	}
}
