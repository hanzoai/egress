package egress

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/hanzoai/ai/proxy"
	iconfig "github.com/hanzoai/egress/internal/config"
	"github.com/hanzoai/egress/internal/containment"
	"github.com/hanzoai/egress/internal/transform/secrets"
	"github.com/zap-proto/zip"
	"github.com/zap-proto/zip/middleware"
)

// Server is the running service. It holds no credential and no session; every
// value it keeps is either configuration or a bounded cache, so one replica is
// interchangeable with the next and a suspect one is deleted rather than
// investigated.
type Server struct {
	cfg      Config
	verify   *Verifier
	custody  *custody
	limiter  *limiter
	circuits circuits
	fetcher  *http.Client
	log      *slog.Logger
	app      *zip.App
	firewall *containment.Runner
}

// New builds the service over a credential store. It refuses an incoherent
// configuration rather than starting with a hole in it.
func New(cfg Config, store Secrets, log *slog.Logger) (*Server, error) {
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		verify:   NewVerifier(cfg.Issuer, cfg.Audience, cfg.JWKS, 5*time.Minute),
		custody:  newCustody(store),
		limiter:  &limiter{rpm: cfg.RPM, seen: map[string]*window{}},
		circuits: circuits{by: map[string]*middleware.Breaker{}},
		log:      log,
	}
	// The dialects make their provider call through one client hanzoai/ai
	// keeps as a package variable, and it holds nothing until a process puts
	// something there. Egress puts its own there: the outbound leg belongs to
	// the service that spends on it. Certificates are verified — an upstream
	// that cannot prove who it is does not get a credential, and there is no
	// configuration for deciding otherwise. The timeout is the call deadline,
	// which is also what stops an abandoned dialect: a dialect takes no
	// context, so without one it runs until the vendor gives up.
	//
	// The route is this process's too. Go's default transport reads
	// HTTP_PROXY and friends out of the environment, which would let whoever
	// writes the environment choose the far end of the connection that
	// carries a credential — the same decision the certificate check exists
	// to take away from them. So the client dials the upstream named in the
	// config and nothing else. Everything else about the default transport,
	// pooling and HTTP/2 included, is kept.
	direct := http.DefaultTransport.(*http.Transport).Clone()
	direct.Proxy = nil
	proxy.ProxyHttpClient = &http.Client{Timeout: cfg.Deadline, Transport: direct}

	// A cloud call gets the same transport for the same reasons, and one thing
	// more: it does not follow a redirect. A dialect talks to an endpoint that
	// answers; a cloud API answers a `Location` too, and following one would let
	// the far end choose the next far end — the decision the nil Proxy above
	// exists to keep. Unfollowed, a 3xx is returned to the caller as what it is.
	s.fetcher = &http.Client{
		Timeout:   cfg.Deadline,
		Transport: direct,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	s.app = zip.New(zip.Config{AppName: "egress"})

	// The gate is the FIRST thing registered, and it is registered on the app
	// rather than wrapped around each route. That is not a style choice, it is
	// the only placement that holds.
	//
	// A typed op is not reachable only at the path it was declared at. The
	// framework also projects it onto an op-call plane, an MCP tool and an
	// OpenAPI document, and it installs those routes itself, at serve time.
	// Middleware wrapped around a handler at registration covers the declared
	// path and nothing else — measured, not assumed: a ZAP call to the op plane
	// carrying no token reached a per-route-gated op and was answered. Ahead of
	// every route, the gate covers the projections too, because they are routes
	// like any other and they are added after it.
	s.app.Use(middleware.Recover(), middleware.RequestID(), zip.Handler(s.gate), zip.Handler(s.limit))

	s.app.Post("/v1/call", s.call)
	zip.Post(s.app, "/v1/enroll", s.enroll,
		zip.WithOperationID("egress_enroll"),
		zip.WithSummary("Seal a customer's own provider key. It is never readable again."))
	zip.Post(s.app, "/v1/fetch", s.fetch,
		zip.WithOperationID("egress_fetch"),
		zip.WithSummary("Make one cloud API call. The credential stays here."))
	zip.Get(s.app, "/v1/health", s.health,
		zip.WithOperationID("egress_health"),
		zip.WithSummary("Report whether this replica is serving"))

	// The firewall is opt-in: with no containment config, egress is exactly the
	// spend service it was. With one, the same binary also runs the outbound
	// network firewall, and its credential transforms read secrets from the same
	// KMS custody the spend side uses — MPC-sharded, held for one request, never
	// returned. A firewall whose config will not load refuses to start rather
	// than serving with a hole in it.
	if cfg.ContainmentPath != "" {
		fc, err := iconfig.LoadConfig(cfg.ContainmentPath)
		if err != nil {
			return nil, fmt.Errorf("egress: loading containment config: %w", err)
		}
		secrets.SetKMSFetcher(func(ctx context.Context, ref string) (string, error) {
			b, err := store.GetSecret(ctx, ref)
			return string(b), err
		})
		s.firewall, err = containment.New(fc, log)
		if err != nil {
			return nil, fmt.Errorf("egress: building firewall: %w", err)
		}
		log.Info("network containment enabled", "config", cfg.ContainmentPath)
	}
	return s, nil
}

// Listen serves the spend API and, when configured, the network firewall, until
// either stops. One binary, both boundaries.
func (s *Server) Listen() error {
	if s.firewall == nil {
		return s.app.Listen(s.cfg.Listen)
	}
	errc := make(chan error, 2)
	go func() { errc <- s.app.Listen(s.cfg.Listen) }()
	go func() { errc <- s.firewall.Run(context.Background()) }()
	return <-errc
}

// App exposes the router so a test can drive it without a socket.
func (s *Server) App() *zip.App { return s.app }

// gate is the only entry point. A caller that cannot be identified is refused before
// anything reads a credential, because an unidentifiable caller has no tenant
// to spend from and nobody to bill.
func (s *Server) gate(c *zip.Ctx) error {
	p, err := s.verify.Verify(c.Context(), c.Header("Authorization"))
	if err != nil {
		return zip.ErrUnauthorized("not identified")
	}
	c.SetContext(with(c.Context(), p))
	return c.Next()
}

// limit caps how fast one principal may spend. It is keyed on the verified
// principal, never on a header: a ceiling keyed on something the caller writes
// is a ceiling the caller sets.
func (s *Server) limit(c *zip.Ctx) error {
	p, ok := principalOf(c.Context())
	if !ok {
		return zip.ErrUnauthorized("not identified")
	}
	if !s.limiter.admit(p.Org + "/" + p.Kind + "/" + p.Name) {
		return zip.Errorf(http.StatusTooManyRequests, "too many calls")
	}
	return c.Next()
}

// call makes one upstream request and streams the answer back as it arrives.
//
// It is the one route here that is not a typed op, and deliberately: a typed op
// is one input to one output, and a token stream has no single output to
// describe. The answer's frames are the provider's own; egress appends one
// final frame of its own, the meter, which is the record of what was spent.
func (s *Server) call(c *zip.Ctx) error {
	p, ok := principalOf(c.Context())
	if !ok {
		return zip.ErrUnauthorized("not identified")
	}
	var in Call
	if err := json.Unmarshal(c.Body(), &in); err != nil {
		return zip.ErrBadRequest("body is not a call")
	}

	c.SetHeader("Content-Type", "text/event-stream")
	c.SetHeader("Cache-Control", "no-cache")

	// Everything the stream needs is captured here, by value. The callback runs
	// after this handler returns, so it must not reach back into the request.
	return c.SendStreamWriter(func(w *bufio.Writer) {
		out := &frames{to: w}
		meter, err := s.spend(context.Background(), p, &in, out)
		if err != nil {
			s.log.Warn("refused",
				"org", p.Org, "name", p.Name, "kind", p.Kind,
				"provider", in.Provider, "model", in.Model, "error", err.Error())
			out.emit("error", map[string]string{"error": err.Error()})
			return
		}
		s.log.Info("spend",
			"org", p.Org, "name", p.Name, "kind", p.Kind,
			"provider", meter.Provider, "model", meter.Model, "scope", meter.Scope,
			"prompt", meter.Prompt, "completion", meter.Completion, "total", meter.Total,
			"price", meter.Price, "currency", meter.Currency, "millis", meter.Millis)
		out.emit("meter", meter)
	})
}

// Enroll seals a customer's own provider key.
type Enroll struct {
	// Provider is the vendor the key belongs to, spelled as hanzoai/ai spells
	// it.
	Provider string `json:"provider" url:"-" validate:"required"`
	// Label distinguishes several keys for one vendor. Empty means "default".
	Label string `json:"label" url:"-"`
	// Key is the credential. It is sealed and never read back — not by its
	// owner, not by an operator, not by a support tool.
	Key string `json:"key" url:"-" validate:"required"`
}

// Enrolled says where a key went, and nothing about the key.
type Enrolled struct {
	Provider string `json:"provider"`
	Label    string `json:"label"`
	Scope    string `json:"scope"`
}

// enroll seals a key at the path the verified principal owns. The path is built
// from the token, so a caller cannot enrol into somebody else's custody, and
// there is no route that reads one back out.
func (s *Server) enroll(ctx context.Context, in *Enroll) (*Enrolled, error) {
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
	if in.Key == "" {
		return nil, zip.ErrBadRequest("key is empty")
	}
	if err := s.custody.enroll(ctx, p, provider, label, in.Key); err != nil {
		s.log.Warn("enroll failed", "org", p.Org, "name", p.Name, "kind", p.Kind, "provider", provider)
		return nil, zip.ErrInternal("could not seal the key")
	}
	s.log.Info("enrolled", "org", p.Org, "name", p.Name, "kind", p.Kind, "provider", provider, "label", label)
	return &Enrolled{Provider: in.Provider, Label: label, Scope: ScopeUser}, nil
}

// Nothing is an operation that reads no part of its request.
type Nothing struct{}

// Ready is what health answers. It carries no state — not a version, not a
// configuration, not a count. Diagnosis happens from the metrics and logs that
// leave this host, never by asking the host about itself.
type Ready struct {
	Ready bool `json:"ready"`
}

// health answers only an identified caller. Every handler here re-checks the
// principal rather than trusting that something upstream did: the gate is the
// perimeter, this is what makes a handler reached by some other road refuse on
// its own account.
func (s *Server) health(ctx context.Context, _ *Nothing) (*Ready, error) {
	if _, ok := principalOf(ctx); !ok {
		return nil, zip.ErrUnauthorized("not identified")
	}
	return &Ready{Ready: true}, nil
}

// limiter caps calls per principal over a fixed window.
//
// It is written here rather than imported, which is worth saying plainly: the
// gateway's edge package measures traffic but never admits or refuses it, and
// the one importable limiter in the estate is a route handler keyed by default
// on a header this service must not trust. What is imported instead is the
// circuit breaker, which is a real reusable Allow/Report pair.
type limiter struct {
	rpm  int
	mu   sync.Mutex
	seen map[string]*window
}

type window struct {
	n     int
	until time.Time
}

// admit reports whether one more call is within the ceiling.
func (l *limiter) admit(key string) bool {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	w, ok := l.seen[key]
	if !ok || now.After(w.until) {
		if len(l.seen) >= 4096 {
			l.sweep(now)
		}
		l.seen[key] = &window{n: 1, until: now.Add(time.Minute)}
		return true
	}
	if w.n >= l.rpm {
		return false
	}
	w.n++
	return true
}

// sweep drops windows that have closed, so a process that has served many
// principals does not hold a row for each of them forever.
func (l *limiter) sweep(now time.Time) {
	for key, w := range l.seen {
		if now.After(w.until) {
			delete(l.seen, key)
		}
	}
}
