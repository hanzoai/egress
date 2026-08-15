// Package egress is the outbound trust boundary: callers ask for a call, egress
// holds the credential that pays for it.
//
// ingress decides who may come in. Egress decides who may spend. A caller sends
// a request with no vendor credential; egress authenticates the workload behind
// it, checks that workload may spend on that provider, rewrites the call onto an
// address it chose itself, and attaches the credential it holds in memory. The
// credential is never returned, never written down, and never reaches a caller.
package egress

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"sync/atomic"
	"time"
)

// Logger is the platform's structured logger.
type Logger = *slog.Logger

// Server answers proxied calls. Build it with New and hand it to http.Server.
type Server struct {
	identity *Identity
	cred     *Credential
	log      Logger
	proxy    *httputil.ReverseProxy
	count    counters
}

// resolved carries the routing decision from the handler, which authorized it,
// to the rewrite, which applies it. Resolving once means the call that was
// authorized is exactly the call that is sent.
type resolved struct {
	up   Upstream
	tail string
}

type key struct{}

// New builds the server. The proxy is built once and shared: connection reuse
// across calls is most of the latency budget on a hot path.
func New(identity *Identity, cred *Credential, log Logger) *Server {
	s := &Server{identity: identity, cred: cred, log: log}
	s.proxy = &httputil.ReverseProxy{
		Rewrite: s.rewrite,
		// Flush every write straight through. Streamed completions arrive as
		// server-sent events whose value is that they are early; buffering them
		// would hold a token back until the next one justified a flush.
		FlushInterval: -1,
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ExpectContinueTimeout: time.Second,
			// The header phase is bounded; the body deliberately is not. A model
			// may think for a minute before its first token and then stream for
			// many more, so a whole-response deadline would cut off correct work.
			ResponseHeaderTimeout: 2 * time.Minute,
			IdleConnTimeout:       90 * time.Second,
			MaxIdleConnsPerHost:   64,
			ForceAttemptHTTP2:     true,
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			s.count.failed.Add(1)
			s.log.Error("upstream failed", "path", r.URL.Path, "err", err)
			fail(w, http.StatusBadGateway, "upstream unavailable")
		},
	}
	return s
}

// ServeHTTP routes one call. The platform surface is public so probes and the
// metrics scraper need no credential; everything else must prove who it is.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/healthz":
		// Names which providers egress can currently spend on — the one place
		// that answers "is this provider live", so an operator console asks here
		// instead of checking for a key in its own environment. Which providers
		// we hold a credential for, never anything about the credential.
		writeJSON(w, http.StatusOK, map[string]any{
			"service": "egress", "status": "ok", "providers": s.cred.Providers(),
		})
		return
	case "/readyz":
		if held, want := s.cred.Held(); held < want {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "no credential"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	case "/metrics":
		s.metrics(w)
		return
	}

	caller, err := s.identity.Check(r)
	if err != nil {
		// The reason is ours to keep: told apart, a bad token, a wrong audience
		// and an ungranted workload are a map for whoever is probing.
		s.count.refused.Add(1)
		s.log.Warn("refused", "path", r.URL.Path, "reason", err)
		fail(w, http.StatusForbidden, "forbidden")
		return
	}

	name, up, tail, ok := route(r.URL.Path)
	if !ok {
		fail(w, http.StatusNotFound, "no such upstream")
		return
	}
	// A vendor's API is wider than the part we use. Only the calls in the table
	// are reachable, so our credential can never authenticate a vendor's
	// key-management surface on a caller's behalf.
	kind, listed := up.Allows(r.Method, tail)
	if !listed {
		s.count.refused.Add(1)
		s.log.Warn("refused", "workload", caller.Subject, "upstream", name,
			"method", r.Method, "path", tail, "reason", "no such operation")
		fail(w, http.StatusNotFound, "no such operation")
		return
	}
	// Authentication proved which workload is asking. This is the separate
	// question of whether that workload may make THIS KIND of call here —
	// buying inference does not come with reading the account behind it.
	if !caller.May(name, kind) {
		s.count.refused.Add(1)
		s.log.Warn("refused", "workload", caller.Subject, "upstream", name,
			"kind", kind, "reason", "no grant")
		fail(w, http.StatusForbidden, "forbidden")
		return
	}
	if _, ok := s.cred.Value(up.Secret); !ok {
		s.log.Error("no credential held", "secret", up.Secret)
		fail(w, http.StatusServiceUnavailable, "no credential")
		return
	}

	s.count.spend.Add(1)
	s.log.Info("spend", "workload", caller.Subject, "upstream", name,
		"kind", kind, "method", r.Method, "path", tail)
	r = r.WithContext(context.WithValue(r.Context(), key{}, resolved{up: up, tail: tail}))
	s.proxy.ServeHTTP(w, r)
}

// rewrite turns the caller's request into the vendor's. It strips what the
// caller sent that must not leave our network, then attaches the credential the
// way this vendor wants it.
func (s *Server) rewrite(p *httputil.ProxyRequest) {
	got, _ := p.In.Context().Value(key{}).(resolved)

	p.Out.URL.Scheme = got.up.Base.Scheme
	p.Out.URL.Host = got.up.Base.Host
	p.Out.URL.Path = got.up.Base.Path + got.tail
	p.Out.URL.RawQuery = p.In.URL.RawQuery
	// Host must name the vendor, not us, or TLS and routing disagree.
	p.Out.Host = got.up.Base.Host

	// The caller's own token proved it may spend HERE. It has no meaning at the
	// vendor and must not be offered to one. The tenant headers go for a
	// different reason: who our customer is, is not the vendor's business.
	for _, h := range []string{
		"Authorization", "Proxy-Authorization", "Cookie",
		"X-Api-Key", "Api-Key", "X-Auth-Token",
		"X-Org-Id", "X-User-Id", "X-Hanzo-Fronted-By",
		"X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
	} {
		p.Out.Header.Del(h)
	}

	for k, v := range got.up.Extra {
		p.Out.Header.Set(k, v)
	}
	if v, ok := s.cred.Value(got.up.Secret); ok {
		p.Out.Header.Set(got.up.Auth.Header, got.up.Auth.Prefix+v)
	}
}

// ── platform surface ─────────────────────────────────────────────────────────

type counters struct {
	spend   atomic.Int64
	refused atomic.Int64
	failed  atomic.Int64
}

func (s *Server) metrics(w http.ResponseWriter) {
	held, want := s.cred.Held()
	w.Header().Set("Content-Type", "text/plain; version=0.0.4")
	fmt.Fprintf(w, "# HELP egress_spend_total Calls forwarded to a vendor.\n"+
		"# TYPE egress_spend_total counter\negress_spend_total %d\n"+
		"# HELP egress_refused_total Calls refused at the caller boundary.\n"+
		"# TYPE egress_refused_total counter\negress_refused_total %d\n"+
		"# HELP egress_upstream_failed_total Calls that reached a vendor and failed.\n"+
		"# TYPE egress_upstream_failed_total counter\negress_upstream_failed_total %d\n"+
		"# HELP egress_credential_held Credentials currently held in memory.\n"+
		"# TYPE egress_credential_held gauge\negress_credential_held %d\n"+
		"# HELP egress_credential_wanted Credentials the allowlist requires.\n"+
		"# TYPE egress_credential_wanted gauge\negress_credential_wanted %d\n",
		s.count.spend.Load(), s.count.refused.Load(), s.count.failed.Load(), held, want)
}

// ── helpers ──────────────────────────────────────────────────────────────────

// mark is a per-process key for naming credentials in logs. It is random and
// never leaves this process, which is what stops the log becoming an oracle: a
// plain digest would let anyone holding a candidate credential and a log line
// confirm the candidate is the one in use.
var mark = func() []byte {
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
		panic("egress: no randomness: " + err.Error())
	}
	return k
}()

// fingerprint identifies a credential within this process's logs without
// disclosing it and without confirming a guess, so a rotation can be seen to
// have happened in a log that never contains the value.
func fingerprint(v string) string {
	m := hmac.New(sha256.New, mark)
	m.Write([]byte(v))
	return hex.EncodeToString(m.Sum(nil))[:12]
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]any{"status": code, "error": msg})
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}

// drain reads and closes a response body so the connection returns to the pool.
func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	_ = resp.Body.Close()
}
