package egress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
)

// A session is the third thing egress brokers, and the first that is not one
// request and one answer. A caller opens a connection to a database and keeps
// it; what egress brokers is the whole connection, for as long as it lasts.
//
// TWO ORIGINS, ONE VERIFIER. It is the one every other route uses — the same
// Verifier, checking the same issuer, audience and expiry, on a token minted by
// the same grant. What differs is only where the connection then goes:
//
//   - a BASE OF OURS carries NO CREDENTIAL. hanzo-sql and the forks beside it
//     are ours and co-located, so egress reaches one over the trust between
//     them and presents the caller's TENANT as the database role. A password
//     between two of our own processes would be a secret invented to guard a
//     boundary that is already closed, and an invented secret is one more thing
//     to rotate, leak and audit.
//   - a DATABASE THAT IS NOT OURS comes out of the caller's own custody: the
//     whole connection URL — where it answers, who to be there, and the
//     credential — sealed at the path the validated principal owns, read on the
//     way past and held for the length of one dial. That is the same custody
//     the model and cloud paths read, not a second one.
//
// The parts that do not depend on which protocol is spoken are here: where a
// session goes, whether this principal may open one, and the record of it. Each
// protocol's own file holds its handshake — `postgres.go` today, one file per
// fork after it.
//
// A session is a SPEND like a call is. It is opened for a verified principal,
// it counts against that principal's ceiling, and it is recorded twice: once
// when it opens, because that is the authorization, and once when it ends,
// because that is the meter.

// bases are the data services that are ours, and where each one answers.
//
// Where hanzo-sql answers is a fact about hanzo-sql rather than a choice a
// deployment makes, so it is stated once here — the same shape as `clouds`, and
// for the same reason. Membership is also the allowlist and the order of
// resolution: a name here is reached over trust and never looked for in a
// caller's custody, and a name absent here is looked for there and nowhere
// else. So a tenant cannot enrol its way onto one of our own bases, and adding
// the next fork is one line written by whoever stood it up.
//
// The value is an ADDRESS and not a connection, which is the mode stated in the
// data: there is nobody to be and nothing to prove, so there is nowhere in it
// for a user or a credential to go. It is spelled the way every other address
// here is — an absolute path is a socket directory, anything else is host:port
// — so an operator moving a base writes what they would write anywhere else,
// and a co-located base on a socket is expressible where a URL could not spell
// one.
var bases = map[string]string{
	"sql": "hanzo-sql.hanzo.svc.cluster.local:5432",
}

// room is how many sessions one replica will hold at once. A session is a
// connection at each end and a goroutine in between, and the far ends have
// ceilings of their own — so this one is stated rather than discovered when a
// database starts refusing. Past it a client is told what postgres tells one.
const room = 1024

// greeting is how long a client has to say who it is. Until it has, it is
// nobody's to bill and nothing has been decided about it, so it does not get to
// hold a connection open indefinitely on the strength of having opened one.
const greeting = 10 * time.Second

// reach bounds the dial to the far end. It is short because both origins are
// one connection away — a base of ours on the network this host shares with it,
// or a database whose address was resolved a moment ago.
const reach = 15 * time.Second

// origin says where a session goes and which custody paid: a connection URL,
// and one of ScopeTrust, ScopeUser or ScopeOrg.
//
// The name comes off the wire, which is allowed because it selects from a
// closed set and never names an address. It is spelled through the one mapping
// every other path uses, so "Analytics" and "analytics" reach one credential
// rather than two.
func (s *Server) origin(ctx context.Context, p Principal, name string) (string, string, error) {
	base, ok := slug(name)
	if !ok {
		return "", "", ErrNoCredential
	}
	if at, ok := s.upstream(bases, base); ok {
		return at, ScopeTrust, nil
	}
	// One coordinate, unlike a cloud, which has a label so that a tenant can
	// hold two accounts on one vendor. A second credential for one database is
	// a second database as far as a caller is concerned, so it is a second
	// name, and there is nothing extra to spell in a connection URL.
	return s.custody.resolve(ctx, p, base, "default")
}

// session is one brokered connection: who opened it, to what, and on whose
// authority. Every protocol fills the same four fields, which is what makes the
// record the same line whichever one was spoken.
type session struct {
	p        Principal
	base     string // the name the caller asked for
	scope    string // which custody paid, or ScopeTrust for a base of ours
	database string // the database within it
}

// opened records the authorization. It is written when the session starts
// rather than when it ends, because a session can outlast a shift and the
// question "who is connected to that" has to be answerable while it still is.
func (s *Server) opened(in session) {
	s.log.Info("session",
		"org", in.p.Org, "name", in.p.Name, "kind", in.p.Kind,
		"base", clip(in.base), "scope", in.scope, "database", clip(in.database))
}

// closed records the spend: how long the session held and how much crossed it.
func (s *Server) closed(in session, started time.Time, from, to int64) {
	s.log.Info("spend",
		"org", in.p.Org, "name", in.p.Name, "kind", in.p.Kind,
		"base", clip(in.base), "scope", in.scope, "database", clip(in.database),
		"millis", time.Since(started).Milliseconds(), "read", from, "wrote", to)
}

// refused records a session that did not open, in the same shape and without
// the reason the client was given. What went wrong is in the error; who wanted
// it is what makes the line worth keeping.
func (s *Server) refused(in session, err error) {
	s.log.Warn("refused",
		"org", in.p.Org, "name", in.p.Name, "kind", in.p.Kind,
		"base", clip(in.base), "database", clip(in.database), "error", err.Error())
}

// bind opens the listener a protocol serves on. An absolute path is a unix
// socket and anything else is host:port, which is the rule libpq itself uses,
// so an operator writing an address writes the one their client already
// understands.
//
// A socket is replaced rather than refused when one is already there: a host
// that was destroyed rather than shut down leaves the file behind, and a broker
// that will not start until somebody deletes it is a broker that needs a person
// at 3am. It is created with the group bit and no more — the token is what
// authorizes a session, and a mode is not, but there is no reason for every
// account on the host to be able to try.
func bind(addr string) (net.Listener, error) {
	if !socket(addr) {
		return net.Listen("tcp", addr)
	}
	if err := os.Remove(addr); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	l, err := net.Listen("unix", addr)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(addr, 0o660); err != nil {
		_ = l.Close()
		return nil, err
	}
	return l, nil
}

// accept hands every connection to speak, on a goroutine of its own, until the
// listener is closed.
//
// A refused accept that is not the listener closing does not end the loop. The
// one that happens in practice is running out of descriptors, and a broker that
// stopped listening because it briefly could not would stay stopped after the
// cause had passed — so it pauses and tries again, and says so, which is what
// makes the cause visible from outside the host.
func (s *Server) accept(l net.Listener, speak func(net.Conn)) {
	for {
		c, err := l.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("accept", "listen", l.Addr().String(), "error", err.Error())
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go speak(c)
	}
}

// relay carries bytes between the caller and the far end until either stops,
// and answers with how much crossed each way.
//
// Nothing here reads what it carries. Once both ends have finished their
// handshakes the protocol is theirs, and a broker that parsed the traffic would
// be a second implementation of every statement, prepared or otherwise, that
// they will ever exchange.
func relay(caller, far net.Conn) (from, to int64) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		to, _ = io.Copy(far, caller)
		_ = far.Close()
	}()
	from, _ = io.Copy(caller, far)
	_ = caller.Close()
	<-done
	return from, to
}

// deadline is when a session must end: the moment the token that opened it
// stops being good. A connection is long-lived and a token is not, so without
// this a session outlives its own authorization — and revoking an identity
// would close nothing that was already open.
//
// It is set on both ends, so neither half lingers on after the other is cut.
//
// A principal with no expiry is refused here rather than given an open-ended
// connection. The verifier requires one, so this is a backstop — and the right
// place for it, because passing a zero time to SetDeadline CLEARS the deadline:
// the failure would be silent, and what it produces is the one thing this
// function exists to prevent.
func deadline(p Principal, ends ...net.Conn) error {
	if p.Until.IsZero() {
		return errors.New("egress: the token says nothing about when it stops")
	}
	for _, c := range ends {
		_ = c.SetDeadline(p.Until)
	}
	return nil
}

// clip bounds what a caller can write into a record. A base and a database
// arrive in a startup packet, which is thousands of bytes wide, and a line is
// worth less the more of it somebody else chose. Everything a record needs is
// inside a segment's own length.
func clip(s string) string {
	if len(s) > 64 {
		return s[:64] + "…"
	}
	return s
}

// serve starts every listener this host was configured for. A listener that
// cannot bind ends the process rather than leaving an address callers were
// told about and nothing is behind.
func (s *Server) serve() ([]net.Listener, error) {
	var open []net.Listener
	if s.cfg.Postgres != "" {
		l, err := bind(s.cfg.Postgres)
		if err != nil {
			return nil, err
		}
		open = append(open, l)
		s.log.Info("brokering", "postgres", s.cfg.Postgres)
		go s.accept(l, s.postgres)
	}
	return open, nil
}

// shut closes listeners on the way out.
func shut(open []net.Listener, log *slog.Logger) {
	for _, l := range open {
		if err := l.Close(); err != nil && log != nil {
			log.Warn("close", "listen", l.Addr().String(), "error", err.Error())
		}
	}
}

// socket reports whether an address names a unix socket rather than a host and
// port. One rule, used everywhere an address is read here: this host binds by
// it, a base is reached by it, and a sealed origin is refused by it.
func socket(addr string) bool { return strings.HasPrefix(addr, "/") }

// where splits an address into the two halves a connection needs. It is the
// rule libpq uses, so an operator writes the address their client already
// understands and this host's listener and its bases are described alike.
//
// A socket directory takes the default port, because the port is only how libpq
// names the file inside it and every base of ours answers on 5432.
func where(addr string) (string, uint16, error) {
	if socket(addr) {
		return addr, 5432, nil
	}
	host, named, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return "", 0, fmt.Errorf("egress: %q is not an absolute socket path or host:port", addr)
	}
	port, err := strconv.ParseUint(named, 10, 16)
	if err != nil || port == 0 {
		return "", 0, fmt.Errorf("egress: %q names no port", addr)
	}
	return host, uint16(port), nil
}
