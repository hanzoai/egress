package egress

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// The PostgreSQL wire protocol, which is the first protocol egress brokers a
// session on. What is protocol-independent about a session — where it goes,
// whether it may be opened, the record of it — is in session.go; this file is
// only the handshake, and the next fork's file is only its own.
//
// THE CALLER'S TOKEN ARRIVES AS THE PASSWORD. A postgres client has one field
// for a secret, so that is the field the IAM access token travels in, and it is
// verified by the same Verifier that guards every other route: same issuer,
// same audience, same expiry, same refusal carrying no detail. The caller's
// DATABASE_URL therefore holds an identity that expires rather than a database
// password that does not, and the database's own password — where there is one
// — stays in custody and is attached here.
//
// Egress terminates the client's authentication and performs the far end's
// itself. Those are two different conversations and nothing is passed between
// them: the token never leaves this process, and the credential never reaches
// the caller.
//
// pgproto3 is used as a codec and not as a reader. Its own reader fills a
// buffer that may reach past the message it was asked for, and after the
// handshake every byte read here is a byte the far end never sees — a failure
// that looks like anything but a broker that read ahead. So the frames are read
// exactly, and pgproto3 decodes and encodes them.

// What a client can ask for before it says who it is. The three are the
// protocol's own reserved version numbers.
const (
	sslAsked    = 80877103
	gssAsked    = 80877104
	cancelAsked = 80877102
)

// How much of a message egress will read while it is still deciding. The first
// is libpq's own limit on a startup packet; the second is generous for an
// access token and far short of anything worth buffering.
const (
	startupMost = 10000
	messageMost = 16 << 10
)

// errCancel is a client asking to cancel a running query.
//
// Egress does not forward one, and that follows from holding nothing rather
// than from an oversight. A cancel arrives on a NEW connection carrying no
// authorization at all — the protocol protects it with the secret the far end
// issued — so honouring one means keeping a table of live sessions keyed on a
// value an unidentified caller supplies, and then dialling that session's
// origin again, which for a database that is not ours means keeping its
// credential for the length of the session. Both are things this service
// deliberately does not have.
//
// What a client loses is one round of Ctrl-C; closing the connection still
// stops the query, because the far end ends a backend whose client has gone.
var errCancel = errors.New("egress: cancel is not brokered")

// postgres brokers one client connection for as long as it lasts.
func (s *Server) postgres(c net.Conn) {
	defer func() { _ = c.Close() }()

	select {
	case s.room <- struct{}{}:
		defer func() { <-s.room }()
	default:
		refuse(c, "53300", "too many connections")
		return
	}

	// Until the client has identified itself it is nobody's to bill, so it does
	// not get to hold a connection open on the strength of having opened one.
	// Replaced by the token's own expiry once there is one — see deadline.
	_ = c.SetDeadline(time.Now().Add(greeting))

	start, err := hello(c)
	if err != nil {
		if errors.Is(err, errCancel) {
			s.log.Debug("cancel", "listen", s.cfg.Postgres)
		}
		return
	}
	if start.ProtocolVersion != pgproto3.ProtocolVersion30 {
		// The far end is spoken to in 3.0, so a client that asked for a later
		// minor version is told what it will get. Answering is what keeps a
		// newer client working; silence leaves it assuming it got what it asked
		// for.
		if err := say(c, &pgproto3.NegotiateProtocolVersion{}); err != nil {
			return
		}
	}

	token, err := password(c)
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), greeting)
	defer cancel()

	// The password field carries a bearer token, so it is spelled as one and
	// goes through the one verifier. There is no second one, and no second
	// thing a caller may present.
	p, err := s.verify.Verify(ctx, "Bearer "+token)
	if err != nil {
		refuse(c, "28000", "not identified")
		return
	}
	if !s.limiter.admit(p.who()) {
		refuse(c, "53400", "too many sessions")
		return
	}

	in := session{p: p, base: start.Parameters["user"], database: start.Parameters["database"]}
	at, scope, err := s.origin(ctx, p, in.base)
	if err != nil {
		s.refused(in, err)
		refuse(c, "28000", "no credential")
		return
	}
	in.scope = scope

	up, err := s.connect(ctx, at, in, start.Parameters)
	if err != nil {
		s.refused(in, err)
		refuse(c, "08006", "the database did not answer")
		return
	}
	defer func() { _ = up.Conn.Close() }()

	if err := greet(c, up); err != nil {
		return
	}
	deadline(p, c, up.Conn)

	s.opened(in)
	started := time.Now()
	from, to := relay(c, up.Conn)
	s.closed(in, started, from, to)
}

// hello reads the client's startup, answering what a client asks before it.
func hello(c net.Conn) (*pgproto3.StartupMessage, error) {
	// libpq asks about GSSAPI and then about TLS before it says who it is, so
	// at most two of those precede a startup packet. A third is a client that
	// is never going to get to one.
	for range 3 {
		_, body, err := take(c, false, startupMost)
		if err != nil {
			return nil, err
		}
		if len(body) < 4 {
			return nil, errors.New("egress: a startup packet with no version")
		}
		switch binary.BigEndian.Uint32(body) {
		case sslAsked, gssAsked:
			// 'N' — not here. The leg from a caller to egress is a unix socket
			// or a link the operator trusts, and this is the same answer
			// postgres itself gives when it is not built to encrypt one.
			if _, err := c.Write([]byte{'N'}); err != nil {
				return nil, err
			}
		case cancelAsked:
			return nil, errCancel
		default:
			var m pgproto3.StartupMessage
			if err := m.Decode(body); err != nil {
				return nil, err
			}
			return &m, nil
		}
	}
	return nil, errors.New("egress: the client never said who it is")
}

// password asks for the secret and reads it. Cleartext, because what travels is
// a signed token that this process must read whole in order to verify it, and a
// challenge-response over it would prove possession of a value that already
// proves possession of itself.
func password(c net.Conn) (string, error) {
	if err := say(c, &pgproto3.AuthenticationCleartextPassword{}); err != nil {
		return "", err
	}
	kind, body, err := take(c, true, messageMost)
	if err != nil {
		return "", err
	}
	if kind != 'p' {
		return "", fmt.Errorf("egress: the client answered %q instead of a password", kind)
	}
	var m pgproto3.PasswordMessage
	if err := m.Decode(body); err != nil {
		return "", err
	}
	return m.Password, nil
}

// connect opens the far end and takes its connection over.
//
// The credential exists only inside this function and on the connection it
// makes. It is not returned, not logged, and taken out of every error that
// leaves here — a database quotes back the role it refused, and often enough
// the password with it.
func (s *Server) connect(ctx context.Context, at string, in session, asked map[string]string) (*pgconn.HijackedConn, error) {
	u, err := url.Parse(at)
	if err != nil || (u.Scheme != "postgres" && u.Scheme != "postgresql") {
		return nil, errors.New("egress: the origin is not a postgres URL")
	}
	host, secret := u.Hostname(), ""
	port := uint16(5432)
	if named := u.Port(); named != "" {
		n, err := strconv.ParseUint(named, 10, 16)
		if err != nil || n == 0 {
			return nil, errors.New("egress: the origin names no port")
		}
		port = uint16(n)
	}

	user := u.User.Username()
	if in.scope == ScopeTrust {
		// A base of ours carries no user and no credential. What egress
		// presents instead is the caller's TENANT as the database role, so the
		// base's own grants are a second boundary under this one rather than
		// one role standing in for every tenant. A base that then asks for a
		// password ends the session: there is nothing to answer it with, and
		// nowhere less guarded to look.
		user = in.p.Org
	} else {
		secret, _ = u.User.Password()
	}
	if user == "" {
		return nil, errors.New("egress: the origin names nobody to be")
	}
	database := in.database
	if database == "" {
		database = strings.TrimPrefix(u.Path, "/")
	}

	// EVERY FIELD THAT DECIDES WHERE THE CREDENTIAL GOES IS WRITTEN HERE.
	// pgconn's parser reads PG* variables and a password file whenever a
	// setting is absent, and this process's environment is exactly where a
	// credential must not be found — the whole point of the service. So the
	// parse supplies the library's own private defaults, which is the only
	// thing it is asked for, and everything that matters is written over them.
	cfg, err := pgconn.ParseConfig("")
	if err != nil {
		return nil, fmt.Errorf("egress: %w", err)
	}
	cfg.Host, cfg.Port, cfg.Database = host, port, database
	cfg.User, cfg.Password = user, secret
	cfg.RuntimeParams = carried(asked)
	cfg.ConnectTimeout = reach
	cfg.DialFunc = (&net.Dialer{Timeout: reach}).DialContext
	// One address, and it is the one named above. A fallback list is how libpq
	// spells "try it again without encryption", and a leg that quietly retries
	// unencrypted is not a weaker leg — it is the whole downgrade.
	cfg.Fallbacks = nil
	cfg.SSLNegotiation = "postgres"
	// 3.0 both ways, so what a client is greeted with is what the far end
	// actually agreed to.
	cfg.MinProtocolVersion, cfg.MaxProtocolVersion = "3.0", "3.0"
	cfg.ValidateConnect, cfg.AfterConnect = nil, nil
	cfg.OnNotice, cfg.OnNotification = nil, nil
	cfg.KerberosSrvName, cfg.KerberosSpn = "", ""
	cfg.TLSConfig = nil

	if in.scope != ScopeTrust {
		if socket(host) {
			// A custody origin is the one place a caller decides an address, so
			// it may not name a socket on this host: that is how a tenant would
			// reach a co-located database as whoever this process is.
			return nil, errors.New("egress: an origin that is not ours must name a host")
		}
		cfg.TLSConfig = &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12, RootCAs: s.roots}
		cfg.LookupFunc = s.lookup
	}

	to, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		return nil, scrub(err, secret)
	}
	if err := to.SyncConn(ctx); err != nil {
		_ = to.Close(ctx)
		return nil, scrub(err, secret)
	}
	up, err := to.Hijack()
	if err != nil {
		_ = to.Close(ctx)
		return nil, scrub(err, secret)
	}
	// Whatever the library read and has not handed back would be lost the
	// moment this becomes a relay, and a session missing its first bytes fails
	// in a way that points anywhere but here. It does not happen after a
	// synchronised connection; if it ever does, the session does not open.
	if n := up.Frontend.ReadBufferLen(); n > 0 {
		_ = up.Conn.Close()
		return nil, fmt.Errorf("egress: the database sent %d bytes the session cannot carry", n)
	}
	return up, nil
}

// greet finishes the handshake the client is waiting on, out of what the far
// end already said. The parameters, the backend key and the transaction status
// are the far end's own, so a client reads its server's encoding, time zone and
// version rather than a broker's idea of them.
func greet(to io.Writer, up *pgconn.HijackedConn) error {
	status := up.TxStatus
	if status == 0 {
		status = 'I'
	}
	out := []pgproto3.BackendMessage{&pgproto3.AuthenticationOk{}}
	for name, value := range up.ParameterStatuses {
		out = append(out, &pgproto3.ParameterStatus{Name: name, Value: value})
	}
	return say(to, append(out,
		&pgproto3.BackendKeyData{ProcessID: up.PID, SecretKey: up.SecretKey},
		&pgproto3.ReadyForQuery{TxStatus: status})...)
}

// carried is what of the client's startup travels to the far end.
//
// Everything the client asked for goes, except the three that are not the
// client's to choose: `user`, which egress writes because it is the identity it
// verified; `database`, which travels as its own field; and `replication`,
// because a connection that streams the write-ahead log is a copy of the
// database rather than a session on it, and nothing in a session's
// authorization says anything about that.
func carried(asked map[string]string) map[string]string {
	out := make(map[string]string, len(asked))
	for name, value := range asked {
		switch strings.ToLower(name) {
		case "user", "database", "replication":
			continue
		}
		out[name] = value
	}
	return out
}

// reachable resolves a host and returns only the addresses that are on the
// public internet.
//
// A database that is not ours is the one origin a caller decides, because its
// URL is theirs and they sealed it. Without this, enrolling one that names
// 127.0.0.1, this host's own network or 169.254.169.254 turns the broker into a
// tunnel to whatever answers there, spoken to as this process. Resolving once
// and returning only what passed also closes the other half of it: pgconn dials
// what this returned, so a name that answers differently a moment later is not
// the name that gets dialled.
func reachable(ctx context.Context, host string) ([]string, error) {
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(ips))
	for _, ip := range ips {
		if !near(ip) {
			out = append(out, ip.String())
		}
	}
	if len(out) == 0 {
		return nil, errors.New("egress: that address is not on the public internet")
	}
	return out, nil
}

// near reports whether an address is one this host can reach only because of
// where it sits — its own loopback, its own network, the link, or the block
// carriers and mesh networks hand out, which is private in every way that
// matters here and is not what IsPrivate answers.
func near(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil && v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 {
		return true
	}
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast()
}

// take reads exactly one message and not a byte more. A startup packet carries
// its length and nothing else in front of it; every message after one carries a
// type byte first.
func take(from io.Reader, typed bool, most int) (byte, []byte, error) {
	var head [5]byte
	at := 0
	if typed {
		at = 1
	}
	if _, err := io.ReadFull(from, head[:at+4]); err != nil {
		return 0, nil, err
	}
	size := binary.BigEndian.Uint32(head[at : at+4])
	if size < 4 || int(size) > most {
		return 0, nil, fmt.Errorf("egress: %d is not a message length", size)
	}
	body := make([]byte, size-4)
	if _, err := io.ReadFull(from, body); err != nil {
		return 0, nil, err
	}
	return head[0], body, nil
}

// say writes messages as one write, so a greeting or a refusal arrives whole.
func say(to io.Writer, out ...pgproto3.BackendMessage) error {
	var raw []byte
	for _, m := range out {
		var err error
		if raw, err = m.Encode(raw); err != nil {
			return err
		}
	}
	_, err := to.Write(raw)
	return err
}

// refuse tells the client why in the one way a postgres client understands, and
// says no more than every other route does. The difference between
// "no token", "wrong audience" and "expired" is an oracle for somebody
// assembling one, and none of it helps a caller that legitimately holds one.
func refuse(to io.Writer, code, why string) {
	_ = say(to, &pgproto3.ErrorResponse{
		Severity: "FATAL", SeverityUnlocalized: "FATAL", Code: code, Message: why,
	})
}
