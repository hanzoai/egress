package egress

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/egress/spend"
	"github.com/hanzoai/jwt"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// far stands in for a database at the other end of a session. It speaks enough
// of the protocol to finish a handshake and answer a query, which is all a
// session needs of it, and it records what arrived — the startup parameters,
// the password, whether the leg was encrypted — because that is the half of the
// design a test can only see from over here.
type far struct {
	addr string
	// secret is the password it demands. Empty means it demands none, which is
	// how one of our own bases answers.
	secret string
	// identity is the certificate it presents. Nil means it will not encrypt.
	identity *tls.Certificate

	mu        sync.Mutex
	asked     []map[string]string
	presented []string
	sealed    bool
	heard     []string
}

// answering stands up a database and returns it listening on loopback.
func answering(t *testing.T, secret string, identity *tls.Certificate) *far {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = l.Close() })
	f := &far{addr: l.Addr().String(), secret: secret, identity: identity}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go f.hold(c)
		}
	}()
	return f
}

// at is where this database answers, spelled the way an origin spells one.
func (f *far) at() string { return "postgres://" + f.addr }

func (f *far) saw() ([]map[string]string, []string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]string(nil), f.asked...),
		append([]string(nil), f.presented...), f.sealed
}

func (f *far) hold(raw net.Conn) {
	c := raw
	defer func() { _ = c.Close() }()

	var start *pgproto3.StartupMessage
	for start == nil {
		_, body, err := take(c, false, startupMost)
		if err != nil || len(body) < 4 {
			return
		}
		switch binary.BigEndian.Uint32(body) {
		case sslAsked:
			if f.identity == nil {
				if _, err := c.Write([]byte{'N'}); err != nil {
					return
				}
				continue
			}
			if _, err := c.Write([]byte{'S'}); err != nil {
				return
			}
			sealed := tls.Server(c, &tls.Config{Certificates: []tls.Certificate{*f.identity}})
			if err := sealed.Handshake(); err != nil {
				return
			}
			c = sealed
			f.mu.Lock()
			f.sealed = true
			f.mu.Unlock()
		case gssAsked:
			if _, err := c.Write([]byte{'N'}); err != nil {
				return
			}
		default:
			var m pgproto3.StartupMessage
			if err := m.Decode(body); err != nil {
				return
			}
			start = &m
		}
	}

	presented := ""
	if f.secret != "" {
		if err := say(c, &pgproto3.AuthenticationCleartextPassword{}); err != nil {
			return
		}
		kind, body, err := take(c, true, messageMost)
		if err != nil || kind != 'p' {
			return
		}
		var m pgproto3.PasswordMessage
		if err := m.Decode(body); err != nil {
			return
		}
		presented = m.Password
	}

	f.mu.Lock()
	f.asked = append(f.asked, start.Parameters)
	f.presented = append(f.presented, presented)
	f.mu.Unlock()

	if presented != f.secret {
		refuse(c, "28P01", "password authentication failed for user "+start.Parameters["user"])
		return
	}

	if err := say(c,
		&pgproto3.AuthenticationOk{},
		&pgproto3.ParameterStatus{Name: "server_version", Value: "18.0"},
		&pgproto3.ParameterStatus{Name: "client_encoding", Value: "UTF8"},
		&pgproto3.BackendKeyData{ProcessID: 4242, SecretKey: []byte{1, 2, 3, 4}},
		&pgproto3.ReadyForQuery{TxStatus: 'I'},
	); err != nil {
		return
	}

	for {
		kind, body, err := take(c, true, 1<<20)
		if err != nil || kind == 'X' {
			return
		}
		if kind != 'Q' {
			continue
		}
		var q pgproto3.Query
		if err := q.Decode(body); err != nil {
			return
		}
		f.mu.Lock()
		f.heard = append(f.heard, q.String)
		f.mu.Unlock()
		if err := say(c,
			&pgproto3.RowDescription{Fields: []pgproto3.FieldDescription{{
				Name: []byte("answer"), DataTypeOID: 25, DataTypeSize: -1, TypeModifier: -1,
			}}},
			&pgproto3.DataRow{Values: [][]byte{[]byte("the base answered")}},
			&pgproto3.CommandComplete{CommandTag: []byte("SELECT 1")},
			&pgproto3.ReadyForQuery{TxStatus: 'I'},
		); err != nil {
			return
		}
	}
}

// vouched mints a certificate for 127.0.0.1 and the pool that trusts it, so a
// test can exercise the encrypted leg rather than configure it out of the way.
func vouched(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "a database"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		DNSNames:              []string{"a.database.example"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(leaf)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, pool
}

// brokering opens egress's database listener and answers with the address a client
// dials. It is the real listener and the real handler; only the address is a
// test's.
func brokering(t *testing.T, s *Server) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	s.cfg.Postgres = addr

	open, err := s.serve()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shut(open, nil) })
	waitFor(t, addr)
	return addr
}

// opening asks egress for one session, the way a service does: the URL comes
// from the SDK and the driver is an ordinary one.
func opening(t *testing.T, addr, base, database, token string) (*pgconn.PgConn, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	to, err := pgconn.Connect(ctx, spend.Session(spend.Config{
		Network: "tcp", Address: addr, Token: token,
		Provider: base, Database: database, Deadline: 10 * time.Second,
	}))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = to.Close(context.Background()) })
	return to, nil
}

// answer runs one statement over an open session and returns the single value
// the stand-in database sends back. It is what proves the relay carries bytes
// in both directions after the two handshakes are over.
func answer(t *testing.T, to *pgconn.PgConn, statement string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := to.Exec(ctx, statement).ReadAll()
	if err != nil {
		t.Fatalf("the session carried nothing: %v", err)
	}
	if len(out) == 0 || len(out[0].Rows) == 0 || len(out[0].Rows[0]) == 0 {
		t.Fatalf("no row came back: %+v", out)
	}
	return string(out[0].Rows[0][0])
}

// ours points the `sql` base at a stand-in, which is the override an operator
// uses to move a base and a test uses to stand one up.
func ours(s *Server, f *far) {
	if s.cfg.URLs == nil {
		s.cfg.URLs = map[string]string{}
	}
	s.cfg.URLs["sql"] = f.at()
}

// TestASessionToOneOfOurBasesCarriesNoCredential is the native mode, whole.
//
// The caller holds no database password and egress reads none: what reaches the
// base is the caller's TENANT as the role, and the only thing that had to be
// true for it is that the caller's IAM token verified.
func TestASessionToOneOfOurBasesCarriesNoCredential(t *testing.T) {
	base := answering(t, "", nil)
	st := newStore(nil)
	s, key := serving(t, st, 100)
	ours(s, base)

	to, err := opening(t, brokering(t, s), "sql", "books", token(t, key, nil))
	if err != nil {
		t.Fatalf("a session to one of our own bases was refused: %v", err)
	}
	if got := answer(t, to, "select 'hi'"); got != "the base answered" {
		t.Errorf("the relay carried %q", got)
	}

	asked, presented, sealed := base.saw()
	if len(asked) != 1 {
		t.Fatalf("the base saw %d connections", len(asked))
	}
	if asked[0]["user"] != alice.Org {
		t.Errorf("the base was told user %q, want the tenant %q", asked[0]["user"], alice.Org)
	}
	if asked[0]["database"] != "books" {
		t.Errorf("the base was told database %q", asked[0]["database"])
	}
	if presented[0] != "" {
		t.Errorf("a credential was presented to one of our own bases: %q", presented[0])
	}
	if sealed {
		t.Error("the base leg was encrypted, which this test cannot have arranged")
	}
	// The whole point of the mode: nothing was read, so nothing had to be
	// stored. A store read here would mean a secret exists for hanzo-sql.
	if st.count() != 0 {
		t.Errorf("custody was read %d times for a base that needs no credential", st.count())
	}
}

// TestASessionToADatabaseThatIsNotOursSpendsTheSealedCredential is custody
// mode, whole: the origin comes out of the caller's own custody, carries the
// credential, and the leg to it is encrypted and verified.
func TestASessionToADatabaseThatIsNotOursSpendsTheSealedCredential(t *testing.T) {
	identity, pool := vouched(t)
	base := answering(t, "the-database-password", &identity)
	_, port, err := net.SplitHostPort(base.addr)
	if err != nil {
		t.Fatal(err)
	}

	st := newStore(map[string]string{
		ownRef(alice, "analytics", "default"): "postgres://reader:the-database-password@a.database.example:" + port + "/facts",
	})
	s, key := serving(t, st, 100)
	s.roots = pool
	// The one thing a test replaces: without it the address below is refused
	// for being off the public internet, which is the property the next test
	// asserts.
	s.lookup = func(context.Context, string) ([]string, error) { return []string{"127.0.0.1"}, nil }

	to, err := opening(t, brokering(t, s), "analytics", "warehouse", token(t, key, nil))
	if err != nil {
		t.Fatalf("a session to the tenant's own database was refused: %v", err)
	}
	if got := answer(t, to, "select 1"); got != "the base answered" {
		t.Errorf("the relay carried %q", got)
	}

	asked, presented, sealed := base.saw()
	if !sealed {
		t.Error("the credential crossed an unencrypted leg")
	}
	if presented[0] != "the-database-password" {
		t.Errorf("the database was given %q — the sealed credential was not attached", presented[0])
	}
	if asked[0]["user"] != "reader" {
		t.Errorf("the database was told user %q, want the origin's own", asked[0]["user"])
	}
	// The origin says where and as whom; the client says which database. A
	// credential's own rights are what bound that, and they are the tenant's.
	if asked[0]["database"] != "warehouse" {
		t.Errorf("database = %q, want the one the client named", asked[0]["database"])
	}
	// And the caller's own token stayed here. It identifies the caller to
	// egress and buys nothing at a database.
	for _, seen := range presented {
		if strings.Count(seen, ".") >= 2 {
			t.Errorf("something shaped like the caller's token reached the database: %q", seen)
		}
	}
}

// TestASessionRefusesAnUnidentifiedCaller is the gate, on this protocol.
//
// It is the same Verifier the routes use, so what is asserted here is that it
// is reached at all — every refusal a token can earn is already walked in
// principal_test.go, and the two must not be able to disagree.
func TestASessionRefusesAnUnidentifiedCaller(t *testing.T) {
	base := answering(t, "", nil)
	s, key := serving(t, newStore(nil), 100)
	ours(s, base)
	addr := brokering(t, s)

	other := issuerKey(t)
	for name, presented := range map[string]string{
		"no password":     "",
		"not a token":     "hunter2",
		"another issuer":  token(t, key, func(c *jwt.Claims) { c.Issuer = "https://evil.example" }),
		"another app":     token(t, key, func(c *jwt.Claims) { c.Audience = jwt.ClaimStrings{"hanzo-console"} }),
		"no expiry":       token(t, key, func(c *jwt.Claims) { c.ExpiresAt = nil }),
		"expired":         token(t, key, func(c *jwt.Claims) { c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Minute)) }),
		"another key":     token(t, other, nil),
		"path in subject": token(t, key, func(c *jwt.Claims) { c.Subject, c.Id = "../../root", "" }),
	} {
		t.Run(name, func(t *testing.T) {
			if to, err := opening(t, addr, "sql", "books", presented); err == nil {
				_ = to.Close(context.Background())
				t.Fatal("an unidentified caller was given a session")
			}
		})
	}
	if asked, _, _ := base.saw(); len(asked) != 0 {
		t.Fatalf("%d connections were made to a base for callers nobody could name", len(asked))
	}
}

// TestASessionCannotReachAnotherPrincipalsDatabase is the isolation invariant
// on this path.
//
// The base name comes off the wire — it has to, it is which database — so this
// is where a caller would try to spend somebody else's. It cannot, and not
// because the name is checked: the credential is addressed by a path built from
// the VERIFIED principal, and a name is only its last segment.
func TestASessionCannotReachAnotherPrincipalsDatabase(t *testing.T) {
	const theirs = "postgres://them:their-password@a.database.example:5432/theirs"
	st := newStore(map[string]string{
		ownRef(Principal{Org: "globex", Kind: Persons, Name: "u-9"}, "analytics", "default"): theirs,
		orgRef(Principal{Org: "globex"}, "analytics", "default"):                             theirs,
	})
	s, key := serving(t, st, 1000)
	s.lookup = func(context.Context, string) ([]string, error) {
		t.Error("a host was resolved for a session that should never have got that far")
		return nil, errors.New("no")
	}
	addr := brokering(t, s)

	// Every spelling that would reach the other tenant's row if the name were
	// doing any of the addressing.
	for _, name := range []string{
		"analytics",
		"globex",
		"orgs/globex/users/u-9/connectors/analytics/default",
		"../../globex/users/u-9/connectors/analytics",
		"..",
		"analytics/../../../globex",
		"ANALYTICS",
	} {
		t.Run(name, func(t *testing.T) {
			if to, err := opening(t, addr, name, "facts", token(t, key, nil)); err == nil {
				_ = to.Close(context.Background())
				t.Fatalf("%q reached a session", name)
			}
		})
	}
	for ref := range st.held {
		if !strings.HasPrefix(ref, "orgs/globex/") {
			t.Errorf("a session wrote outside the store it was given: %s", ref)
		}
	}
}

// TestAnOriginThatIsNotOursCannotNameThisHost is the one hole custody mode
// would otherwise open.
//
// A tenant seals its own connection URL, so for the first time a caller decides
// an address. Left alone that makes the broker a tunnel: to this host's
// loopback, to the network it sits on, to a cloud's metadata service. The
// resolver refuses everything that is not on the public internet, and a socket
// path is refused before a resolver is reached at all.
func TestAnOriginThatIsNotOursCannotNameThisHost(t *testing.T) {
	st := newStore(nil)
	s, key := serving(t, st, 1000)
	addr := brokering(t, s)

	for name, at := range map[string]string{
		"loopback":       "postgres://u:p@127.0.0.1:5432/x",
		"loopback by v6": "postgres://u:p@[::1]:5432/x",
		"this network":   "postgres://u:p@10.1.2.3:5432/x",
		"also private":   "postgres://u:p@192.168.0.9:5432/x",
		"carrier grade":  "postgres://u:p@100.64.3.4:5432/x",
		"the metadata":   "postgres://u:p@169.254.169.254:5432/x",
		"a socket":       "postgres://u:p@%2Fvar%2Frun%2Fpostgresql:5432/x",
		"nothing at all": "postgres://u:p@0.0.0.0:5432/x",
	} {
		t.Run(name, func(t *testing.T) {
			if err := st.PutSecret(context.Background(), ownRef(alice, "elsewhere", "default"), []byte(at)); err != nil {
				t.Fatal(err)
			}
			to, err := opening(t, addr, "elsewhere", "x", token(t, key, nil))
			if err == nil {
				_ = to.Close(context.Background())
				t.Fatalf("a sealed origin reached %s", at)
			}
		})
	}
}

// TestNearIsWhatThisHostCanReachOnlyBecauseOfWhereItSits pins the rule the
// resolver applies, so that it can be read on its own rather than inferred from
// a table of URLs.
func TestNearIsWhatThisHostCanReachOnlyBecauseOfWhereItSits(t *testing.T) {
	for _, at := range []string{
		"127.0.0.1", "::1", "10.0.0.1", "172.16.0.1", "192.168.1.1",
		"169.254.169.254", "100.64.0.1", "100.127.255.255", "0.0.0.0",
		"224.0.0.1", "fe80::1", "fd00::1", "ff02::1",
	} {
		if !near(net.ParseIP(at)) {
			t.Errorf("near(%s) = false — a sealed origin could name it", at)
		}
	}
	for _, at := range []string{
		"1.1.1.1", "8.8.8.8", "99.99.99.99", "100.63.255.255", "100.128.0.1",
		"2606:4700:4700::1111",
	} {
		if near(net.ParseIP(at)) {
			t.Errorf("near(%s) = true — a real database could not be reached", at)
		}
	}
}

// TestTheResolverRefusesWithoutBeingReplaced drives the shipped resolver rather
// than the test's stand-in, on a literal address that needs no network to
// resolve. Without this the property above is only ever asserted against a
// function the tests replaced.
func TestTheResolverRefusesWithoutBeingReplaced(t *testing.T) {
	if _, err := reachable(context.Background(), "127.0.0.1"); err == nil {
		t.Fatal("the shipped resolver returned this host's own loopback")
	}
	out, err := reachable(context.Background(), "8.8.8.8")
	if err != nil || len(out) != 1 || out[0] != "8.8.8.8" {
		t.Fatalf("reachable(8.8.8.8) = %v, %v", out, err)
	}
}

// TestNothingAboutASessionComesFromTheEnvironment pins invariant 7 on this
// path. pgconn's own parser fills an absent setting from PG* variables and from
// a password file, and this process's environment is exactly where a credential
// must not be found — so a base that needs no credential must not acquire one,
// and none of the three fields that decide where a session goes may be moved by
// a variable.
func TestNothingAboutASessionComesFromTheEnvironment(t *testing.T) {
	base := answering(t, "", nil)
	elsewhere := answering(t, "", nil)

	t.Setenv("PGPASSWORD", "a-password-from-the-environment")
	t.Setenv("PGUSER", "postgres")
	t.Setenv("PGDATABASE", "somebody-elses")
	host, port, err := net.SplitHostPort(elsewhere.addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PGHOST", host)
	t.Setenv("PGPORT", port)

	s, key := serving(t, newStore(nil), 100)
	ours(s, base)

	to, err := opening(t, brokering(t, s), "sql", "books", token(t, key, nil))
	if err != nil {
		t.Fatalf("session refused: %v", err)
	}
	_ = answer(t, to, "select 1")

	asked, presented, _ := base.saw()
	if len(asked) != 1 {
		t.Fatalf("the base saw %d connections — the session went somewhere else", len(asked))
	}
	if presented[0] != "" {
		t.Fatalf("a password reached the base out of the environment: %q", presented[0])
	}
	if asked[0]["user"] != alice.Org || asked[0]["database"] != "books" {
		t.Errorf("the environment moved the session: %+v", asked[0])
	}
	if other, _, _ := elsewhere.saw(); len(other) != 0 {
		t.Error("PGHOST chose where a session went")
	}
}

// TestWhatTheClientAsksForTravelsExceptWhatIsNotItsToChoose covers the startup
// parameters. A client's own settings are its own; the identity is not, and
// neither is a connection that streams the write-ahead log instead of running
// statements.
func TestWhatTheClientAsksForTravelsExceptWhatIsNotItsToChoose(t *testing.T) {
	carries := carried(map[string]string{
		"user":             "postgres",
		"database":         "books",
		"replication":      "database",
		"application_name": "reports",
		"search_path":      "public",
	})
	for _, gone := range []string{"user", "database", "replication"} {
		if _, there := carries[gone]; there {
			t.Errorf("%q travelled — it is not the client's to choose", gone)
		}
	}
	if carries["application_name"] != "reports" || carries["search_path"] != "public" {
		t.Errorf("the client's own settings were dropped: %+v", carries)
	}

	// And the same over the wire, because a filter that is never reached is not
	// a filter.
	base := answering(t, "", nil)
	s, key := serving(t, newStore(nil), 100)
	ours(s, base)
	addr := brokering(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg, err := pgconn.ParseConfig(spend.Session(spend.Config{
		Network: "tcp", Address: addr, Token: token(t, key, nil),
		Provider: "sql", Database: "books",
	}))
	if err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams["application_name"] = "reports"
	cfg.RuntimeParams["replication"] = "database"
	to, err := pgconn.ConnectConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("session refused: %v", err)
	}
	defer func() { _ = to.Close(context.Background()) }()

	asked, _, _ := base.saw()
	if asked[0]["application_name"] != "reports" {
		t.Errorf("application_name = %q", asked[0]["application_name"])
	}
	if _, there := asked[0]["replication"]; there {
		t.Error("a client asked for a replication connection and got one")
	}
}

// TestASessionDoesNotOutliveItsToken. A connection is long-lived and a token is
// not. Without an end, revoking an identity closes nothing that is already
// connected, and a session opened this morning is still spending tonight on an
// authorization that lapsed at noon.
func TestASessionDoesNotOutliveItsToken(t *testing.T) {
	base := answering(t, "", nil)
	s, key := serving(t, newStore(nil), 100)
	ours(s, base)

	// Seconds rather than milliseconds because an expiry is stated in whole
	// seconds and a sub-second one truncates to already gone.
	brief := token(t, key, func(c *jwt.Claims) {
		c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(3 * time.Second))
	})
	to, err := opening(t, brokering(t, s), "sql", "books", brief)
	if err != nil {
		t.Fatalf("session refused: %v", err)
	}
	if got := answer(t, to, "select 1"); got != "the base answered" {
		t.Fatalf("the session did not work while its token did: %q", got)
	}

	time.Sleep(3500 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := to.Exec(ctx, "select 1").ReadAll(); err == nil {
		t.Fatal("a session outlived the token that opened it")
	}
}

// TestASessionWithNoCredentialIsRefusedAndNothingIsDialled. An absent
// credential ends the session; it never becomes a reason to look somewhere less
// guarded, and it never becomes a connection made as nobody.
func TestASessionWithNoCredentialIsRefusedAndNothingIsDialled(t *testing.T) {
	base := answering(t, "", nil)
	s, key := serving(t, newStore(nil), 100)
	ours(s, base)

	to, err := opening(t, brokering(t, s), "warehouse", "facts", token(t, key, nil))
	if err == nil {
		_ = to.Close(context.Background())
		t.Fatal("a session opened with no credential for the base it named")
	}
	if asked, _, _ := base.saw(); len(asked) != 0 {
		t.Error("something was dialled for a base with no credential")
	}
}

// TestAnUnreachableStoreDoesNotFallThrough. Absence is the ordinary state of a
// tenant with no database of its own; a store that cannot ANSWER is a fault,
// and the two must not read alike — the cost of confusing them is a session
// opened as somebody else, or none at all when there should be one.
func TestAnUnreachableStoreDoesNotFallThrough(t *testing.T) {
	st := newStore(nil)
	st.fail = errors.New("dial kms: connection refused")
	s, key := serving(t, st, 100)

	to, err := opening(t, brokering(t, s), "analytics", "facts", token(t, key, nil))
	if err == nil {
		_ = to.Close(context.Background())
		t.Fatal("a session opened while the credential store could not answer")
	}
}

// TestTheClientsFirstBytesAreNotEatenByTheHandshake is the failure that a
// buffered reader would produce and nothing else would explain.
//
// A client may write its startup, its password and its first statement in one
// go. Every byte read past the password while deciding is a byte the database
// never sees, and what the caller observes is a session that hangs on a
// statement it certainly sent. So the handshake reads exact frames, and this
// pipelines a query behind the password to prove it.
func TestTheClientsFirstBytesAreNotEatenByTheHandshake(t *testing.T) {
	base := answering(t, "", nil)
	s, key := serving(t, newStore(nil), 100)
	ours(s, base)
	addr := brokering(t, s)

	c, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = c.Close() }()
	_ = c.SetDeadline(time.Now().Add(15 * time.Second))

	startup, err := (&pgproto3.StartupMessage{
		ProtocolVersion: pgproto3.ProtocolVersion30,
		Parameters:      map[string]string{"user": "sql", "database": "books"},
	}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(startup); err != nil {
		t.Fatal(err)
	}
	if kind, _, err := take(c, true, messageMost); err != nil || kind != 'R' {
		t.Fatalf("egress asked %q, %v", kind, err)
	}

	// The password and a statement, in ONE write. A reader that filled a buffer
	// takes both.
	both, err := (&pgproto3.PasswordMessage{Password: token(t, key, nil)}).Encode(nil)
	if err != nil {
		t.Fatal(err)
	}
	both, err = (&pgproto3.Query{String: "select 'pipelined'"}).Encode(both)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Write(both); err != nil {
		t.Fatal(err)
	}

	// Read until the row comes back. The greeting arrives first; the answer to
	// the pipelined statement is what proves nothing was eaten.
	for range 20 {
		kind, body, err := take(c, true, 1<<20)
		if err != nil {
			t.Fatalf("the pipelined statement was never answered: %v", err)
		}
		if kind != 'D' {
			continue
		}
		var row pgproto3.DataRow
		if err := row.Decode(body); err != nil {
			t.Fatal(err)
		}
		if got := string(row.Values[0]); got != "the base answered" {
			t.Fatalf("row = %q", got)
		}
		if heard := base.said(); len(heard) != 1 || heard[0] != "select 'pipelined'" {
			t.Fatalf("the database heard %q", heard)
		}
		return
	}
	t.Fatal("no row arrived")
}

// TestTheSDKDialsTheSocketThisHostBound closes the loop on the address: what an
// operator writes once is what egress binds and what a driver dials, with the
// directory and port a client states derived from it rather than typed a second
// time.
func TestTheSDKDialsTheSocketThisHostBound(t *testing.T) {
	dir, err := os.MkdirTemp("", "eg")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	base := answering(t, "", nil)
	s, key := serving(t, newStore(nil), 100)
	ours(s, base)
	s.cfg.Postgres = filepath.Join(dir, ".s.PGSQL.5432")

	open, err := s.serve()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { shut(open, nil) })

	mode, err := os.Stat(s.cfg.Postgres)
	if err != nil {
		t.Fatal(err)
	}
	if mode.Mode().Perm() != 0o660 {
		t.Errorf("the socket is %v — every account on the host may try", mode.Mode().Perm())
	}

	to, err := opening(t, s.cfg.Postgres, "sql", "books", token(t, key, nil))
	if err != nil {
		t.Fatalf("the SDK could not dial the socket this host bound: %v", err)
	}
	if got := answer(t, to, "select 1"); got != "the base answered" {
		t.Errorf("the relay carried %q", got)
	}

	// And a second time over the same path, because a broker that leaves the
	// file behind only starts once.
	shut(open, nil)
	if open, err = s.serve(); err != nil {
		t.Fatalf("a socket left behind stopped the next start: %v", err)
	}
	shut(open, nil)
}

// TestASessionCountsAgainstTheSamePrincipalsCeiling. A session is a spend like
// a call, so it is admitted by the same limiter and keyed on the same verified
// principal — two ceilings would disagree about who is over budget.
func TestASessionCountsAgainstTheSamePrincipalsCeiling(t *testing.T) {
	base := answering(t, "", nil)
	s, key := serving(t, newStore(nil), 2)
	ours(s, base)
	addr := brokering(t, s)

	mine := token(t, key, nil)
	for i := range 2 {
		if _, err := opening(t, addr, "sql", "books", mine); err != nil {
			t.Fatalf("session %d refused early: %v", i, err)
		}
	}
	if to, err := opening(t, addr, "sql", "books", mine); err == nil {
		_ = to.Close(context.Background())
		t.Fatal("the ceiling did not hold")
	}
	theirs := token(t, key, func(c *jwt.Claims) { c.Owner = "other"; c.Subject = "u-9" })
	if _, err := opening(t, addr, "sql", "books", theirs); err != nil {
		t.Fatalf("one principal's ceiling refused another: %v", err)
	}
}

// TestASessionURLNamesEgressAndCarriesTheTokenAsThePassword pins what a service
// puts in DATABASE_URL. It is an ordinary connection URL, which is the point:
// the driver is unchanged and only what is in the password field is different.
func TestASessionURLNamesEgressAndCarriesTheTokenAsThePassword(t *testing.T) {
	over := spend.Session(spend.Config{
		Network: "tcp", Address: "egress.hanzo.ai:5432",
		Token: "a.b.c", Provider: "sql", Database: "books", Deadline: 10 * time.Second,
	})
	cfg, err := pgconn.ParseConfig(over)
	if err != nil {
		t.Fatalf("the SDK built a URL no driver reads: %v (%s)", err, over)
	}
	if cfg.Host != "egress.hanzo.ai" || cfg.Port != 5432 {
		t.Errorf("the driver would dial %s:%d", cfg.Host, cfg.Port)
	}
	if cfg.User != "sql" || cfg.Password != "a.b.c" || cfg.Database != "books" {
		t.Errorf("user/password/database = %q/%q/%q", cfg.User, cfg.Password, cfg.Database)
	}
	if cfg.TLSConfig != nil || len(cfg.Fallbacks) != 0 {
		t.Error("the leg to egress is stated, so a driver should not be negotiating it")
	}
	if cfg.ConnectTimeout != 10*time.Second {
		t.Errorf("connect timeout = %v", cfg.ConnectTimeout)
	}

	// A socket is split back into the two halves libpq states.
	on := spend.Session(spend.Config{
		Network: "unix", Address: "/run/hanzo/.s.PGSQL.6543",
		Token: "a.b.c", Provider: "sql", Database: "books",
	})
	cfg, err = pgconn.ParseConfig(on)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "/run/hanzo" || cfg.Port != 6543 {
		t.Errorf("the driver would dial %s/.s.PGSQL.%d, want /run/hanzo/.s.PGSQL.6543", cfg.Host, cfg.Port)
	}
}

// TestAClientThatAsksForTLSIsToldNo. The leg to egress is a socket or a link
// the operator trusts; a client that will not have that finds out at the
// handshake rather than by getting a connection it believes is encrypted.
func TestAClientThatAsksForTLSIsToldNo(t *testing.T) {
	base := answering(t, "", nil)
	s, key := serving(t, newStore(nil), 100)
	ours(s, base)
	addr := brokering(t, s)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	// prefer: asks, is told no, carries on. This is the round trip egress must
	// answer rather than ignore.
	over := spend.Session(spend.Config{
		Network: "tcp", Address: addr, Token: token(t, key, nil), Provider: "sql", Database: "books",
	})
	asking := strings.Replace(over, "sslmode=disable", "sslmode=prefer", 1)
	to, err := pgconn.Connect(ctx, asking)
	if err != nil {
		t.Fatalf("a client that asked about TLS was not answered: %v", err)
	}
	_ = to.Close(context.Background())

	// require: will not proceed without it, and does not.
	if to, err := pgconn.Connect(ctx, strings.Replace(over, "sslmode=disable", "sslmode=require", 1)); err == nil {
		_ = to.Close(context.Background())
		t.Fatal("a client was told it had TLS on a leg that has none")
	}
}

// said is what the stand-in database was asked to run.
func (f *far) said() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.heard...)
}
