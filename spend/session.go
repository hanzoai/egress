package spend

import (
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"
)

// Session returns what a database driver dials to reach egress.
//
// It is the same swap Client is, one layer down. Client hands an SDK an
// *http.Client and the SDK is unchanged; this hands a driver a connection URL
// and the driver is unchanged — pgx.Connect, sql.Open, DATABASE_URL. What
// changes underneath is that the password is this caller's IAM access token
// rather than a database password, and the far end is egress, which holds
// whatever the real database wants and attaches it there.
//
// Provider names the base, and it travels as the postgres user because that is
// the field a connection URL has for it. Database names the database within
// that base and travels as its own.
//
// The token expires, which is the point of it and is worth saying out loud: the
// URL is good for as long as the token in it is, so a pool that opens a
// connection later needs one built later. Call this again — it is a string and
// costs nothing — from wherever the driver lets you set a password per
// connection, and mint the token the way visor does, replacing it before it
// dies rather than after.
func Session(cfg Config) string {
	u := &url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.Provider, cfg.Token),
		Path:   "/" + cfg.Database,
	}
	// sslmode is stated rather than left to default, so that this leg is what
	// the URL says it is and not what the environment last decided. Egress
	// answers no to TLS here: what the caller reaches is a unix socket or a
	// link the operator trusts, and the encryption that matters is on the leg
	// egress makes to the database.
	q := url.Values{"sslmode": {"disable"}}
	if deadline := cfg.Deadline; deadline > 0 {
		q.Set("connect_timeout", strconv.Itoa(int((deadline+time.Second-1)/time.Second)))
	}
	if cfg.Network == "unix" || strings.HasPrefix(cfg.Address, "/") {
		// libpq takes a socket as the DIRECTORY holding it and derives the file
		// from the port, so the address egress binds is split back into the two
		// halves a client states. One value configures both ends.
		dir, port := socket(cfg.Address)
		q.Set("host", dir)
		if port != "" {
			q.Set("port", port)
		}
	} else {
		u.Host = cfg.Address
	}
	u.RawQuery = q.Encode()
	return u.String()
}

// prefix is how libpq names a socket file inside its directory.
const prefix = ".s.PGSQL."

// socket splits the path egress binds into the directory and port a client
// states. A path that is not named the way libpq names one is taken whole as
// the directory, which is what a client would do with it too.
func socket(address string) (dir, port string) {
	base := path.Base(address)
	if !strings.HasPrefix(base, prefix) {
		return address, ""
	}
	return path.Dir(address), strings.TrimPrefix(base, prefix)
}
