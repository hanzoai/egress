package egress

import (
	"fmt"
	"net/url"
	"strings"
)

// An Upstream is a third-party API egress may call, the KMS secret that pays for
// it, how that vendor wants its credential presented, and the exact calls a
// caller may make. The table below IS the allowlist, three times over: an
// unlisted vendor is unreachable, an unlisted call is unreachable, and the
// address is never taken from the request.
//
// Base, Auth and Ops are compiled in because none of them varies by
// environment — there is one openrouter.ai, it takes one kind of credential, and
// the set of calls we make of it is a thing to review, not to configure. Only
// what genuinely differs per deployment (KMS address, identity, listen address)
// is configuration. That is also what keeps this from being an open proxy: no
// value an attacker can set reaches the destination.
type Upstream struct {
	// Base is the vendor root a call is rewritten onto. It carries no version
	// segment: the operation supplies the rest of the path.
	Base *url.URL
	// Secret is the KMS reference for this vendor's credential, relative to the
	// reading identity's org — a subpath and a name, because a bare name
	// resolves to a different partition than the one records are written to.
	Secret string
	// Auth is how this vendor wants the credential presented. Vendors disagree:
	// a bearer for one is an `x-api-key` for the next, and getting it wrong
	// produces a 401 that reads like a bad credential.
	Auth Auth
	// Extra is any static header the vendor requires alongside the credential.
	Extra map[string]string
	// Ops is the set of calls allowed, keyed "METHOD /path", each tagged with
	// the kind of thing it does. A vendor API is wider than the part we use:
	// OpenRouter's root also answers /v1/key, /v1/credits and a key-management
	// surface. Forwarding an arbitrary path under the vendor root would
	// authenticate those calls with our credential, so only the calls we
	// actually make are reachable — and a caller is granted a KIND, not a
	// vendor, so buying inference does not also come with reading the account.
	Ops map[string]Kind
}

// Auth names how a vendor wants its credential presented — the header it reads
// and the prefix it expects before the value.
type Auth struct {
	Header string
	Prefix string
}

// Kind separates buying inference from reading the account behind it. They are
// different acts with different consequences, so they are granted separately:
// the service that answers prompts has no business knowing our balance, and the
// job that watches the balance has no business spending it.
type Kind string

const (
	Inference Kind = "inference"
	Account   Kind = "account"
)

var bearer = Auth{Header: "Authorization", Prefix: "Bearer "}

// upstreams is the allowlist. A second vendor is one row plus a KMS record, and
// no new code path.
var upstreams = map[string]Upstream{
	"openrouter": {
		Base:   mustURL("https://openrouter.ai/api"),
		Secret: "ai/OPENROUTER_API_KEY",
		Auth:   bearer,
		Ops: map[string]Kind{
			"GET /v1/models":            Inference, // catalog discovery
			"POST /v1/chat/completions": Inference, // streamed or not
			"POST /v1/completions":      Inference,
			"POST /v1/embeddings":       Inference,

			// Read-only account metadata: the float a treasury job refills
			// against, the key status a console shows, the usage record.
			// Granted as `account`, so the service that answers prompts cannot
			// read them — that service is the one with the widest attack
			// surface, and our balance and key metadata are exactly what an
			// attacker inside it would want next.
			//
			// Absent entirely is the surface beside these that MOVES money
			// rather than reporting it: /v1/keys, which mints and revokes. No
			// kind reaches it.
			"GET /v1/credits":    Account,
			"GET /v1/key":        Account,
			"GET /v1/generation": Account,
			"GET /v1/activity":   Account,
		},
	},
}

// Allows reports the kind of call this is, and whether the upstream permits it
// at all.
func (u Upstream) Allows(method, path string) (Kind, bool) {
	k, ok := u.Ops[method+" "+path]
	return k, ok
}

// Upstreams reports the allowlisted names, sorted for a stable startup log.
func Upstreams() []string {
	out := make([]string, 0, len(upstreams))
	for name := range upstreams {
		out = append(out, name)
	}
	sortStrings(out)
	return out
}

// route splits a request path into the upstream it names and the tail handed to
// the vendor. It accepts exactly `/{name}` and `/{name}/{tail...}`.
//
// The caller names a provider, never a destination. The address is looked up
// here, in the table above, so no request field can reach a host we did not
// choose — the difference between a broker and an open proxy.
func route(path string) (name string, up Upstream, tail string, ok bool) {
	trimmed := strings.TrimPrefix(path, "/")
	name, rest, _ := strings.Cut(trimmed, "/")
	up, ok = upstreams[name]
	if !ok {
		return "", Upstream{}, "", false
	}
	return name, up, "/" + rest, true
}

func mustURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(fmt.Sprintf("egress: bad upstream URL %q: %v", raw, err))
	}
	return u
}

// sortStrings is an insertion sort over the handful of upstream names — small
// enough that reaching for the sort package would cost more to read than it saves.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
