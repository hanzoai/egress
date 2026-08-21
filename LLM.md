# LLM.md — hanzoai/egress

The outbound trust boundary: upstream credentials stay in KMS, callers ask for a
metered call and never hold a key. `ingress` is the inbound twin.

## Laws

- **Import the provider surface from `hanzoai/ai`; never copy it.** A second
  implementation of the dialects drifts silently and the drift reaches customers
  before it reaches us.
- **Import rate limits and circuit breakers from `gateway`'s edge policy.** Two
  limiters disagree about who is over budget.
- **Never return a credential.** A caller asks for a CALL. Handing back a key
  reduces this to a secret-fetch service, which is the thing being replaced.
- **Runs off the managed cluster.** A DO token reaching this process defeats the
  entire design; deployment location is a correctness property, not an ops
  preference.
- **A BYOK key is write-only and never returned** — not to its owner, not to an
  operator, not to support. It is spent only for the validated principal it
  belongs to, and its use is recorded because the customer will ask.
- **Refuse rather than serve unauthenticated.** An unidentifiable caller cannot
  spend money.

## What lives elsewhere

- credential custody at rest, per-secret policy, audit trail → KMS
- the provider dialects → `hanzoai/ai`
- inbound identity, JWT validation, header hygiene → `ingress` / `gateway`

Egress owns exactly one thing: the decision to spend, and the record of it.

## Two shapes, one custody

Egress sells two things, and the difference between them is the shape of the
answer, not the shape of the trust.

| | `POST /v1/call` | `POST /v1/fetch` |
|---|---|---|
| spends on | a model | a cloud API |
| answer | a token stream, then a meter | one status and one body |
| typed op | no — a stream has no single output | yes, so it projects into OpenAPI, MCP, the op plane |
| contract lives in | this package (`call.go`) | `hanzoai/egress/spend` |

They share the door, the ceiling, the custody path, the circuit breaker and
`scrub`. That is the point: **custody is orthogonal to shape**, so a second
thing to spend on cost a request struct and a handler, not a second service.

**What a caller may say is the whole design of `Fetch`.** No org and no user —
those come from the token. No host — egress decides that. No headers — a caller
that can write a header can write the one carrying the credential. Egress writes
every header itself.

**ONE table says which clouds egress can pay for AND where each answers.**
`clouds` maps `digitalocean → https://api.digitalocean.com`. Where DigitalOcean
answers is a fact about DigitalOcean, not a choice a deployment makes, so no
operator types it — the same shape as a model dialect carrying its vendor's
endpoint. The rule that matters is that the CALLER cannot name a host, and it
has no field for one either way; an operator naming it added nothing to that and
was one more thing to forget.

Membership is also the allowlist, which is why it is one table and not two to
drift apart. A cloud in `clouds` carries its credential as a bearer token; a
cloud that signs its requests instead — AWS, anything on SigV4 — is absent and
refused. Adding a cloud is one line, written by whoever worked out both halves.

`EGRESS_URLS` / `-url` is an OVERRIDE and is ordinarily empty: it MOVES a cloud
egress already carries (a regional or sovereign endpoint, a test's own server)
and can never admit one it cannot pay for, because an address is not what makes
a cloud payable.

`serving()` in the tests refuses any non-loopback dial. Now that a cloud's real
address is known, a fetch test that forgets to stand up a stand-in would
otherwise reach the vendor for real and hand it a made-up token.

**Two rules keep a path a path, and they are two functions.** `rooted` asks
whether this is a path at all — one leading slash, no backslash. `resolve` asks
whether the resolved request stayed on the configured host. Nothing reaches the
second while the first stands: a reference beginning with a single slash cannot
carry an authority, because an authority appears only after two. It is there for
the day someone loosens `rooted` for convenience, and it is its own function so
`TestReference` can call it directly and prove it works — phrased as a third
check inside `reference` it was unreachable, and deleting it broke no test.

**Redirects are not followed.** `CheckRedirect` returns `ErrUseLastResponse`, so
a 3xx comes back as itself. Following one would let the far end choose the next
far end — the same decision the nil `Proxy` takes away from whoever writes the
environment.

`visor`'s own registry refuses the same providers for the same reason: a
credential that cannot be carried correctly is not sent at all.

**The client is its own module, and a measurement is why.** `hanzoai/egress/spend`
carries `Fetch`, `Fetched` and `spend.Client`, with `fasthttp` and
`zap-proto/http` as its entire dependency set. Requiring the PARENT for those two
structs moved `visor` from authz 1.10.14 to 1.10.30, which relocated packages
visor imports and broke its build — besides bringing the KMS client and the
dialects into a process whose whole point is that it holds no key. The parent
requires the leaf and `replace`s it with `./spend`, which is how one repo builds
two modules against its own tree. Tag the leaf as `spend/vX.Y.Z`.

`spend.Client` returns an `*http.Client`, so adopting egress is a transport swap
and not an SDK rewrite — `godo.NewClient(c)`, `hcloud.WithHTTPClient(c)`. The
SDK's base URL is discarded; only method, path and body travel.

## What the laws meant once the code met them

**The provider surface imports cleanly.** `github.com/hanzoai/ai/model` is it:
`GetModelProvider(...)` builds a dialect from a type and a credential, and
`ModelProvider.QueryText(question, writer, history, prompt, knowledge, agent,
lang)` makes the upstream call and streams into an `io.Writer`. No web framework,
no database. The writer must also have `Flush()`; every dialect checks for it
before anything else.

**Where a call goes, and how it proves it may, import cleanly too.**
`github.com/hanzoai/ai/upstream` is a leaf on `object` and the standard library:
`Endpoint(provider, path)` answers the address and `Authorize(req, provider)`
applies the credential and returns nothing. Both lived inside `controllers`,
which nothing outside can import, and the extraction was made for this door.
Import them; do not restate an address or an auth scheme here. The rule that
keeps the credential in one place now parses `controllers` AND `upstream`, so a
copy made here would not be caught by it — the first law is the only thing
guarding this side.

That covers the text path, the address and the credential. It does NOT cover
tool calls or vision. In `ai` those go down a second road,
`controllers.proxyAnthropicToolRequest`, and the earlier note here named three
functions that do not exist — `resolveEndpointForPath`,
`resolveUpstreamEndpoint`, `proxyToolRequest`. The real shape is one method on a
web controller that writes to `c.Ctx.ResponseWriter`, holds a budget and bills,
so most of it is controller work and should stay there.

What is genuinely reusable is the translation beneath it:
`controllers/anthropic_translate.go` is 802 lines and 21 functions, and the
whole file is pure — no controller, no http, no object, no iam. It needs exactly
two things from its package: `AnthropicContentBlock` and a four-line `text`
helper. Extracting it means moving the Anthropic wire types with it, and those
carry 21 references across 6 files for `AnthropicRequest` alone, on the live
`/v1/messages` path. That is the next move and it is a typed migration, not a
file move. Copying the translation here instead is the one thing the first law
forbids.

**The gateway's limiter does not exist.** `apps/gateway/edge` measures traffic —
`Observe` returns counts — and never admits or refuses; the thresholds live in
its callers. Nothing in the estate exports an `Allow(key)`. So the ceiling here
is written, small, and keyed on the verified principal. The circuit breaker IS
imported: `zip/middleware.NewBreaker(...).Allow()/.Report()` is a real reusable
pair. Importing `hanzoai/cloud` to reach `edge` would have cost 692 modules and
a hand-ported replace block for a package containing neither thing.

**Resolution is KMS-first with no second leg.** `ai` falls back to configuration
when the store is silent, because its keys are still migrating out of env vars.
Egress must not: this process's environment is exactly where a provider key used
to live, so a fallback would restore the exposure. Absent credential, unreachable
store, both end the call.

**The gate goes ahead of every route, never wrapped around each one.** A typed op
is not reachable only at its declared path — zip also projects it onto an op-call
plane, an MCP tool and an OpenAPI document, and installs those routes itself at
serve time. Per-route middleware covers the declared path alone. Measured, not
assumed: a ZAP `zip.Call` to `egress_health` carrying no token was answered
`{ready:true}` while every route was gated. `app.Use(...)` registered before any
route covers the projections too. Each handler re-checks the principal anyway —
that backstop is what refused an `enroll` arriving over `/mcp` while the
perimeter had the hole.

**A bearer cannot ride `zip.Call`.** It forwards the gateway's `X-*` identity
assertions and nothing else, and those are precisely what a service outside the
cluster must not believe. Callers reach egress at its ROUTE over the ZAP
transport, which carries a whole request, headers included.

**The custody path is `{user}` = the subject, not the username.** A username can
be given up and taken by somebody else, and a path keyed on one hands the new
holder the previous holder's credentials.

**A person and a program are filed in different namespaces, and the class comes
from the issuer.** `orgs/{org}/users/{subject}/…` and `orgs/{org}/apps/{client}/…`.
Both names are attacker-chosen — anyone may register an account, and whoever
registers an application picks its client id — so any scheme that flattens the
two classes into one segment has to keep two chosen values from meeting. The
obvious flattening, a program's `admin/hanzo-egress` with the slash rewritten to
the `-` the segment rule already allows, puts them one registration apart: an
account named `admin-hanzo-egress` lands on the path holding that program's
provider keys. So they are not flattened; each class gets its own namespace,
spelled by a constant no claim reaches.

Which class a token belongs to is IAM's `type` claim, which it resolves from the
grant it answered. It is not inferred, because the inference within reach —
a subject shaped `owner/name` — is what a person's subject ALSO looks like
whenever the token names the account rather than its id, and filing those people
under `apps/` is the collision arriving by the front door.

**The tenant is the `owner` claim and never the subject's first half.** A
program's subject reads `admin/hanzo-egress`, where `admin` is the org the
APPLICATION ROW is filed under — the reserved one that means platform sudo —
while the tenant it acts for is `hanzo`. Splitting the subject for a tenant roots
every program's credentials in that one org.

**Nothing on the wire may name a tenant or an upstream.** The first comes from
the token, the second from this host's `-url` configuration. A test pins the
shape of `Call` and `Enroll` against ever growing such a field, because both are
the kind that gets added later for a good local reason.

**The outbound client belongs to this process.** The dialects reach for one
client `hanzoai/ai` keeps as a package variable, and it holds nothing until
something fills it, so `New` fills it. Two consequences worth keeping: it
verifies certificates and there is no setting that says otherwise, and its
timeout is the call deadline, which is the only thing that actually stops a
dialect — they take no context, so an abandoned call is otherwise still running.
It also carries a transport of its own with `Proxy` nil. Go's default reads
`HTTP_PROXY` and friends, which would let whoever writes the environment choose
the far end of a connection carrying a key — the same choice the certificate
check exists to take away. Do not reach for `proxy.InitHttpClient` either: it
reads a SOCKS setting and, when it finds one, builds a transport that verifies
nothing.

**A dialect runs on a goroutine, so it is caught on one.** A vendor client that
falls over is one refused call. Uncaught it is the whole replica, and every
replica serves every tenant. The error that replaces the fall goes through the
same scrub as any other, because a panic carries whatever the client was
holding, which here is a request with the key in its header.

**Nothing keeps a credential.** There is no window and no map — every call reads
what it spends and it lives on that call's stack. A value here cannot be zeroed
(KMS hands back a `string`, and so does the dialect surface), so the only
property worth having is that no copy outlives the call that made it. Rotation
follows: a key rewritten in KMS is spent on the next call.

**The KMS leg is signed, and wants to be sealed.** `luxfi/keys` v1.4.2 is
required directly here rather than through the SDK, because before it a service
identity surrendered its signing key to the collector after its first signature
— quietly, since the second signature is produced without error and simply does
not verify. `kms_test.go` guards it; that guard is the only thing standing
between a dependency bump and finding it in production.

The seal is `hanzoai/kms/sdk/go` v1.1.4. It agrees an X25519 + ML-KEM-768
session or fails the dial, and every request names that session: the handshake
derives a binding alongside the session key, computable only by the two
endpoints that ran it, and the store honours a request only on the channel it
names. So a party that agrees keys with both sides — which is what an on-path
adversary does — can read nothing and pass nothing on. There is no field to set
and no session-less client to construct; `envelope.Build` will not sign a
request that is addressed to nobody.

What this does not give is the other direction. Egress has no name for the real
store, so something answering in its place is not yet distinguishable — the
credential cannot be taken, but a substitute can be offered. See §9 of
`docs/architecture.md`.

## The module must resolve on GitHub

`github.com/hanzoai/egress` is mirrored public on GitHub, and that is load-bearing
rather than decorative: it is how every consumer's CI fetches `spend`.

A build container has no `insteadOf` rewrite. A developer machine usually does —
`url.https://git.hanzo.ai/hanzoai/.insteadOf https://github.com/hanzoai/` — so a
missing mirror builds fine locally and fails in CI with
`fatal: repository 'https://github.com/hanzoai/egress/' not found`. That is
exactly how visor's image build went red on every commit for an afternoon while
`go build ./...` passed on the machine that wrote it.

So: **every push to the forge must also reach GitHub, tags included.** `spend` is
resolved by its own tag (`spend/vX.Y.Z`), so pushing `main` without `--tags`
leaves consumers unable to resolve a version that exists. `origin` in this
checkout has both push URLs; a checkout that does not is one push away from
breaking every consumer.

Verify a version really resolves the way CI will — clean HOME, no rewrite:

    HOME=$(mktemp -d) GOPATH=$(mktemp -d) go get github.com/hanzoai/egress/spend@vX.Y.Z

The nine hanzoai modules visor already imports are all public on GitHub for the
same reason. `hanzoai/kms` is the exception, and it is why egress's own release
job cannot fetch its SDK — see the release note below.

## One gateway, and it is not this one

`hanzoai/ai` is the ONLY AI gateway. It calls egress; egress holds the
credential in KMS, sealed to a host identity. Nothing else reaches a model
vendor — not a second gateway, not a service with a vendor key in its
environment, not a hardcoded endpoint in a client.

The rule is not tidiness. A call that goes straight to a vendor is a call egress
never saw, and a call egress never saw is a call nobody metered — so "one
gateway" and "billing is correct" are the same sentence. Every extra road is
both an unmetered spend and a key sitting somewhere a person can read.

Measured against the fleet, the gap is credential material rather than code:

- **Nothing reads `FIREWORKS_API_KEY`.** Zero occurrences in `cloud`'s Go source
  (its only Fireworks reference is a catalog row keyed on `FIREWORKS_API_BASE`),
  and zero commits ever touched it in `bot`. The key nevertheless sits in three
  Secrets and two pod environments. A credential with no reader is pure
  exposure, and the only action that ends it is revoking at the vendor.
- **Nine Secrets across three namespaces** carry OpenAI, Anthropic, Fireworks and
  OpenRouter keys directly.
- **Two DigitalOcean credentials** exist for one capability, under two names in
  two stores, so a rotation reaches one and a meter reaches neither.

Deleting a Secret does not remove a key. Several are written by the KMS operator
— `managed-by: lux-kms-operator` or `manual-kms-sync`, with a
`kmssecret.secrets.lux.network/source` label naming where they come from — and
those are rewritten from KMS on their resync interval. The source is KMS; the
Secret is a copy. Remove the key there, then the copy, then revoke at the vendor.

A caution worth keeping about that check: `kubectl get kmssecrets -A` answering
with nothing is not evidence a Secret is unmanaged. Confirm the query can see a
KMSSecret you already know exists before believing an empty answer.

## Verifying

`GOWORK=off go test -race ./...`. The suite runs against a fake `Secrets` and a
real in-memory issuer; the streaming path runs end to end through `ai`'s own
Dummy dialect, and one test binds the real ZAP listener. No network, no KMS.
