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

## What the laws meant once the code met them

**The provider surface imports cleanly.** `github.com/hanzoai/ai/model` is it:
`GetModelProvider(...)` builds a dialect from a type and a credential, and
`ModelProvider.QueryText(question, writer, history, prompt, knowledge, agent,
lang)` makes the upstream call and streams into an `io.Writer`. No web framework,
no database. The writer must also have `Flush()`; every dialect checks for it
before anything else.

That covers the text path. It does NOT cover tool calls or vision: in `ai` those
go down a second road, `controllers.proxyToolRequest`, which is a method on a
web controller that writes to `c.Ctx.ResponseWriter` and returns nothing. It
cannot be imported. Serving them through egress needs an extraction in `ai`
first — `resolveEndpointForPath`, `resolveUpstreamEndpoint`, `proxyToolRequest`
and `streamCaptureUsage` moved into a leaf package taking an
`http.ResponseWriter` and a `context.Context`. Copying them here instead is the
one thing the first law forbids.

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

**The custody path is `{user}` = the user id, not the username.** A username can
be given up and taken by somebody else, and a path keyed on one hands the new
holder the previous holder's credentials.

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

## Verifying

`GOWORK=off go test -race ./...`. The suite runs against a fake `Secrets` and a
real in-memory issuer; the streaming path runs end to end through `ai`'s own
Dummy dialect, and one test binds the real ZAP listener. No network, no KMS.
