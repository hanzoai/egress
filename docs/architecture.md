# Egress — architecture and threat model

`ingress` decides who may come in. **Egress decides who may spend.**

An upstream credential is money. Held in a calling process's environment it is
readable by anything that can reach that process, it spends off our network
without limit once taken, and rotating it is a fleet-wide restart. Egress holds
it instead: a caller asks for a **call**, not for a key.

```
caller ──asks for a call──▶ egress ──resolves the credential──▶ provider
       ◀─── frames, then ──         (custody in KMS)
            the meter
```

This is the design and the threat model. §9 lists what is still open.

---

## 1. Invariants

If a change breaks one of these it is wrong, regardless of what it improves.

1. **No application process holds a provider credential.** Callers ask for a
   call.
2. **Egress never returns a credential.** No read route, no decrypt, no debug
   endpoint that reflects state. Handing one back reduces this to a secret-fetch
   service, which is the thing being replaced.
3. **The credential lives in the store and, briefly, in one call's memory.** No
   third copy — no file, no environment variable, no log line.
4. **Egress owns its own store.** The credential lives in egress's embedded,
   sealed store — never in an external secrets plane, and never in a store served
   by the process tree the credential is leaving. §8.
5. **Nothing on the wire names a tenant or an upstream.** The tenant comes from
   the verified token; the upstream from this host's configuration. A caller that
   could name either could spend another tenant's key, or have the credential
   delivered to an address it chose.
6. **Refuse rather than serve unidentified.** An unidentifiable caller has no
   tenant to spend from and nobody to bill.
7. **Resolution is store-first with no second leg.** No fallback to
   configuration or environment. This process's environment is exactly where a
   provider key used to live; a fallback restores the exposure.
8. **Rotation is one write.** A value rewritten in the store is spent on the
   next call — no redeploy, no restart.

---

## 2. What this is, in standard terms

**Secretless Broker** (CyberArk's OSS pattern; the shape of `cloud-sql-proxy`
and `rds-proxy` in IAM mode). The application connects holding no credential; a
broker authenticates it by platform identity, attaches the real credential, and
completes the call. *Deviation:* a shared service rather than a per-pod sidecar —
a sidecar puts one copy of the credential beside every caller, which is the
opposite of the goal.

**Workload/principal-identity secret release** (SPIFFE/SPIRE's model). The
requester authenticates with an identity the infrastructure attests to, not with
a secret it was handed, and the store releases only against a named identity.
*Ours:* IAM-issued JWTs verified against the issuer's published keys. Egress
checks a signature; it never mints or holds an identity of its own.

**Broker call, not forward proxy.** The caller sends a typed call — provider,
model, question — and egress selects the dialect and the credential. *Deviation
from the classic pattern, and deliberate:* a forward proxy that passes a
caller-supplied path through to a vendor root is an open credentialed relay to
that vendor. A vendor's API is wider than the part we use — the same root
typically answers account, usage and **key-management** endpoints — so path
passthrough would authenticate those with our credential. Naming an operation
instead makes the reachable set finite and reviewable.

**Sealed store, owned by the process that spends from it.** The credential is
ciphertext at rest under a key not stored beside it. *Ours:* `kms.Embed()` from
`hanzoai/kms`, running **in-process inside egress** over its own encrypted ZapDB.
Deviation from the usual split, and deliberate: custody and the decision to spend
live in one service rather than two. A separate secrets plane would add a second
deploy, a second identity to get right, and a network read on the money path —
and, if that plane were ever served by a caller's own process tree, would hand the
credential straight back to the thing it was taken from. One service, one
boundary.

**Composed, not rewritten.** The provider dialects are imported from
`hanzoai/ai` — `model.GetModelProvider` builds a dialect from a type and a
credential, `ModelProvider.QueryText` makes the call and streams into an
`io.Writer`. A second implementation would drift silently: a changed streaming
shape or a moved usage field works in one copy and not the other, and a customer
finds out before we do. The circuit breaker is imported from `zip/middleware`.
The per-principal rate limiter is written here, small, because nothing in the
estate exports an `Allow(key)` — see §9.

**Not imported:** Vault, Conjur, cloud secret managers, Envoy, nginx, a service
mesh. KMS is ours and adding a second secrets plane would give two answers to one
question.

---

## 3. The contract

### Transport

ZAP, listening on `:9653` by default. Callers reach egress **at its route** over
the ZAP transport, which carries a whole request including headers.

Not `zip.Call`: the op-call plane forwards the gateway's `X-*` identity
assertions and nothing else, and those are precisely what a service outside the
cluster must not believe. A bearer cannot ride it.

Outbound to the store is ZAP too, and it carries credentials across whatever
sits between this host and the store. Every request on it is a signed envelope,
which settles who is asking and stops a replay, but a signature is not a
curtain. The bodies are sealed under an X25519 + ML-KEM-768 session by
`hanzoai/kms/sdk/go` v1.1.2, whose dial refuses a peer that will not agree one
and refuses a session that ran X25519 alone — hybrid because a break in the
curve and a machine that breaks it are two different futures, and a key read
today is a key stored today.

Refusing is the point. A handshake that fails and carries on is not a weaker
channel, it is no channel: dropping one message is the whole downgrade, and an
adversary who can do that gets every secret afterwards in both directions. So
there is no setting for it, because a setting is a thing an adversary gets to
influence.

v1.1.2 is published on the forge and verified composing with this build. It is
not required here yet: the module path resolves through `github.com/hanzoai/kms`,
which today redirects to an archived repository that cannot take a new tag. When
that repository exists again, `go get github.com/hanzoai/kms/sdk/go@v1.1.2` is
the whole of the change, and rows 15 and 16 read alike.

### Routes

| Route | Shape | Purpose |
|---|---|---|
| `POST /v1/call` | streaming, not a typed op | make one upstream call |
| `POST /v1/enroll` | typed op | seal a customer's own key; write-only |
| `GET /v1/health` | typed op | is this replica serving |

`/v1/call` is deliberately not a typed op: a typed op is one input to one output,
and a token stream has no single output to describe.

### The call

```json
{ "provider": "OpenRouter", "label": "default", "model": "...",
  "question": "...", "prompt": "...", "history": [{"author":"...","text":"..."}],
  "temperature": 0.7, "thinking": false }
```

Note what is **absent**: no org, no user, no upstream URL. The first two come
from the verified token; the third from this host's `-url` configuration. A test
pins the shape of `Call` and `Enroll` against ever growing such a field, because
both are the kind that gets added later for a good local reason.

`provider` is spelled as `hanzoai/ai` spells it — `OpenAI`, `OpenRouter`,
`Claude`, `Fireworks`, `DigitalOcean`. It selects both the wire dialect and the
credential, so a key enrolled for one vendor cannot be spent against another.

### The response

Server-sent events: the provider's own frames as they arrive, then one final
frame of egress's own — the **meter**, the record of what was spent.

```
event: meter
data: {"provider":"OpenRouter","model":"...","scope":"user",
       "prompt":812,"completion":344,"total":1156,
       "price":0.0043,"currency":"USD","millis":2170}
```

`scope` is `user` or `org` — whose credential paid. That is the difference
between a customer's vendor bill and ours, and it belongs in the record.

A refusal arrives as `event: error` on the same stream, because by the time the
call is running the status line has already gone.

### Enrolment

`POST /v1/enroll` with `{provider, label, key}` seals a customer's own
credential at the path their token owns. There is **no route that reads one back
out** — not for the customer who supplied it, not for an operator, not for a
support tool. A credential that can be read back leaks through whichever surface
reads it.

---

## 4. Identity and the tenant boundary

A caller presents an IAM bearer token. Egress verifies it against the issuer's
published keys and requires three things:

- **issuer** — it must name our IAM.
- **audience** — required, with no default. A service that accepts any audience
  accepts a token minted for a different app.
- **expiry** — required. A token with no expiry never stops being spendable.

Every failure returns one refusal carrying no detail. The difference between "no
token", "wrong audience" and "expired" is an oracle for somebody assembling a
token, and none of it helps a caller that legitimately holds one.

The verified token yields the **principal**:

```go
type Principal struct {
    Org  string // the `owner` claim — the tenant
    User string // the `id` claim — the immutable user id
}
```

**The user id, never the username.** A username can be given up and taken by
somebody else, and a custody path keyed on one would hand that somebody the
previous holder's credentials.

### The custody path is the tenant boundary

```
orgs/{org}/users/{user}/connectors/{provider}/{label}   the customer's own key
orgs/{org}/cloud/{provider}/{label}                     the tenant's shared key
```

**Both are built entirely from the validated principal.** This is the whole
boundary: a caller that could name its own path could name another tenant's.

Every segment is checked against an allowlist — letters, digits, and `-`/`_` not
in first position, 64 characters maximum. An allowlist rather than a search for
bad input: a separator or a parent reference cannot be *spelled* with these
characters, so a path assembled from passing segments cannot leave the tenant it
was built for. The claims are signed, so this is not a check on the caller — it
is a check on what may become a path segment, because a credential's location
must not depend on an issuer never emitting a slash.

Provider names are mapped by one function, `Amazon Bedrock` → `amazon-bedrock`,
which **rejects** anything it cannot spell rather than dropping characters — two
provider names differing only by a dropped character would otherwise share one
credential.

### Resolution: the customer's key wins

`resolve` reads the user path, then the org path. A tenant that brought a key
expects it to be the one spent. An absent secret is the ordinary state of a
tenant with no key of its own and falls through; a store that **cannot answer**
is an error that ends the call — an unreachable store must not become a reason to
look somewhere less guarded.

A resolved value is held for the call that read it and for nothing else. There
is no window and no map, so there is nothing for a core dump, a heap profile or
another tenant's call to reach, and a replica is worth deleting rather than
investigating: it knows nothing that outlives a request. Reading every time is
also what makes rotation a store write rather than a deploy.

It cannot be zeroed. The store hands back a `string`, and so does the dialect
surface it is passed to; Go strings are immutable, so the copies belong to the
collector. The property that is actually available is the one above — no copy
outlives its call — and it is the one the code keeps.

### The gate goes ahead of every route

Registered with `app.Use(...)` before any route, never wrapped around individual
handlers. This is not style, it is the only placement that holds: a typed op is
not reachable only at its declared path — the framework also projects it onto an
op-call plane, an MCP tool and an OpenAPI document, and installs those routes
itself at serve time. Per-route middleware covers the declared path alone.

Measured, not assumed: a ZAP call to the op plane carrying no token reached a
per-route-gated op and was answered. Registered ahead of every route, the gate
covers the projections too, because they are routes like any other and they are
added after it.

**Each handler re-checks the principal anyway.** That backstop is what refused an
enrolment arriving over the MCP projection while the perimeter still had the
hole. A handler reached by some other road must refuse on its own account.

---

## 5. What authorization does and does not check

Stated plainly, because "egress decides who may spend" implies more than the code
does.

**Checked.** The token is ours, minted for this audience, unexpired. The
credential resolved is inside the caller's own org — cross-tenant spend is
structurally impossible, not merely forbidden. Calls per principal per minute are
capped. A provider with no dialect is refused. A vendor that starts failing gets
its circuit opened, so an outage stops costing every caller a full deadline.

**Not checked.** Whether this principal is *entitled* to spend the org's shared
credential. Any principal holding an egress-audience token for an org can spend
that org's platform key, bounded only by the rate limit. Credit, plan and
per-user entitlement belong to commerce and are not consulted here.

That is a defensible separation — custody is one job — but it means the audience
is doing more security work than it looks like it is. **The audience is the
membership test for spending the platform key**, so it must be an app whose
tokens are only minted for callers we intend to fund, and it must not be widened
casually. If self-service signup can obtain a token with that audience, the
platform credential is reachable by anyone who signs up.

---

## 6. Deployment

One process on a host we provision, configured by flags with environment
fallback, so a unit file supplies configuration without putting it on a command
line. Inbound ZAP; outbound HTTPS to providers and ZAP to the store. Nothing is
read from an orchestrator.

Stateless: no session, no sticky routing, every value held is either
configuration or a bounded cache. One replica is interchangeable with the next,
which is what makes horizontal scale ordinary and a suspect replica something to
delete rather than investigate.

An incoherent configuration is refused rather than defaulted. Everything that
decides *who may spend* or *where a credential may be sent* — audience, issuer,
JWKS, store address, custody tenant, identity path — is required, and an upstream
URL that is not `https://` is rejected.

**No interactive access.** A host a person can log into is a host whose memory a
person can read, and "a person" includes anyone who takes that person's
credential. That only works if nothing is repaired in place: a host that
misbehaves is destroyed and replaced from the image, which is affordable exactly
because it holds no state worth keeping. Two things make it honest rather than a
slogan — it must boot without a human, and it must be diagnosable from outside,
because being on the box is the thing that was removed.

### On running it off the managed cluster

The argument for it is that a cloud API token reaches every pod, secret and
volume in a managed cluster, so a broker running there holds a decrypted
credential inside the blast radius it exists to escape. The premise is sound, and
disk encryption genuinely defeats snapshot, detached-volume and
password-reset paths.

Two honest limits, both of which must be said next to it:

- **A running host is decrypted.** Full-disk encryption defends a powered-off
  disk, not a live process, and the credential lives in the live process. The
  controls that matter there are no interactive access, a small surface, and
  replacement rather than repair.
- **Relocating the reader while the store stays put buys nothing.** If a
  credential is read from a plane served inside the cluster being escaped — worse,
  by the very process tree it is leaving — then moving the *reader* moves nothing.
  The boundary has to move where the **store** is. Under the embedded model that
  holds by construction: egress carries its store with it, so wherever egress
  runs, the credential is already there and nowhere else (§8).

Also note that a host outside the cluster but inside the same cloud account is
not outside a compromise of that account. Escaping that means a different
provider, which is a real cost and should be a deliberate choice rather than an
assumed property.

---

## 7. Threat model

**Total** (attacker obtains the credential) · **High** · **Bounded** (can spend
through our meter, cannot take the credential) · **Low** · **None**.

| # | Surface | Before | After | Note |
|---|---|---|---|---|
| 1 | Code execution co-located with a caller, reading its environment | **Total** | **Bounded** | The credential is not in any caller's environment. Co-located code holding a valid token can still *call* egress — metered, rate-limited, attributed, and confined to its own tenant. |
| 2 | Compromised sibling process of a caller | **Total** | **Bounded** | As above. |
| 3 | A caller reading the store directly | **Total** | **None** | Structural under the embedded model: the store is in-process inside egress, exposes no read route to anyone, and no application shares that process. There is no external plane to reach and no cross-service grant to get wrong. §8. |
| 3b | Egress's store at rest — volume, snapshot or replica theft | n/a (new) | **Low** | Ciphertext under a key held by the process, not stored beside the data. Defends the disk; does not defend a running process — that is row 8. |
| 4 | Human or CI reading cluster Secrets | **Total** — base64 is not encryption | **None** | No Secret holds a provider credential. |
| 5 | Image or registry theft | **Low** | **None** | Verified in CI rather than asserted: export every layer, grep for credential prefixes and live values, fail the build on a hit. |
| 6 | Node disk or volume snapshot | **High** | **Low** | Nothing durable holds the credential; disk encryption covers the powered-off case. Residual is live-memory capture — row 8. |
| 7 | etcd / managed control plane | **High** — encryption there is the provider's control, not ours to attest | **None** | The credential is never a cluster Secret. |
| 8 | **Compromised egress process** | n/a | **Total, irreducible** | §10. |
| 9 | Cross-tenant spend | **Total** where keys are shared by configuration | **None** | The custody path is built from the verified token and cannot be spelled by a caller. The strongest property in the design. |
| 10 | Stolen caller token | **Total** — a leaked provider key spends off our network, invisibly, until a multi-vendor rotation | **Bounded** | A stolen IAM token is short-lived, audience-bound, and buys only metered calls inside its own tenant. |
| 11 | Credential echoed in an upstream error | **High** — providers quote rejected keys back, whole or in pieces | **None** | An error reaching a caller or a log has every stretch it shares with the credential taken out, in whatever shape the key travelled: whole, masked to a prefix and last four, truncated, base64, escaped. |
| 12 | Compromised store | **Total** | **Total** | Inherent, and under the embedded model this row **is** row 8: store and spender are one process, so compromising either compromises both. That collapse is deliberate — it trades a second attack surface for a second boundary we would have had to prove. Bounded by keeping the process small, its writes admin-scoped, its reads audited, and its loss capped by a vendor-side spend limit. |
| 13 | Vendor-side escalation through the broker | n/a (new) | **None** | No caller supplies a path or a URL. Account, usage and key-management endpoints are unreachable by construction — there is no route that would carry a caller there. |
| 14 | An entitled-looking caller burning spend | **Total** (no limit) | **Bounded** | Rate limit per principal, meter per call, attribution in every log line. Entitlement itself is not checked — §5. |
| 15 | On-path adversary on the leg to the store | **Total** — an enrolled key crosses the network as it is written and again on every read | **None for disclosure** | Bodies are sealed under an X25519 + ML-KEM-768 session, and each request names that session and is honoured only there. Agreeing keys with both sides no longer helps: a request written for one channel cannot be re-signed for another. What remains is that egress cannot yet tell the real store from something that answers in its place — §9. |
| 16 | On-path adversary on the leg to a provider | **Total** if certificates go unverified, or if the route can be chosen | **None** | The outbound client belongs to this process. It verifies certificates with no setting that disables it, and its transport reads no proxy from the environment, so the far end is the upstream in the config and nothing else. An acceptance test points a call at a server presenting an unvouched certificate and asserts nothing was sent. |

Net: the design converts *credential theft* into *bounded, observable,
tenant-scoped spend*. It does not make the credential unreachable to an adversary
who owns the host or the store.

---

## 8. The store egress owns

**Invariant 4.** Provider credentials live in egress's own embedded store —
`kms.Embed()` over an encrypted ZapDB in egress's data directory. There is no
external secrets plane in the call path and none in the deploy path.

This is not convenience. An external plane has to be a *separate workload that
authorizes per identity*, and if it is not — if it is served by a caller's own
process tree, or if its authorization proves only "this is one of ours" without
proving *which* one — then the credential stays reachable from the very place it
was taken from, and every improved row in §7 is fiction. Owning the store removes
that class of failure instead of requiring it to be verified on someone else's
schedule.

It also answers the obvious simplification, "why not skip the broker and let each
application read the store directly?" — because in-process reading *by an
application* is not an authorization boundary. Egress is the one process that may
read, and it exists to spend rather than to serve reads.

**What this costs, stated plainly.** Egress becomes stateful. A replica holds
durable ciphertext rather than only a cached value, so:

- **backup and restore** are ours to own, and losing the store means re-enrolling
  every credential — recoverable, because provider keys rotate, but an
  availability event rather than a non-event;
- **horizontal scale needs one writer.** Reads scale freely; writes must be
  fenced so two replicas cannot diverge. `hanzoai/kms` ships this — a Kubernetes
  Lease writer-fence with a primary/follower split and age-encrypted incremental
  replication. Use it rather than inventing one;
- "delete a suspect replica rather than investigate it" is **no longer free**:
  the replica held the store, so replacement means restore, not reschedule.

**What sealing does and does not buy.** At-rest sealing uses an encryption key
supplied to the process. That defends **disk, snapshot and backup theft** —
someone who walks off with the volume or the replica gets ciphertext. It does
**not** defend against a developer, because anyone who can reach the running
process does not need the disk.

**What actually stops a developer taking the key** is reachability, not
cryptography — five properties, each independently checkable:

1. the credential is **absent from every application's environment** and from any
   Secret an application namespace can read;
2. it exists only in **egress's own namespace**, with its own RBAC and no
   developer grants;
3. the image is **distroless with no shell**, so `exec` into the pod has nothing
   to run;
4. egress runs **no user code** — no code-execution route, no sandboxes, no
   plugins, nothing that evaluates caller input;
5. **no route returns a credential**, so possession cannot be requested, only
   spent.

Those five hold with or without sealing, and they are what the cutover buys. Do
not let sealing gate it.

---

## 9. Known gaps

Stated rather than described around.

**Store-absence is detected by error text.** "No such secret" is distinguished
from "the store could not answer" by matching the word *not found* in the error
string. The two are opposite signals and the consequence of confusing them is
specific: a permission denial phrased as *not found* — a common practice, chosen
precisely to avoid disclosing existence — would make a customer's own key look
absent and silently spend the **platform's** key instead. The customer's bill and
ours would both be wrong, and the meter would say `scope: org` with nobody
noticing. The fix is a typed sentinel on the `Secrets` interface that the store
adapter maps onto, so the seam carries the distinction structurally instead of
in prose.

**Abandoned calls retain the credential.** The dialects take no context, so a
call past its deadline is left running rather than stopped — correctly, and its
output is sealed off so it cannot interleave with the refusal. But the goroutine
survives until the vendor client gives up, holding the dialect and therefore the
credential. Under a vendor hang with sustained traffic that is unbounded
goroutine growth, each one retaining a copy. Bound the number in flight, and push
for context-taking dialects upstream in `ai`, which is the real fix.

**The store is not authenticated to egress.** A request is answered only by the
peer it was addressed to, so nothing can collect a credential in transit. The
converse is open: egress has no name for the real store to check, so something
that answers in its place can hand back a credential of its own choosing rather
than read one. The consequences are bounded — a wrong key spends nowhere, and
the upstream URL is this host's configuration, not the store's — but the store
should be named, and the shape that fits what the estate already has is the
store signing its side of the exchange with the identity the caller already
trusts.

**Health requires a token, and there is no metrics route.** Liveness therefore
needs a credential to check, and diagnosis depends entirely on what is pushed
out. That is a deliberate posture — nothing about diagnosis should require being
on the box — but it must actually be wired, or an unreachable replica is
invisible.

**The rate limiter is local to a replica.** A principal's ceiling is per replica,
so the effective limit is the ceiling times the replica count. Fine while the
limit is a safety net; not fine if it is ever treated as a quota.

**Tool calls and vision are not served.** In `ai` those go through a web
controller that cannot be imported. Serving them needs an extraction there
first — copying them here is the one thing the composition law forbids.

---

## 10. Where "unstealable" is overstated

A credential "unstealable, unviewable, ungettable after it is set" is three
achievable properties and one that is not.

**Achievable.** Unviewable by humans: no read-back route, no environment
variable, no log line, no image layer. Ungettable by callers: no route returns a
credential. Ungettable from storage: not in a cluster Secret, not in etcd, not in
a snapshot.

**Not achievable: unstealable from a running egress process.** Egress must hold
the plaintext to make the call. Anyone who can read that process's memory has the
credential — a shell on the host, a container escape, root, or a
remote-code-execution bug in egress itself. No design that makes outbound calls on
a caller's behalf avoids this: the credential must exist at the moment it is used.
An HSM would move signing into hardware, but provider APIs take a bearer string,
not a signature, so there is nothing to move.

The code says the credential "exists only inside this function". Precisely: it is
also retained by the dialect object it was passed to, and by any abandoned
goroutine still holding one (§9) — both of which end with the call. Nothing
outlives it: there is no window in which a resolved value is resident, so the
memory an adversary must catch is the memory of a request in flight.

What bounds it: no interactive access to the host; replacement rather than repair;
a small surface with no user code, no templating, and no debug route; no held credential
so a replica holds a value briefly; rotation as one store write, so a suspected
compromise is answered in minutes rather than a multi-vendor scramble; scrubbed
errors; and a per-principal ceiling so even successful abuse is metered and
visible.

The honest formulation: **the credential stops being available to every process
sharing an environment, every Secret reader, and every snapshot, and becomes
available only to one small process that exists to spend it.** A large, real
reduction. Not "unstealable".

---

## 11. Acceptance tests

| # | Test | Pass |
|---|---|---|
| 1 | Caller's environment grepped for credential names | no output |
| 2 | Export every image layer, grep credential prefixes and live values | no match; CI fails the build on a hit |
| 3 | No token | refused, no detail |
| 4 | Token minted for a different audience | refused |
| 5 | Expired token, and token with no expiry claim | both refused |
| 6 | Token from a different issuer | refused |
| 7 | Identified caller, ordinary call | frames stream, meter frame terminates |
| 8 | Any route reached over the op-call plane, the MCP projection or the OpenAPI surface, without a token | refused — the gate covers projections |
| 9 | `enroll` then `call` for the same principal | `scope: user` — the customer's key won |
| 10 | Same call for a principal with no key of its own | `scope: org` |
| 11 | Store returns a permission error phrased *not found* | call fails; does **not** silently spend the org key (§9) |
| 12 | Store unreachable | call fails; no fallback to configuration or environment |
| 13 | A `Call` or `Enroll` carrying an org, user or upstream URL field | field is absent from the type; the shape test fails on any addition |
| 14 | Principal from org A attempts to reach org B's credential | structurally impossible — no input reaches the path |
| 15 | Claim containing a separator or a parent reference | rejected by the segment allowlist |
| 16 | Any route that returns a credential | none exists |
| 17 | Logs and error frames grepped for the live credential | no match |
| 18 | Upstream error quoting the credential, whole or in pieces | every stretch it shares with the key is taken out before it reaches caller or log |
| 19 | Rotation: new value written to the store, nothing else changed | spent on the next call; no restart; no failed call |
| 20 | Post-rotation, replay the old credential against the vendor | rejected — confirms the old value is dead |
| 21 | Rate limit exceeded for one principal | refused; upstream not called |
| 22 | Vendor failing repeatedly | circuit opens; calls refused fast rather than each costing a deadline |
| 23 | Caller hangs up mid-stream | upstream call stops; no goroutine left writing |
| 24 | Call exceeding the deadline | refusal frame arrives; abandoned dialect output does not interleave |
| 25 | Store read as an application identity | denied |
| 26 | Store read as a human operator | denied |
| 27 | Store read as egress's identity | allowed |

Tests run against a fake store and a real in-memory issuer; the streaming path
runs end to end through `ai`'s own Dummy dialect, and one test binds the real ZAP
listener. No network, no store.

---

## 12. Cutover

Strict order. Reversing the last two steps takes every SKU that provider serves
to 401.

1. **Reconcile to one implementation** — the byte-forwarding proxy, not the typed
   call shape. Only the former carries tool calls, vision and arbitrary JSON, and
   only it can be adopted by a caller flipping one base URL. Delete the other
   before anything deploys: two implementations of a credential boundary is the
   condition where a fix lands in one and not the other.
2. **Egress deployed with its embedded store seeded**, one provider. The
   credential is written once, by a human, from their own machine, through
   egress's own admin write path — never through a transcript, an image or a
   manifest. Confirm the image actually published before assuming a green build
   shipped anything. Serving proven on synthetic traffic.
3. **First consumer repointed** by base URL only — values, no code — and observed
   carrying real traffic. This is the proof step and it reverts instantly.
4. **Remaining consumers repointed**, including any balance probe and any status
   surface. The old injection stays in place throughout. Enumerate consumers
   first: a missed one does not fail here, it fails at step 5, after the
   credential is gone.
5. **Only then** remove the credential from the injection, and only then apply any
   prohibition on reaching the vendor directly. Both belong at this step and
   neither belongs earlier — the prohibition blocks the old direct path, so
   applying it before the repoint is an outage.
6. **Rotate the value** at the provider and write it once into egress's store.
   This makes any prior exposure of the old value moot, and comes last because it
   is only safe once the value lives in one place. Set the vendor-side **spend cap
   and expiry** in the same visit — that cap is the only control that survives a
   compromised egress.
7. **Repeat 2–6 per remaining provider.** One at a time, each independently
   reversible.

Rollback before step 5 is a configuration change; after, it is restoring the
injection — a redeploy. That asymmetry is why steps 3 and 4 are not optional.

Note what is *absent* under the embedded-store model: no external secrets plane to
stand up, no cross-service grant to scope, no second identity to prove. That
removal is the point.

**OAuth application credentials do not belong here.** A provider key is a bearer
credential presented on every call — what a broker can hold on a caller's behalf.
OAuth application credentials participate in a redirect-based authorization-code
flow: the client id is public by design, appearing in the browser's authorization
URL, and the secret is used once at token exchange, in a flow whose other half is
a user-agent redirect egress is not in the path of. Brokering them would mean
reimplementing an OAuth client — an identity concern, not an outbound-spend one.
