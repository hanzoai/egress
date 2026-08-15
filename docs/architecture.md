# Egress — architecture and threat model

Canonical. Three tracks build to this: the egress service, the cloud-side
consumer cutover, and the KMS grant. Where an implementation and this document
disagree, one of them is wrong and it gets settled here rather than in two
codebases.

Scope: outbound provider credentials. Not inbound auth (`ingress`/IAM), not the
provider dialects (`hanzoai/ai`), not metering.

Status: the service is built and matches this design. **Three preconditions are
open and one of them can void the whole thing — §9.** Read that before the
cutover, not after.

---

## 1. The problem, as measured

In namespace `hanzo` on `do-sfo3-hanzo-k8s`, deployment `cloud` runs one binary
that forks roughly two dozen sibling processes. They inherit `os.Environ`. That
environment carries about 120 secrets, including:

| Secret | Source | What it is |
|---|---|---|
| `OPENROUTER_API_KEY` + 5 more | `cloud-api-llm-keys` | provider credentials |
| `GITLAB_CLIENT_ID` / `_SECRET` | `gitlab-oauth` | OAuth application credentials |
| `DO_API_TOKEN` | `shared-credentials` | the DigitalOcean account |
| `CLOUD_KMS_MASTER_KEY_REF` | `cloud-kms-master-key` | the KMS envelope key |
| `KMS_CLIENT_ID` / `KMS_CLIENT_SECRET` | `cloud-api-secrets` | cloud's identity at the secrets plane |
| `S3_ADMIN_*`, `CLOUD_SQL_ADMIN_DSN`, treasury signers, every per-brand IAM client secret | various | — |

`/exec` and `/sandboxes` are among those sibling processes. Code that reads this
environment reads all of it.

Three consequences:

- **Reach.** A provider key is readable from code-execution-adjacent surfaces and
  from any human or job with `kubectl get secret -n hanzo`. (The `cloud`
  ServiceAccount itself cannot — `kubectl auth can-i get secrets` returns `no`. The
  Kubernetes read path is a human and CI surface, not an application one.)
- **Rotation.** Regenerating the key at the provider revokes the old one
  immediately. Because the value is copied into a Secret and into every replica's
  environment, rotation is a fleet-wide restart with a window where every
  OpenRouter-backed SKU returns 401.
- **The reframe.** `kms.hanzo.ai` routes to `hanzo/cloud:8000`, and the secrets
  plane is `apps/kms` *inside the cloud binary*. Sealing a provider key "into KMS"
  without moving that plane relocates it inside the process tree it is being
  removed from. §9.

---

## 2. Invariants

If a change breaks one of these, it is wrong regardless of what it improves.

1. **No application process holds a provider credential.** Not in an environment
   variable, a file, a Secret, or memory. Callers ask for a call.
2. **Egress never returns a credential.** No get-key operation, no decrypt, no
   debug endpoint that reflects state.
3. **The credential exists in exactly two places:** the KMS store, and the heap of
   a running egress replica. No third copy, including logs and dumps.
4. **The store is not reachable from the process tree the credential is being
   removed from.** Otherwise invariant 1 is theatre.
5. **Identity is attested, not shared.** No `EGRESS_TOKEN`, no bearer value a
   human could paste. A caller proves what workload it is with a credential the
   platform mints and rotates for it.
6. **The caller names a provider, never a destination.** No request field reaches
   the address. Every reachable call is written out in a table.
7. **Refuse rather than serve unidentified.** An unauthenticated caller cannot
   spend; an unresolved credential fails readiness rather than the customer's
   request.
8. **Rotation is one write.** A new value in KMS is in use within the refresh
   interval — no redeploy, no restart, no manifest change.

---

## 3. What this is, in standard terms

A composition of four established patterns. Deviations are called out.

**Secretless Broker** (CyberArk's OSS pattern; same shape as `cloud-sql-proxy`
and `rds-proxy` in IAM mode). The application connects with no credential; a
broker authenticates it by platform identity, injects the real credential, and
completes the call. *Ours:* egress is the broker. Deviation: a shared cluster
service rather than a per-pod sidecar — a sidecar would put one copy of the
credential in every caller pod, which is the opposite of the goal.

**Workload-identity secret release** (SPIFFE/SPIRE's model). A workload
authenticates with an identity the infrastructure attests to, not a secret it was
given, and the store releases only to a named identity. *Ours:* projected
ServiceAccount tokens verified by TokenReview — the same model using the
platform's own attestor rather than a second one. §5.

**Forward-proxy credential injection.** Terminate the caller's request, rewrite
onto an allowlisted upstream, attach the credential at the rewrite, stream back.
*Ours:* Go `httputil.ReverseProxy`, `FlushInterval: -1`. No deviation. This is
the boring path and it is correct.

**Envelope encryption at rest.** *Ours:* KMS's envelope. Deviation to fix: the
envelope key is currently in the environment of the process being defended
against (§9).

**Not imported:** Vault, Conjur, AWS Secrets Manager, Envoy, nginx, a service
mesh. KMS and ingress exist and are ours; a second secrets plane or proxy runtime
would give two answers to one question. Egress is a small Go service in the shape
of `hanzoai/ingress`, with no external module dependencies.

**What egress is made of.** The provider surface — dialects, request shaping,
streaming, credential resolution — is extracted from `hanzoai/ai` into a shared
package and imported. It is already KMS-first with 16 call sites, and a second
implementation of the dialects would drift silently: a changed streaming shape or
a moved usage field works in one copy and not the other, and a customer finds out
before we do. Egress adds custody and authorization around that package and
nothing else.

---

## 4. The load-bearing decision: proxy, not dispenser

**Egress is a forward proxy that makes the outbound call itself.** Settled, not
offered.

A dispenser — authenticate, hand back the key, let the caller call the vendor —
fails on its own terms. The moment the caller receives the key, the caller's
process holds a provider credential, which is the condition being removed. It
would relocate the exposure from a Secret into a heap `/exec` shares, and make
every caller a rotation participant again. A dispenser is the current
architecture with extra steps.

The cost is real: egress is in the hot path of every inference call, adds a hop,
and is a new failure domain for revenue traffic. Bought back with statelessness
(any replica serves any request), a shared connection pool amortising TLS to the
vendor, `FlushInterval: -1` so a streamed token is not held back, and an unbounded
body deadline because a model may think for a minute before its first token. The
header phase is bounded; the body deliberately is not.

---

## 5. Identity

### Caller → egress: projected ServiceAccount token, verified by TokenReview

The caller mounts a token; nothing is stored:

```yaml
volumes:
  - name: egress-identity
    projected:
      sources:
        - serviceAccountToken: {path: token, audience: egress, expirationSeconds: 3600}
```

The kubelet mints it, rotates it before expiry, writes it to `tmpfs`. Never in a
Secret, never in an environment variable, and valid nowhere but egress.

Egress does not verify the signature itself — it POSTs a `TokenReview` to the API
server and reads back `status.authenticated`, `status.user.username`
(`system:serviceaccount:<ns>:<name>`), and `status.audiences`. Delegating to the
cluster keeps revocation instant and leaves no signature checking here to get
wrong.

**The audience echo-back is the anti-replay control and it is not optional.** A
token minted for another service authenticates fine; what distinguishes it is
that the cluster returns *our* audience only when the token was minted for us. The
implementation checks `status.audiences` contains `egress` and refuses otherwise.
Without that check, any workload's token would spend here.

Egress holds `system:auth-delegator` — create TokenReview and
SubjectAccessReview, nothing else. No read of Secrets, Pods or any other object.
It is the grant every extension API server holds. Positive verdicts cache for 60s
keyed by a hash of the token, swept when the map exceeds 1024 entries, so API
server load is bounded by caller count rather than request rate. Refusals are not
cached — a workload just granted access must not stay refused.

### Why not SPIRE

SPIRE would add attestation on selectors finer than the pod (`unix:uid`,
`unix:path`), which is the one thing this does not do. It costs a SPIRE server,
an agent DaemonSet on every node of every cluster, a trust domain, a
registration-entry lifecycle, and an SVID-consuming library in egress *and every
caller*. Nothing in the cluster speaks it today (`kubectl get pods -A` finds no
SPIRE, no SPIFFE). And the gap it closes is closed better by splitting the pod —
see below. Revisit for cross-cluster workload identity or universal mTLS.

### Why not IAM client credentials for the caller

Issue a caller an IAM `client_id`/`client_secret` and that secret lives in the
caller's environment — the environment `/exec` reads. Stolen from there, it
spends. It is a long-lived bearer value with no attestation: the pattern being
deleted, moved one hop.

The distinction that resolves the standing "IAM owns auth" rule: **IAM answers
*which principal*; the ServiceAccount token answers *which workload*.** Only the
second can gate spending, because every IAM path available to `cloud` is equally
available to `/exec` inside `cloud`. A kubelet-minted, audience-bound,
auto-rotated token is not a competing auth system any more than a TLS client
certificate is — it is the platform attesting to its own workloads, and it is
what SPIFFE itself bootstraps from on Kubernetes. IAM claims a caller forwards are
recorded as attribution and are never the basis for the spend decision.

### Honest limit on granularity

Egress **cannot** distinguish `/ai` from `/exec` while they are siblings in the
`cloud` pod. They share a ServiceAccount and share the projected token file. Any
claim of per-process authorization is false.

**And a better token does not fix this.** A projected token is a file on `tmpfs`
readable by every process in the pod. A compromised `/exec` reads the same file
`/ai` reads and presents the same identity. Short-lived, audience-bound and
auto-rotated are real properties worth having — process granularity is not among
them.

> A compromised `/exec` in the `cloud` pod can still **call** egress as if it
> were `/ai`. It cannot **steal** the key. Same-pod impersonation closes only by
> splitting the pod.

The fix is a manifest change, not a bigger identity system: run `/exec` and
`/sandboxes` in their own pod with their own ServiceAccount, absent from the
grant table. Strictly stronger than SPIRE selectors — those workloads would not
merely fail authorization, they would hold no `egress`-audience token at all.
Recommended follow-on; not a blocker.

What the proxy buys in full, even with this limit: `/exec` can call egress but
cannot obtain a key, cannot exfiltrate a credential, cannot use one after losing
access, cannot spend off our network, and cannot force a five-vendor rotation.
The residual is bounded spend through our own meter — a different and much
smaller problem than theft of a bearer credential.

### Egress → KMS: the open gap

Egress currently authenticates to KMS with `EGRESS_KMS_ID`/`EGRESS_KMS_SECRET`
from the `egress-kms` Secret. That is a long-lived client credential in a
Kubernetes Secret — the storage class the provider keys are being removed from —
and it is now **the single most valuable secret in the system**, because it
unlocks all six provider credentials.

This is a genuine reduction (one secret in a locked-down namespace with no shell,
versus eight in a 26-process pod), but it is not what the mandate asked for, and
it should not be described as if the chain has no standing secret in it.

The fix is small and the client side already exists: `Cluster()` builds a client
presenting the pod's own projected identity. KMS must accept that token, verify it
by TokenReview, and map `system:serviceaccount:hanzo-egress:egress` to a grant.
Then `EGRESS_KMS_ID`/`EGRESS_KMS_SECRET` and the `egress-kms` Secret are deleted
and no standing credential exists anywhere in the chain. §12.

---

## 6. The contract

### Call shape

Internal HTTP to the cluster service: `http://egress.hanzo-egress.svc.cluster.local`.
ClusterIP only — no Ingress, no IngressRoute, no LoadBalancer. Publishing it
would put a credential-spending door on the internet.

Not ZAP-over-UDS: UDS requires egress and the caller to share a pod, meaning one
egress per caller pod and one credential copy per caller. The network hop is
protected by policy (§8), not by being a socket.

The caller names a **provider**; egress looks up the address in its own table.
The request is the provider's request shape minus any credential:

```
POST /openrouter/v1/chat/completions
Authorization: Bearer <projected SA token, audience=egress>
Content-Type: application/json

{"model":"anthropic/claude-3.5-sonnet","messages":[...],"stream":true}
```

### The allowlist, three times over

An unlisted vendor is unreachable, an unlisted call is unreachable, and the
address is never taken from the request.

| Provider | Secret (org-qualified) | Auth scheme | Allowed calls |
|---|---|---|---|
| `openrouter` | `ai/OPENROUTER_API_KEY` | `Authorization: Bearer` | `GET /v1/models`, `POST /v1/chat/completions`, `POST /v1/completions`, `POST /v1/embeddings`, `GET /v1/credits`, `GET /v1/key`, `GET /v1/generation`, `GET /v1/activity` |
| `openai` | `ai/OPENAI_API_KEY` | `Authorization: Bearer` | chat, embeddings |
| `anthropic` | `ai/ANTHROPIC_API_KEY` | `x-api-key` + `anthropic-version: 2023-06-01` | `POST /v1/messages` |
| `fireworks` | `ai/FIREWORKS_API_KEY` | `Authorization: Bearer` | chat |
| `doai` | `ai/DO_AI_API_KEY` | `Authorization: Bearer` | chat |
| `spark` | `ai/SPARK_VIDEO_API_KEY` | vendor scheme | video |

Auth scheme is per-provider, not global: a bearer for one vendor is an
`x-api-key` for the next, and getting it wrong produces a 401 that reads exactly
like a bad credential.

**`POST /v1/keys` — OpenRouter's key provisioning surface — is deliberately
absent and must never be added.** It is the one vendor endpoint that could
manufacture a durable credential, which would undo the design from inside. A
caller can learn what is left; it cannot mint more.

### Per-request authorization: the open gap

Two checks run today: *which workload is this* (TokenReview), and *may it spend
on this provider* (`Caller.May(provider)`). The grant table is written out:

```
system:serviceaccount:hanzo:cloud=openrouter
system:serviceaccount:zen:zen=openrouter
system:serviceaccount:enso:enso=openrouter
```

**The gap: grants are per-provider, so a grant on `openrouter` reaches every call
in that provider's list — including `GET /v1/credits`, `GET /v1/key` and `GET
/v1/activity`.** `cloud` is the pod containing `/exec`. So a compromised `/exec`
can read our account balance, the key's label, limit and tier, and the full usage
record. That is not spend and it is not key theft, but it is account intelligence
handed to the exact surface this design exists to contain.

The operations differ in kind and the grant should say so:

| Caller | inference | account (`/v1/credits`, `/v1/key`, `/v1/activity`, `/v1/generation`) |
|---|---|---|
| `hanzo:cloud`, `zen:zen`, `enso:enso` | **allow** | deny |
| treasury balance loop | deny | **allow** |
| admin status surface | deny | **allow** |
| anything else, every human | deny | deny |

Concretely: a grant becomes `subject=provider:kind`, e.g.
`system:serviceaccount:hanzo:cloud=openrouter:inference` and
`system:serviceaccount:hanzo:treasury=openrouter:account`, with each row in the
operation table tagged `inference` or `account`. Small change, and it is what
makes the treasury and status callers safe to add rather than a reason to widen
`cloud`'s grant. Default stays deny; a new caller is a reviewed table edit.

### Streaming

`stream: true` returns the vendor's SSE frames verbatim including `[DONE]`. Every
write flushed straight through. Client disconnect cancels upstream via request
context.

### Headers

Stripped before forward: `Authorization` (the caller's, replaced),
`Proxy-Authorization`, `Cookie`, `X-Api-Key`, `Api-Key`, `X-Auth-Token`,
`X-Org-Id`, `X-User-Id`, `X-Hanzo-Fronted-By`, `X-Forwarded-For`,
`X-Forwarded-Host`, `X-Forwarded-Proto`. The caller's token proved it may spend
*here*; it means nothing at the vendor and must not be offered to one. Tenant
headers go because who our customer is, is not the vendor's business. `Host` is
set to the vendor or TLS and routing disagree.

### Errors

| Condition | Status |
|---|---|
| missing/invalid/expired token, wrong audience, workload holds no grant, no grant on this provider | `403 forbidden` |
| unknown provider, or a call not in that provider's list | `404` |
| credential not resolved | `503` |
| per-caller rate limit | `429` |
| upstream unreachable | `502` |
| upstream answered | passthrough, unmodified |

One refusal message for every authentication and authorization failure. Told
apart, "bad token", "wrong audience" and "ungranted workload" are a map for
whoever is probing which they got right.

### Platform surface

`/healthz` — liveness; names which providers egress can currently spend on, so an
operator console asks here instead of checking for a key in its own environment.
Which providers, never anything about the credential. `/readyz` — false until a
credential is actually held. `/metrics` — Prometheus text, scraped by Victoria
Metrics: `egress_spend_total`, `egress_refused_total`,
`egress_upstream_failed_total`, `egress_credential_held`,
`egress_credential_wanted`. All three unauthenticated; none reflects state that
matters.

---

## 7. Credential lifecycle

**Set once, by a human, from their own machine.** `z@hanzo.ai` writes the final
value with the kms CLI. Never through a chat transcript, never baked into an
image, never in a manifest. The only moment plaintext exists outside KMS and
egress.

**Stored under one org-qualified reference.** KMS parses a reference as `name`,
`path/name`, or `path/name@env`. A **bare name resolves to path `/`, which selects
the system namespace — a different SQLite partition from an org's** — so a value
seeded at an org path is genuinely absent when read back bare. The write succeeds,
the read 404s, and nothing reports the mismatch. The rule that removes it: **seed
and read through the same org-qualified reference, always.** One constant, shared
by the seeding step and the client; environment (`prod`) always named. Egress
holds `ai/OPENROUTER_API_KEY`, not `OPENROUTER_API_KEY`.

**Sealed at rest.** KMS stores ciphertext under its envelope key. Application-
layer encryption is the guarantee; DigitalOcean encrypts block storage at rest,
but that is a control we neither own nor can attest to, and disk encryption only
defends a powered-off disk. A floor, not the guarantee.

**Released only to egress.** KMS grants read on the six provider secrets to
exactly `system:serviceaccount:hanzo-egress:egress` — not to `cloud`, `zen`, `ai`,
`agents`, any human, or `admin`. Read-only: egress can spend and cannot change.
Rotation is a separate admin-scoped write path. **This grant is the entire
design.** `cloud` holds `KMS_CLIENT_ID`/`KMS_CLIENT_SECRET` today, so "cloud
cannot read these" is a test to run, not an assumption.

**Held in memory only.** Resolved before the listener opens — a boot that cannot
reach KMS never accepts a request it would have to refuse. Refreshed on a timer,
not in the request path, so a proxied call never waits on KMS. A failed refresh
keeps the last good value and logs the reason: a KMS outage must not stop paid
traffic a still-valid credential can serve, and a genuinely revoked credential
fails at the vendor, which is the correct place for that verdict.

**Kept off disk.** Two ways a value in RAM reaches a disk with nobody writing it:
the kernel pages it to swap, or writes a core file when the process dies badly.
Core dumps are closed unconditionally (`RLIMIT_CORE` 0). Locking pages is
attempted and **non-fatal on failure** — correct, because Restricted Pod Security
drops all capabilities and unprivileged `mlockall` is bounded by
`RLIMIT_MEMLOCK`. Kubernetes runs with swap off, which is the real guarantee;
locking reinforces it rather than replacing it.

> **Hazard to verify before rollout.** `MCL_FUTURE` makes *future* allocations
> fail once locked memory reaches `RLIMIT_MEMLOCK`. If the limit is low (some
> container runtimes default to 64 MiB) and `mlockall` succeeds at boot while the
> heap is small, the process will fail allocations later under concurrency and
> die in a way that looks like a random OOM rather than a limit. Either read
> `RLIMIT_MEMLOCK` at boot and skip locking unless it is at least the container
> memory limit, or drop `MCL_FUTURE`. A silent success is more dangerous here
> than a logged failure.

**Image carries nothing.** Distroless static, one binary, no shell, no package
manager, no config file. Verified in CI: export every layer, grep for credential
prefixes (`sk-or-`, `sk-ant-`, `sk-`, `fw_`) and the live values, fail the build
on any hit. An image carrying no secret is a claim that gets tested.

**Horizontally scalable.** Every replica identical and interchangeable, each
fetching for itself at boot. No replica authoritative, no key in any pod spec,
scaling up copies nothing.

**Rotation is one write.** New value into KMS; every replica picks it up within
the refresh interval. No redeploy, no restart, no fleet-wide 401 window.

**Logs name the credential without disclosing or confirming it.** The fingerprint
is an HMAC under a 32-byte per-process random key that never leaves the process.
A plain digest would be a confirmation oracle — anyone holding a candidate
credential and a log line could verify it is the one in use. Rotation stays
visible; the oracle does not exist.

---

## 8. Deployment

### Where it runs

**`do-sfo3-hanzo-k8s`, namespace `hanzo-egress`.** Not off-cluster.

The case for off-cluster is that a DigitalOcean API token reaches every pod,
secret and volume in DOKS, so egress there holds a decrypted credential inside the
blast radius it exists to escape. The premise is true; the conclusion does not
follow, for two reasons the cluster makes concrete:

- `DO_API_TOKEN` is *in the cloud pod's environment right now*. The adversary who
  holds it is the same one who already reads all six provider keys directly.
  Moving egress off-cluster takes nothing from them.
- Once that token is out, the remaining adversary is a DigitalOcean account
  compromise — and a DigitalOcean droplet is not outside a DigitalOcean account.
  Genuinely escaping it means a different provider, buying a bespoke host fleet, a
  network-bound unlock service, and a no-login provisioning path to run and
  secure.

Meanwhile the controls doing this work are already here at near-zero cost: Cilium
enforces policy, gVisor and Kata runtimeclasses are registered, Restricted Pod
Security is available, projected identity is native.

The instinct is right — the boundary should move — but it has to move where the
*store* is, and consistently. Relocating the process while the secrets plane stays
inside `cloud` (§9) buys nothing. Hardened hosts stay a documented later option,
worth revisiting after the store has moved and `DO_API_TOKEN` has left cloud's
environment. For node-level separation sooner: a dedicated tainted DOKS node pool
— same cluster, same controls, no new fleet.

### Namespace and pod

Its own namespace, so default-deny and Restricted Pod Security apply to exactly
one workload — enforcing either inside a shared namespace means weakening it to
suit the neighbours or breaking them. Note ns `hanzo` carries **no** pod-security
labels today, so nothing is inherited:

```yaml
pod-security.kubernetes.io/enforce: restricted
pod-security.kubernetes.io/enforce-version: latest
pod-security.kubernetes.io/audit: restricted
pod-security.kubernetes.io/warn: restricted
```

Pod: `runAsNonRoot`, uid 65532, `seccompProfile: RuntimeDefault`,
`allowPrivilegeEscalation: false`, `readOnlyRootFilesystem: true`, `capabilities:
drop [ALL]`, no `hostPath`/`hostNetwork`/`hostPID`/`hostIPC`. Memory limit, no CPU
limit — throttling a proxy in the inference hot path turns a load spike into
latency for everyone. `automountServiceAccountToken: true`, because egress asks the
API server to authenticate its callers.

`replicas: 2` minimum, `maxUnavailable: 0` so a rollout never drops below serving
capacity. Add `topologySpreadConstraints` on hostname and a
`PodDisruptionBudget minAvailable: 1`, and raise
`terminationGracePeriodSeconds` to 60 with a 20s drain — an in-flight streamed
completion is a long, legitimate response and the default 30s can cut one off.

Kustomize, pinned semver tag (`ghcr.io/hanzoai/egress:v0.1.0`), declared in
`hanzoai/universe`, reconciled by Hanzo CD. Floating tags never reach a cluster.

### Network policy

Written as Cilium policy throughout, because two things that need saying — "the
cluster API server" and "this vendor by name" — cannot be said in a plain
NetworkPolicy, and splitting the boundary across two dialects leaves nobody able
to read the whole thing.

The credential not living in a caller is the control; policy is the second latch,
making the single path structural so a credential that somehow reached a pod again
still could not be spent from there.

- **Ingress:** only namespaces holding a granted workload (`hanzo`, `zen`, `enso`)
  may open a connection, port 8080.
- **Egress:** kube-dns; `kube-apiserver` (TokenReview); the secrets plane; and the
  vendor by FQDN (`openrouter.ai:443`). Adding a provider means adding it here as
  well as in the binary — deliberately two places, because reaching a new third
  party should be visible in the network boundary and not only in code.
- **`vendor-direct-deny`**, a `CiliumClusterwideNetworkPolicy`: nothing except
  egress may reach the vendor directly. `enableDefaultDeny: false` on both
  directions and it **must stay false** — enabling it would put every endpoint in
  the cluster into default-deny egress, which is a total outage. It adds one
  prohibition and changes nothing else.

> **Ordering hazard.** `vendor-direct-deny` blocks the `cloud` pod from reaching
> `openrouter.ai`. Applying it before cloud is repointed to egress takes every
> OpenRouter-backed SKU down instantly. It belongs at step 6 of §14, never
> earlier. Verify the `NotIn` selector matches pods with no `app` label at all
> before relying on it for coverage.

---

## 9. The gating dependency: the store is still inside cloud

`kms.hanzo.ai` → `hanzo/cloud:8000`; the secrets plane is `apps/kms` inside the
cloud binary; `CLOUD_KMS_MASTER_KEY_REF` is in cloud's environment. The deployment
reads its credentials from `http://cloud.hanzo.svc.cluster.local:8000` — an
in-cluster address chosen for a correct operational reason (the public host is
fronted by a CDN that refuses a server-side POST), but pointing at the same
process tree regardless.

Worse than co-location: **in-process authorization does not separate co-located
callers.** The secret RPC's `authorize()` returns nil for any reference naming no
tenant; the capability travelling with the request is parsed but never verified.
`SO_PEERCRED` proves the peer is one of ours — not *which* of ours. A per-app
broker that would have made that distinction was designed and deleted.

So today, after a complete cutover, a compromised `/exec` could still:

1. read `CLOUD_KMS_MASTER_KEY_REF` from its own environment, and
2. reach the co-located secrets plane, where `authorize()` does not distinguish it
   from any other cloud process,

and obtain the provider credentials **without going through egress at all**. Every
threat-model row that improves below would be unchanged in reality.

This is the one thing that can make the whole design theatre, so it is a hard
precondition, not a follow-on:

**Egress must read from a secrets plane that is not the `cloud` deployment, whose
envelope key is absent from cloud's environment, and whose grant on the six
provider secrets names only egress's identity.**

It is also the answer to the obvious simplification, "why not skip egress and have
each app read KMS in-process?" — because in-process is not an authorization
boundary. A separate pod with its own workload identity and an org-scoped grant is
what turns the read into a decision KMS can actually make.

Three things must be true before step 6, in order:

1. **A secrets plane separate from `cloud`**, with its own envelope key, holding
   the provider credentials. Whether `kms.hanzo.ai` is repointed wholesale or the
   provider secrets simply live only there is an implementation choice; the
   invariant is that reading them does not go through `cloud`. The Cilium egress
   rule and `EGRESS_KMS` both change to its address.
2. **The read path works** through the org-qualified reference (§12).
3. **The grant is scoped**, and verified denied for `cloud`, `zen`, `ai`,
   `agents`, and every human including `admin`.

Until all three hold, egress can be built, deployed and proven serving — but the
credentials have not actually moved, and the environment injection must stay.

---

## 10. Threat model

**Total** (attacker obtains the credential), **High**, **Bounded** (can spend
through our meter, cannot take the credential), **Low**, **None**.
"After" assumes §9 is satisfied.

| # | Surface | Before | After | What changed, and what does not |
|---|---|---|---|---|
| 1 | Code execution via `/exec`, `/sandboxes` reading `os.Environ` | **Total** — 6 keys plus `DO_API_TOKEN` and the KMS master key | **Bounded** | Keys are not in the environment. `/exec` still shares `cloud`'s identity so it can call egress as if it were `/ai` — metered, rate-limited, attributed, revocable by one table edit. Same-pod impersonation closes only by splitting the pod (§5). Account-metadata reads stay open until grants are per-kind (§6). |
| 2 | Compromised sibling process in the `cloud` pod | **Total** | **Bounded** | Same as 1. |
| 3 | A co-located app reading the secret **in-process** from `apps/kms` | **Total** — `authorize()` returns nil for untenanted refs; `SO_PEERCRED` proves "one of ours", not which | **None** *only if §9 lands* | This is why apps must not read KMS in-process. **If §9 is skipped this stays Total and voids rows 1, 2, 5 and 6.** |
| 4 | Human or CI with `kubectl get secret -n hanzo` | **Total** — base64 is not encryption | **Low** | No Secret holds a provider key. Residual: the `egress-kms` Secret in `hanzo-egress`, which unlocks all six. **None** once KMS accepts the projected token (§12). |
| 5 | Image or registry theft | **Low** | **None** | Verified in CI, not asserted. |
| 6 | Node disk or volume snapshot | **High** — kubelet writes Secrets to the node; a snapshot is an API call | **Low** | Nothing durable holds the credential. Residual is live-memory capture, which is row 8. |
| 7 | etcd / managed control plane | **High** — Secrets live in etcd; encryption there is DigitalOcean's control, not ours | **Low** | The provider credential is never a Secret. Residual is the `egress-kms` Secret until §12. |
| 8 | **Compromised egress process** | n/a | **Total, irreducible** | §11. |
| 9 | Network between caller and egress | n/a (new) | **Low** | In-cluster only, no Ingress, ClusterIP, Cilium ingress restricted to three namespaces. Plaintext HTTP in-cluster is the accepted residual; cluster-wide mTLS is a separate programme. |
| 10 | Stolen caller credential | **Total** — a leaked provider key spends off our network, invisibly, until a five-vendor rotation | **Bounded** | A stolen SA token expires in ≤1h, is audience-bound, useless elsewhere, and buys only metered calls. |
| 11 | DigitalOcean account compromise (`DO_API_TOKEN`) | **Total** | **Total** | **Not addressed.** Tracked separately. It is why off-cluster egress alone would not have helped (§8). |
| 12 | Credential in logs, metrics or errors | **High** — any of ~26 processes may log its environment on a crash | **Low** | One process touches the value; HMAC fingerprint under a per-process random key, never the value; upstream error bodies not reflected; no pprof. |
| 13 | Compromised KMS | **Total** | **Total** | Inherent: the store holds everything. Mitigated by KMS being small, admin-scoped for writes, audited per read, and no longer the same process as `cloud`. |
| 14 | Vendor-side escalation through the proxy | n/a (new) | **Low** | The call list means no caller composes a path, so `/v1/keys` provisioning is unreachable. Would be **High** with a caller-controlled tail. **Moderate** today for account metadata, until grants are per-kind (§6). |
| 15 | Malicious or buggy allowed caller burning spend | **Total** (no limit) | **Bounded** | Per-caller rate limits and attribution; one identity removable without touching the credential. |

Net: the design converts *credential theft* into *bounded, observable, revocable
spend*. It does not make the credential unreachable to an adversary who owns the
cluster or the cloud account.

---

## 11. Where "unstealable" is overstated

The mandate asks for a credential "unstealable, unviewable, ungettable after it's
set". Three are achievable and one is not.

**Achievable.** Unviewable by humans: no read-back, no Secret, no environment
variable, no log line, no image layer. Ungettable by callers: no operation returns
a credential. Ungettable from storage: not in etcd, not on a node disk, not in a
snapshot.

**Not achievable: unstealable from a running egress process.** Egress holds the
plaintext in memory to sign the outbound request. Anyone who can read that
process's memory has the key — `kubectl exec` (RBAC), a container escape, root on
the node, or a remote-code-execution bug in egress. No design that makes outbound
calls on a caller's behalf avoids this: the credential must exist at the moment it
is used. An HSM would move signing into hardware, but provider APIs take a bearer
string, not a signature, so there is nothing to move.

What bounds it: no shell in the image, so `kubectl exec` has nothing to execute;
`pods/exec` in `hanzo-egress` granted to no one by default, break-glass being a
reviewed, audited, time-boxed SuperAdmin act; a small surface with no user code,
no templating, no deserialization beyond JSON passthrough, no pprof; Restricted
Pod Security; a narrow set of people who can reach a node; rotation as one KMS
write so a suspected compromise is answered in minutes; and per-caller rate limits
so successful abuse is metered and visible.

The honest formulation: **the credential stops being available to twenty-six
processes, every Secret reader, and every snapshot of the cluster, and becomes
available only to one small process with no shell that exists to spend it.** A
large, real reduction. Not "unstealable".

---

## 12. KMS: what must change

**The read path — a reference-shape trap, not a missing route.** `parseRef`
accepts `name`, `path/name`, `path/name@env`. A bare name resolves to path `/`,
selecting the system namespace — a different partition from an org's. Measured: a
bare `OPENROUTER_API_KEY` GET returns 404 while the same record read with its
org-qualified path returns 200, and listing the org partition shows it present
throughout. The write succeeded; the read looked in another drawer. The fix is
discipline: **one org-qualified reference constant, shared by the seeding step and
the client, environment always named.** Egress already holds
`ai/OPENROUTER_API_KEY`; the seeding step must write to exactly that. A bare-name
read should arguably fail loudly rather than resolve to the system namespace —
worth proposing, not a blocker.

**Workload-identity authentication.** KMS must accept a projected ServiceAccount
token (audience `kms`), verify it by TokenReview, and map
`system:serviceaccount:<ns>:<name>` to a grant:

| Identity | Six provider secrets | Everything else |
|---|---|---|
| `system:serviceaccount:hanzo-egress:egress` | **read** | none |
| `system:serviceaccount:hanzo:cloud` | **denied** | unchanged |
| `zen`, `ai`, `agents`, any other workload | **denied** | unchanged |
| humans, including `admin` | **write / re-seal only, no read-back** | unchanged |

This retires `EGRESS_KMS_ID`/`EGRESS_KMS_SECRET` and the `egress-kms` Secret —
after which no standing credential exists anywhere in the chain. Until then, that
Secret is the residual named in threat rows 4 and 7.

Reads are audited: which identity read which secret, when. That trail answers
"what was spent on my key" for BYOK later, and "what did the attacker reach" after
an incident.

---

## 13. Acceptance tests

Executable checks, not review items.

| # | Test | Pass |
|---|---|---|
| 1 | `kubectl -n hanzo exec deploy/cloud -- env \| grep -E 'OPENROUTER\|ANTHROPIC\|OPENAI\|FIREWORKS\|DO_AI\|SPARK_VIDEO'` | no output |
| 2 | `kubectl -n hanzo get secret cloud-api-llm-keys` | not found, or provider keys removed |
| 3 | `kubectl -n hanzo-egress exec deploy/egress -- env` | no shell in image; fails |
| 4 | Export every image layer, grep credential prefixes and live values | no match; CI fails the build on a hit |
| 5 | No token | `403` |
| 6 | Token minted for audience `api` instead of `egress` | `403` — the audience echo-back check |
| 7 | Expired token | `403` |
| 8 | Valid `egress` token, ServiceAccount absent from the grant table | `403` |
| 9 | `hanzo:cloud`, `POST /openrouter/v1/chat/completions` | `200`, correct completion |
| 10 | Same, `"stream": true` | SSE frames arrive incrementally, `[DONE]` terminates |
| 11 | `POST /openrouter/v1/keys` (provisioning) | `404`, no upstream call |
| 12 | Any path not in the provider's call list | `404`, no upstream call |
| 12a | `GET /openrouter/v1/credits` as `hanzo:cloud` | `403` once grants are per-kind — **fails today**, see §6 |
| 12b | `GET /openrouter/v1/credits` as the treasury caller | `200` |
| 13 | Any request that could return a credential | no such operation exists |
| 14 | KMS read of the provider secret as `system:serviceaccount:hanzo:cloud` | denied |
| 15 | Same as `zen`, `ai`, `agents`, and as a human operator | denied |
| 16 | Same as `system:serviceaccount:hanzo-egress:egress` | allowed |
| 17 | Seed then read back through the **same org-qualified reference** | `200`, value matches |
| 18 | Read the same secret by **bare name** | `404` expected — documents the trap |
| 19 | `kubectl -n hanzo-egress logs deploy/egress \| grep -F "$OR_KEY"` | no match; fingerprint present, value absent |
| 20 | Rotation: new value in KMS, nothing else changed | in use within one refresh interval; no restart; no failed request |
| 21 | Post-rotation, replay the old key directly against the vendor | rejected (confirms the old value is dead) |
| 22 | Kill one replica mid-stream | one failed request; others serve; no key re-provisioning |
| 23 | Scale 2 → 10 | every replica self-resolves; no key in any pod spec; no manual step |
| 24 | From an egress pod: `curl https://example.com` | blocked by policy |
| 25 | From the `cloud` pod: `curl https://openrouter.ai` | blocked by `vendor-direct-deny` — **only valid after step 6** |
| 26 | Per-caller rate limit exceeded | `429`, upstream not called |
| 27 | Sustained load at the memory limit | no allocation failure — the `MCL_FUTURE` hazard in §7 |

---

## 14. Cutover order

Strict. Reordering steps 5 and 6 takes every OpenRouter-backed SKU to 401.

1. **Secrets plane separated from `cloud`** (§9); read path proven through the
   org-qualified reference (§12).
2. **Grant scoped** to egress's identity; tests 14–18 pass.
3. **Egress deployed** to `hanzo-egress`, OpenRouter only. `/readyz` green — it
   resolved the credential. Environment injection untouched; nothing consumes
   egress yet.
4. **Egress proven serving** on synthetic traffic. Tests 5–13, 19–24 pass.
5. **Every consumer of that key repointed**, deployed, and observed carrying real
   traffic — inference *and* the treasury balance probe *and* the admin status
   surface. `cloud-api-llm-keys` still injected; this step is reversible by
   config, which is the point. Enumerate consumers before starting: a missed one
   does not fail here, it fails at step 6, after the key is gone.
6. **Only then**, remove `OPENROUTER_API_KEY` from the injection, and apply
   `vendor-direct-deny`. Tests 1, 2 and 25 pass.
7. **Value rotated** at the provider by the user, written once into KMS. Tests 20
   and 21 pass. This makes any prior exposure of the old value moot, and it comes
   last because it is only safe once the value lives in one place.
8. **Repeat 3–7 per remaining provider**: OpenAI, Anthropic, Fireworks, DO AI,
   Spark video. One at a time, each independently reversible.

GitLab OAuth credentials are not in this sequence — §15, answer 4.

Rollback before step 6 is a config change. After, it is re-adding the Secret
reference and removing a policy — a redeploy. That asymmetry is why steps 4 and 5
are not optional.

---

## 15. Answers for the cloud-side consumer

**1. Call shape.** Internal HTTP:
`http://egress.hanzo-egress.svc.cluster.local`. Not ZAP-over-UDS — UDS needs a
per-pod sidecar, which multiplies credential copies instead of reducing them to
one. `POST /openrouter/v1/chat/completions`, body is the OpenAI-compatible payload
unchanged, `Authorization: Bearer <projected SA token, audience=egress>`. You name
the provider; egress chooses the address. Streaming exactly as with the vendor:
set `"stream": true`, read SSE. Full table in §6.

**2. Proxy or dispenser.** **Proxy.** Egress makes the outbound call itself. No
operation returns a key and none will — a dispenser would put a provider
credential back in your process, which is the exposure being removed. §4.

**3. Caller identity and granularity.** Mount a projected ServiceAccount token
with `audience: egress`; egress verifies it via TokenReview and authorizes on
`system:serviceaccount:<ns>:<name>`. No shared `EGRESS_TOKEN`, no client secret,
nothing to store or rotate — the kubelet handles it. Your grant is already in the
table: `system:serviceaccount:hanzo:cloud=openrouter`.

Being direct about the limit you asked about: **no, egress cannot distinguish
`/ai` from `/exec` while they are siblings in the `cloud` pod** — and a better
token does not fix it, because a projected token is a file every process in the
pod can read. Anyone claiming per-process authorization is wrong.

The proxy still closes the exposure that matters. `/exec` can call egress; it
cannot obtain a key, exfiltrate one, use one after losing access, spend off our
network, or force a five-vendor rotation. The residual is bounded spend through
our meter, rate-limited and attributed. Per-process authorization needs the
code-execution surfaces in their own pod with their own ServiceAccount, absent
from the grant table — recommended follow-on, not a blocker.

One thing to fix on our side before you rely on it: grants are currently
per-provider, so your grant also reaches `GET /v1/credits`, `/v1/key` and
`/v1/activity`. Being tightened to per-kind (§6) so inference callers cannot read
account metadata.

**4. Coverage.** The **six provider credentials**: `OPENROUTER_API_KEY`,
`DO_AI_API_KEY`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `FIREWORKS_API_KEY`,
`SPARK_VIDEO_API_KEY`. OpenRouter first.

This means every *use*, not only inference. The treasury balance probe and the
admin provider-status surface spend the same key and go through the same door, on
their own identities. If either keeps a direct path to the vendor, the key still
has to live somewhere else and the cutover does not complete — and
`vendor-direct-deny` will break them at step 6.

**`GITLAB_CLIENT_ID` and `GITLAB_CLIENT_SECRET` stay out.** Different kind of
thing. A provider key is a bearer credential presented on every call — exactly what
a proxy can hold for you. OAuth application credentials participate in a
redirect-based authorization-code flow: the client id is *public by design* (it
appears in the browser's authorization URL) and the secret is used once at token
exchange, in a flow whose other half is a user-agent redirect egress is not in the
path of. Brokering them would mean egress reimplementing an OAuth client — an
identity concern, IAM's, not egress's. Two unrelated lifecycles behind one door,
and a second job for egress.

**5. Cutover order.** §14. Two rules that matter: egress must be proven serving
real traffic *before* any environment injection is removed, and removal is
per-provider, one at a time. Concretely — deploy egress, prove it, repoint and
watch real traffic flow through it, and only then delete `OPENROUTER_API_KEY` and
apply `vendor-direct-deny`. Either one first takes every OpenRouter-backed SKU to
401. Rollback before that is a config change; after, a redeploy.

---

## 16. Open dependencies

| # | Item | Owner | Blocks |
|---|---|---|---|
| 1 | Provider secrets read from a plane that is not the `cloud` deployment | KMS | **everything — §9** |
| 2 | Seeding writes the same org-qualified reference egress reads (`ai/OPENROUTER_API_KEY`) | KMS | tests 17, 18 |
| 3 | Workload-identity auth in KMS; grant scoped to egress only | KMS | tests 14–16 |
| 4 | Retire `EGRESS_KMS_ID`/`_SECRET` and the `egress-kms` Secret | KMS + egress | threat rows 4, 7 |
| 5 | Grants per **kind** (`inference` vs `account`), not per provider | egress | test 12a |
| 6 | Provider surface extracted from `hanzoai/ai` into the shared package | ai + egress | step 3 |
| 7 | Remaining five providers in the table with their auth schemes | egress | step 8 |
| 8 | Per-caller rate limits | egress | test 26 |
| 9 | Image credential scan in CI | egress | test 4 |
| 10 | `RLIMIT_MEMLOCK` check before `mlockall`, or drop `MCL_FUTURE` | egress | test 27 |
| 11 | PodDisruptionBudget, topology spread, 60s termination grace | egress | rollout safety |
| 12 | Treasury and status callers get their own ServiceAccounts and grants | cloud | step 5 |
| 13 | `/exec` and `/sandboxes` in their own pod and ServiceAccount | cloud | follow-on; threat rows 1–2 residual |
| 14 | `DO_API_TOKEN` out of cloud's environment | cloud | not this cutover; threat row 11 |
