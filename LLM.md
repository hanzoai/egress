# LLM.md — hanzoai/egress

The outbound trust boundary: upstream credentials stay in KMS, callers ask for a
metered call and never hold a key. `ingress` is the inbound twin.

## Laws

- **Never return a credential.** A caller asks for a CALL. Handing back a key
  reduces this to a secret-fetch service, which is the thing being replaced.
- **The destination is never taken from the request.** A caller names a provider;
  the address comes from the table in `upstream.go`. A service that accepted a
  URL would be an authenticated open proxy, and its credential would be a way to
  sign requests to anywhere.
- **Only listed operations are reachable.** A vendor's API is wider than the part
  we use. Inference and read-only account metadata are listed; the surface that
  mints or revokes keys is not.
- **Refuse rather than serve unauthenticated.** An unidentifiable caller cannot
  spend money.
- **A BYOK key is write-only and never returned** — not to its owner, not to an
  operator, not to support. It is spent only for the validated principal it
  belongs to, and its use is recorded because the customer will ask.

## Shape

Four orthogonal pieces, flat in the root package:

| file | owns |
|---|---|
| `upstream.go` | the allowlist: provider → address, credential reference, auth scheme, permitted operations |
| `credential.go` | credentials in memory, refreshed on a timer, never written down |
| `kms.go` | reading a sealed credential from the secrets plane |
| `identity.go` | who the caller is, and whether it may spend on this provider |
| `cluster.go` | the client that talks to the cluster, and only the cluster |
| `egress.go` | the proxy: route, authorize, strip, attach, stream |

Adding a provider is one row in `upstream.go`, one KMS record, and one name in
the network policy. No new code path.

## Two coordinates that are easy to get wrong

A KMS reference is a **path and a name within the reading identity's org**, and
the read must also name the **environment**:

    ai/OPENROUTER_API_KEY   env=prod        resolves
    OPENROUTER_API_KEY      env=prod        404 — a bare name resolves to the
                                            platform partition, a different file
    ai/OPENROUTER_API_KEY   env unset       404 — falls back to env `default`
                                            while the fleet writes `prod`

Both mistakes return "not found" for a secret that plainly exists, and the
listing endpoint shows it either way because listing enumerates the whole
subtree across every environment while reading is exact. That asymmetry is the
`get`-404-but-`list`-shows-it defect; `TestSecretReadSendsFullCoordinate` pins
the client against it.

## Caller authentication

Callers present the projected service-account token the kubelet mints for them,
addressed to audience `egress`. Egress does not verify it — it asks the cluster
(`TokenReview`), which is the authority on its own tokens. That keeps revocation
instant and leaves no signature checking here to get wrong. The answer is cached
for a minute; refusals are never cached.

Egress holds `system:auth-delegator` and nothing else: it may ask who someone
is, and may not read a Secret, a Pod, or any other object.

## What lives elsewhere

- credential custody at rest, per-secret policy, audit trail → KMS
- which model, margin, billing → `hanzoai/ai`
- rate limits, budgets, circuit breaking → `gateway`'s edge policy
- inbound identity, JWT validation, header hygiene → `ingress` / `gateway`

Egress owns exactly one thing: the decision to spend, and the record of it.

## Why it is not built on the provider surface from `hanzoai/ai`

The law against a second implementation of the dialects stands. Egress does not
implement them at all — it forwards bytes, so there is nothing to drift. A
transparent proxy is immune to dialect change in a way that a shared library is
not, and keeping the dependency graph of a credential holder small is itself a
security property: the fewer packages linked into the process holding a live key,
the smaller the claim being made. The only dialect-shaped knowledge here is how a
vendor wants its credential presented, which is three fields in a table.

## Honest limits

- A running host is decrypted. Memory is locked and core dumps are off, so the
  credential does not reach a disk on its own — but anyone who can execute in
  this pod, or read its memory, has it. The image carries no shell to help them.
- The secrets plane is served by `cloud` today, and `cloud` holds the master key
  in its environment. Until KMS is a separate process with its own key custody,
  compromising `cloud` still yields every sealed secret, including this one.
  Moving the credential here removes it from `zen` and `enso` and from three
  Kubernetes Secrets; it does not put it out of reach of `cloud`.
- The identity egress reads KMS with is a client credential delivered as a
  Kubernetes Secret. It is read-only and org-scoped, and it is the last durable
  secret on disk in this path.
