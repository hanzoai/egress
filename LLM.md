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
- **Refuse rather than serve unauthenticated.** An unidentifiable caller cannot
  spend money.

## What lives elsewhere

- credential custody at rest, per-secret policy, audit trail → KMS
- the provider dialects → `hanzoai/ai`
- inbound identity, JWT validation, header hygiene → `ingress` / `gateway`

Egress owns exactly one thing: the decision to spend, and the record of it.
