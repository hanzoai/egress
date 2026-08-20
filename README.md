# Hanzo Egress

The outbound trust boundary. `ingress` decides who may come in; **egress decides
who may spend.**

An upstream credential — an OpenRouter, OpenAI, Anthropic, Fireworks or DO key —
is money. Today those keys sit in the calling process's environment, which means
anything that can reach that process can take one, and nothing records that it
happened. Egress holds them instead: a caller asks for a **call**, not for a key.

```
ai / any caller  ──asks for a call──▶  egress  ──holds the key──▶  upstream
                 ◀──── response ─────         (KMS custody)
```

## What it changes

A stolen caller credential buys metered calls through our own meter — rate
limited, attributed, audited, and revocable in one place — instead of a vendor
bearer token that spends without limit, off our network, invisibly, and takes a
five-vendor rotation to undo.

This is bounded and observable rather than unstealable. No credential that lives
in a cluster is unstealable from someone who owns that cluster; what changes is
what the theft is worth.

## Composed, not rewritten

Three things exist already and egress is their composition. It should add
custody and nothing else:

- **the provider surface** — dialects, relay, streaming, media — lives in
  `hanzoai/ai`. Egress IMPORTS it. A second copy would drift silently: a changed
  streaming shape or a moved usage field works in one and not the other, and we
  find out from a customer.
- **rate limits and circuit breakers** — `gateway`'s edge policy. Imported for
  the same reason: two rate limiters disagree about who is over budget.
- **credential custody at rest** — KMS, which already keeps a per-secret policy
  (`auto-approve` / `requires-approval` / `blocked`) and a per-agent audit trail.

## Where it runs, and why that is the whole point

**Off the managed cluster.** A DO API token reaches every pod, every secret and
every volume in DOKS. Egress running there would hold a decrypted key inside the
blast radius it exists to escape.

It runs on metal we own, because renting the escape hatch from the provider it
escapes puts it back inside. The root is sealed to the machine's TPM under a PCR
policy: no passphrase exists for anyone to know or type, the disk opens only on
that board under the boot chain we signed, and a changed binary measures
differently and is refused. Every provider key is encrypted to a key that cannot
leave that TPM before it is written anywhere, so what KMS stores is ciphertext
KMS cannot open.

Honest limit: a RUNNING host holds the key in memory. A TPM seals storage, not
RAM — only SEV-SNP or TDX closes that, and it is a machine to buy rather than an
architecture to change. See `deploy/README.md`.

## Callers hold no key

`hanzoai/ai` resolves every credential through one precedence rule — the KMS
store first, configuration second — so sealing a key removes it from the
caller's environment with no code change there. Egress is what makes the sealed
key usable without ever handing it back.

A local single-binary `ai` needs none of this: keys from the environment, direct
calls, no KMS and no egress. That path stays exactly as it is.

## BYOK — a customer's key is not ours to hold loosely

A customer bringing their own provider key is the sharper case: it is their
money, their vendor relationship and our liability. It must be **more** guarded
than our own keys, not less, and it must reach the upstream through this same
door — a BYOK path that bypasses egress to call directly would be the one place
a customer key is handled worse than a platform key.

The custody rule already exists and egress inherits it rather than inventing a
second one:

    /orgs/{org}/users/{user}/connectors/{provider}/{label}    per-user
    /orgs/{org}/cloud/{provider}/{label}                      per-org

**The path is built from the VALIDATED principal, never from a request field.**
That is the whole tenant boundary: a caller that could name its own path could
name another tenant's. Sealed in KMS, never in a row, verified before store.

Three properties egress owes a BYOK key specifically:

- **it is never returned, to anyone** — not to the customer who supplied it, not
  to an operator, not to a support tool. Write-only after enrolment. A key that
  can be read back is a key that leaks through whichever surface reads it.
- **it is spent only for its owner** — the credential used for a call is
  selected by the validated principal of the caller, so one tenant's key cannot
  fund another's request even by mistake.
- **its use is the customer's record too** — the same audit trail that answers
  "who read this" answers "what did you spend my key on", which is the question
  a customer asks after a surprise vendor bill.

The failure this prevents is specific: a customer key read out of a process
environment, or logged in an error, is a breach of somebody else's account
rather than an internal incident.

## No one logs in, including us

A host that a person can log into is a host whose secrets a person can read, and
"a person" includes anyone who takes that person's credential. So there is no
interactive access: no SSH for operators, no shell, no console login, no
debug endpoint that returns state.

That only works if **nothing is ever repaired in place**. A host that
misbehaves is destroyed and replaced from the image, which is possible precisely
because it holds no state worth keeping — the credentials live in KMS and the
host is a way of spending them, not a place they live. Repair is replacement,
which is also why the absence of a login costs nothing operationally.

Two things have to be true for that to be honest rather than a slogan:

- **it boots without a human.** A LUKS root that needs a passphrase typed makes
  every reboot an outage and every 3am page a person. The unlock is
  network-bound instead — the host asks an unlock service that is NOT in the
  same cloud, and mounts only if it answers. A stolen disk elsewhere cannot ask;
  a cloud API token cannot answer.
- **it is observable from outside.** Metrics, logs and health leave the host to
  the o11y plane. Nothing about diagnosis requires being on the box, because
  being on the box is the thing that was removed.

## The key is fetched, never carried

A replica resolves an upstream credential from KMS over ZAP at call time, behind
a short TTL, and holds nothing durable. That is what makes it horizontally
scalable — every replica is identical and interchangeable, none is authoritative
— and it is also what makes rotation ordinary: a key rewritten in KMS is in use
within the TTL, with no redeploy, no restart and no manifest change.

The same property is what lets a compromised replica be deleted rather than
investigated. It knew nothing that outlives it.

## Scaling

Stateless. The only state worth holding is the credential, and a replica does
not keep one — it resolves through the store behind a short TTL and holds
nothing durable. No sessions, no sticky routing, horizontal by default.
