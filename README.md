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

It runs on hosts we provision with a LUKS root whose passphrase never enters any
cloud. Then a snapshot, a detached volume, a reboot and DO's own password reset
all yield ciphertext — the last because it must write `/etc/shadow`, which is
inside the encrypted volume.

Honest limit: a RUNNING host is decrypted. LUKS defends disks at rest, not a
live process. Sandboxing, keys-not-in-environment and change review cover that.

## Callers hold no key

`hanzoai/ai` resolves every credential through one precedence rule — the KMS
store first, configuration second — so sealing a key removes it from the
caller's environment with no code change there. Egress is what makes the sealed
key usable without ever handing it back.

A local single-binary `ai` needs none of this: keys from the environment, direct
calls, no KMS and no egress. That path stays exactly as it is.

## Scaling

Stateless. The only state worth holding is the credential, and a replica does
not keep one — it resolves through the store behind a short TTL and holds
nothing durable. No sessions, no sticky routing, horizontal by default.
