# Deploying egress

Egress runs on a host we provision, not in DOKS. That is a correctness property:
a DO API token reaches every pod, secret and volume in the cluster, and every DO
team member holds one — measured, `kubectl auth can-i get secrets -A
--as-group=do-role-name:Member` answers yes. A credential broker inside that
blast radius has not moved the credential anywhere useful.

## The host

**Our own metal, and that is not a preference.** The point of this host is to sit
outside the blast radius of a DO API token; renting it from DO puts it back
inside. There is also nothing to ask DO for — it sells no confidential compute —
so the choice is not between providers, it is between borrowed hardware and ours.

**The passphrase does not exist.** The LUKS root is sealed to the machine's TPM
under a PCR policy, so the disk unlocks only on this board, only under the boot
chain we signed. Nobody types anything, nobody knows a passphrase, and a reboot
is unattended — which matters because a host that needs a human to come back is a
host somebody keeps a passphrase for.

```
# root, sealed to firmware + secure boot + the signed kernel image
systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs=7+11 /dev/<root>
```

**A provider key is encrypted to this box before it is stored anywhere.** The
TPM holds a key that cannot be exported — not by us, not by root, not with the
disk in another machine. Every credential is sealed to it and only then written
to KMS, so what KMS holds is ciphertext that KMS itself cannot open. That answers
the question the store model could not: a KMS administrator reading every row
learns nothing.

```
# the identity, sealed once on the host — the plaintext never lands on disk
systemd-creds encrypt --with-key=tpm2 --name=mnemonic - /etc/egress/mnemonic.cred
# the unit receives it decrypted into its own credential directory, memory only
LoadCredentialEncrypted=mnemonic:/etc/egress/mnemonic.cred
```

**The identity is sealed even where the root is not.** `systemd-creds` binds to
the TPM independently of LUKS, so a host that has not yet been rebuilt with an
encrypted root still keeps its innermost secret as ciphertext at rest. That
matters because the mnemonic derives the key that unlocks every provider
credential: it used to sit in `/etc/egress/env` as plaintext AND in this
process's environment, where `/proc/<pid>/environ` hands it to anything running
as root. Invariant 3 forbids exactly that, and the identity was the one
credential exempting itself from the rule it exists to enforce. There is no
environment fallback — one way to hold it, or the service does not start.

**The policy binds the code, not the operator.** PCR 11 measures the unified
kernel image, so a changed binary, an added debug route or an attached debugger
produces a different measurement and the TPM simply declines to unseal. Nothing
here rests on trusting whoever holds the machine — it rests on the build being
the one that was reviewed.

Consequently the box is an appliance: no SSH, no shell, no console login, and
nothing is repaired in place. CI signs an image, the host verifies the signature
and takes it whole, and a host that misbehaves is destroyed and replaced. It
holds no state worth keeping, which is what makes that cheap.

```
adduser --system --group --no-create-home egress
install -m0755 egress /usr/local/bin/egress
install -d -m0700 /etc/egress
install -m0644 egress.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now egress
```

### What this does not do

**A running host has the key in memory.** The TPM seals storage; it does not
encrypt RAM. Root on a live box, a DMA-capable port, or a cold-boot attack still
reaches the plaintext. Only encrypted memory closes that — SEV-SNP on AMD EPYC or
TDX on Xeon, neither of which is a consumer part and neither of which any cloud
we use offers. It is one machine to buy, not an architecture to change: the
sealing and attestation above are unchanged by it.

**Sealing does not authenticate the store.** A substitute answering in KMS's
place can no longer offer a credential of its choosing — it would have to seal
one to this host's recipient, which it cannot do — but it can still replay a
genuine sealed record it captured. Forgery is closed; replay is not.

**Egress can always spend.** Custody stops a key being taken; it does not stop
the door being used. That is what the meter, the per-principal quota and the
vendor-side cap are for, and they remain load-bearing rather than decorative.

## The sealing pair — mint before anything else

Every provider credential in KMS is sealed to this host. Mint the pair on the
host, and let the pipe put each half where it belongs:

```
egress mint | systemd-creds encrypt --with-key=tpm2 --name=identity - /etc/egress/identity.cred
```

The secret half goes down the pipe into the TPM and never exists as a file. The
public half prints on stderr as `EGRESS_RECIPIENT=age1pq1…` — read it off the
screen and put it in `/etc/egress/env`. It is public by construction: anything
holding it can seal a credential and open none, which is exactly why the cluster
is allowed to have it and why enrolling a key is not the same capability as
reading one.

Losing `identity.cred` loses every credential sealed to it. That is the design
working, not a fault in it — so the recovery plan is re-enrolment at the vendors,
and there is deliberately no copy anywhere to fall back on.

Rotation is a second recipient, not an outage: re-seal each credential to the new
one, then retire the old. A record names its own recipient in `key_handle`, so
both can be in the store at once and each opens with the identity it belongs to.

## Enrolling the identity

Generate the mnemonic **on the host**, write it into `/etc/egress/env`, and
register the derived identity with KMS at `hanzo/egress`. It must not exist in a
cluster Secret, a repo, or CI. Grant that identity read on the provider
credentials and nothing else.

The check that matters: `cloud`'s KMS identity must NOT be able to read the
provider paths. Cloud's `KMS_CLIENT_ID` and `KMS_CLIENT_SECRET` sit in a process
environment shared by 30 sibling processes, so an identity that can read
provider keys from there closes nothing.

## Cutover — order is load-bearing

Every provider key in the estate is live in more than one place. Remove one
before egress serves and the fleet 401s.

1. **Serve.** Start egress. `EGRESS_AUDIENCE` set, KMS reachable, credentials
   resolving. It refuses to open a listener without them.
2. **Seal.** Write each provider key into KMS under the egress identity's tree.
   Nothing is deleted yet — both paths work.
3. **Prove.** Point one caller at egress and confirm a real inference call
   round-trips, streaming included. Not a health check: a status code is not a
   working call.
4. **Cut.** Repoint callers — and this is NOT a URL change. Two things have to
   be true before it can be, and neither is today:

   - **The relay ignores the provider URL for most vendors.** `ai`'s
     `resolveEndpointForPath` hardcodes the endpoint for OpenRouter, Fireworks,
     Grok, Gemini, Jina, Cohere and Moonshot, honouring `ProviderUrl` only for
     OpenAI, Azure, Local/Ollama/DigitalOcean and the default. On the dialect
     side the constructors take no URL argument at all. So setting a URL to point
     here leaves the caller dialing the vendor with its key still in the header
     while the configuration claims otherwise — a caller that keeps its key and
     reports that it does not, which is worse than not moving.
   - **`OPENROUTER_URL` is not read by cloud's Go source.** It decides only
     whether a model family exists at all; the name appears in no call path.

   What a cut actually needs: one place in `ai` that authorizes an outbound call,
   so repointing is a swap of that one thing rather than of every caller.
5. **Delete.** Only now remove the provider keys from the thirteen Secrets
   across three clusters:
   - `hanzo-k8s` — `hanzo/cloud-api-llm-keys`, `hanzo/llm-secrets`,
     `zen/zen-secrets`, `enso/enso-secrets`
   - `hanzo-dev-k8s` — `hanzo/bot-secrets`, `hanzo/chat-secrets`,
     `hanzo/cloud-search-config`, `hanzo/gateway-secrets`,
     `hanzo/hanzo-app-secrets`, `hanzo/llm-secrets`, `hanzo/platform-secrets`,
     `hanzo/rag-secrets`
   - `bootnode-k8s` — `hanzo/shared-credentials`
6. **Rotate.** Reissue every key at the vendor. The old values sat in 30 process
   environments and in kubectl-readable Secrets for an unknown period, so they
   are disclosed, not merely stale. Two providers currently have two live values
   in circulation, so revoke rather than replace.

Steps 1-3 are reversible. Step 5 is not, until step 6 completes.

## Cutover — the cloud plane

A cloud key cuts more cleanly than a model key, and the reason is step 4 above:
the relay hardcodes most vendors' endpoints, so repointing a model caller is not
a URL change. A cloud caller has no such problem. `visor` builds every provider
client over one `*http.Client` from `service/transport.go`, so pointing it here
is a transport swap — `service.RegisterCarrier`, wired by `carry()` from
`egressAddress` + `egressToken`. That seam is the one place, which is exactly
what step 4 says a clean cut needs.

What holds the DigitalOcean key today:

| where | what |
|---|---|
| KMS `hanzo/prod/visor-config` | `DIGITALOCEAN_ACCESS_TOKEN`, the only source of the value |
| `KMSSecret hanzo/visor-kms-sync` | syncs it into the Secret every 600s |
| Secret `hanzo/visor-config` | plaintext to anyone with cluster read |
| Deployment `hanzo/visor` | reads it as env |
| Deployment `hanzo/bot-gateway` | **reads it as env too** |

**`bot-gateway` is the one that blocks a clean delete.** It has no carrier: it
takes the token from its environment and calls DigitalOcean itself. Repointing
visor and deleting the Secret breaks it. Either it grows a carrier of its own —
it is the same `spend.Client` swap, since `spend.Client` returns an
`*http.Client` — or the delete waits for it.

Order, and it is the same shape as the model plane:

1. **Serve**, as above.
2. **Seal** the cloud key at `orgs/<org>/cloud/digitalocean/default` — the org
   scope, since it is the platform's account rather than a customer's. `POST
   /v1/enroll` with `{"provider":"DigitalOcean","key":"…"}`. Write-only: there
   is no route that reads one back.
3. **Prove** with a real call, not a health check:
   `POST /v1/fetch {"provider":"DigitalOcean","method":"GET","path":"/v2/account"}`
   answers 200 and an account. Then `"/v2/droplets?per_page=1"`, which proves a
   query and a non-trivial body.
4. **Cut** — set `egressAddress` and `egressToken` on visor. Both, or it refuses
   to start: an address without a token would 401 every cloud call, and the
   obvious repair for that is to put the key back.
5. **Delete** `DIGITALOCEAN_ACCESS_TOKEN` from the KMS path FIRST, then the key
   from the `KMSSecret`'s list. Deleting the Secret alone accomplishes nothing —
   the sync rewrites it within 600 seconds.
6. **Rotate**, same reasoning as above.

**DigitalOcean's inference API is the model plane, not this one.** Its key
(`doo_v1_…`, distinct from the `dop_v1_…` cloud token) serves an
OpenAI-compatible surface at `https://inference.do-ai.run/v1`. It needs no new
code: enrol it as an OpenAI-dialect provider and point `EGRESS_URLS` at that
base. DigitalOcean is one of the few vendors whose `ProviderUrl` the relay
actually honours, so this is one of the model cuts that IS a URL change.

## Verifying

```
Compromise a caller        -> cannot obtain a provider key
Read any pod environment   -> not present
Read any Kubernetes Secret -> not present
Arbitrary outbound curl    -> blocked
Call egress unauthorized   -> refused
Call an allowed operation  -> succeeds
Use a leaked old key       -> useless after step 6
```

`GOWORK=off go test -race ./...` covers the process. The list above covers the
deployment, and only step 6 makes the last line true.
