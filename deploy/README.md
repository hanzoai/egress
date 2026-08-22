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

**The disk is encrypted, all of it.** LUKS2 on the root, so a stolen disk, a
returned drive or a machine carried out of the rack is ciphertext. There is no
partition that escapes it: every path this service reads or writes — the
credential files, the systemd host key, the journal — is inside it.

```
cryptsetup luksFormat --type luks2 /dev/<root>
```

The passphrase is typed at boot and nowhere else. It is not on the box, not in
KMS, not in a repo, and a reboot is therefore attended — that is the cost of
having no TPM to hold it, and it is a real one: a host that needs a human to come
back is a host somebody keeps a passphrase for. Keep it where a passphrase for a
safe would go, and say who holds it.

**A provider key is encrypted to this box before it is stored anywhere.** The
identity that opens them is held as a systemd credential bound to this host's
own key (`/var/lib/systemd/credential.secret`), which lives on the LUKS root —
so it is ciphertext at rest twice over, and a disk read without the passphrase
yields neither. Every provider credential is sealed to that identity and only
then written to KMS, so what KMS holds is ciphertext that KMS itself cannot open.
That answers the question the store model could not: a KMS administrator reading
every row learns nothing.

```
# the identity, encrypted once on the host — the plaintext never lands on disk
egress mint | systemd-creds encrypt --with-key=host --name=identity - /etc/egress/identity.cred
# the unit receives it decrypted into its own credential directory, memory only
LoadCredentialEncrypted=identity:/etc/egress/identity.cred
```

**No credential is ever plaintext on disk or in the environment.** The mnemonic
derives the key that unlocks every provider credential, and it used to sit in
`/etc/egress/env` as plaintext AND in this process's environment, where
`/proc/<pid>/environ` hands it to anything running as root. Invariant 3 forbids
exactly that, and the identity was the one credential exempting itself from the
rule it exists to enforce. There is no environment fallback — one way to hold it,
or the service does not start.

**A provider API key is not a way in.** Whoever holds one can spend at that
vendor; they cannot reach this host. It is not a resource of any cloud we buy an
API key from, so there is no console to open, no root password to reset, no
snapshot of its disk to take, and no rescue mode to boot it into. That is the
property the whole design rests on, and it is the reason this box is not rented
from the provider whose keys it holds.

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

**Nothing measures the code.** With no TPM there is no PCR policy, so the disk
does not refuse to unlock for a changed binary, an added debug route or an
attached debugger. What protects the build is that the box is an appliance —
signed image, no shell, replaced rather than repaired — and that rests on
trusting whoever holds the machine and the passphrase, which a measured boot
would not. This is the property given up by dropping the TPM, and it is worth
naming rather than discovering.

**A running host has the key in memory.** Encryption at rest is storage; it does
not encrypt RAM. Root on a live box, a DMA-capable port, or a cold-boot attack still
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
egress mint | systemd-creds encrypt --with-key=host --name=identity - /etc/egress/identity.cred
```

The secret half goes down the pipe into the encrypted credential and never
exists as a plaintext file. The
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

**A second DigitalOcean credential exists, and it is not this one.**
`shared-credentials/DO_API_TOKEN` is a DIFFERENT value (different hash) read by
`bot-gateway`. So the two cut independently — deleting visor's key does not
break bot-gateway — but the capability has two names, two stores and two
lifetimes, which is why a rotation misses one and a meter never sees the other.
Both belong at the same custody path; the second is not a blocker, it is a
second migration.

**Measured, and it is the same shape on the model plane.** Nine Secrets across
three namespaces hold vendor LLM keys directly — `enso/enso-secrets`,
`hanzo/bot-secrets`, `hanzo/chat-secrets`, `hanzo/cloud-api-llm-keys`,
`hanzo/cloud-search-config`, `hanzo/gateway-secrets`, `hanzo/hanzo-app-secrets`,
`hanzo/llm-secrets`, `zen/zen-secrets` — carrying OpenAI, Anthropic, Fireworks
and OpenRouter between them. `bot-gateway` holds `HANZO_API_KEY` AND
`FIREWORKS_API_KEY`, so it reaches a vendor by two roads and only one of them is
metered. Every one of those is a call egress never sees, which is the same
sentence as "a call nobody billed".

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
