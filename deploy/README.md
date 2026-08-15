# Deploying egress

Egress runs on a host you provision, not in a managed Kubernetes cluster. That is
a correctness property: a cloud provider's API token typically reaches every pod,
secret and volume in its managed cluster, and every member of the provider team
holds one. A credential broker inside that blast radius has not moved the
credential anywhere useful.

## The host

**Your own metal, and that is not a preference.** The point of this host is to
sit outside the blast radius of a cloud provider's API token; renting it from
that provider puts it back inside. Unless the provider sells confidential
compute, the choice is not between providers, it is between borrowed hardware
and yours.

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

`--with-key` is the choice, and it is an operator's rather than a code change:

| `--with-key=` | what holds the wrapping key | when |
|---|---|---|
| `host` | `/var/lib/systemd/credential.secret`, on the LUKS root | the default: no special hardware |
| `tpm2` | the TPM, optionally under a PCR policy | when the board has one and measured boot is wanted |
| `auto` | tpm2 where present, host otherwise | a fleet with both |

Egress reads `$CREDENTIALS_DIRECTORY` either way, so it never learns which was
used and nothing in it changes when the choice does. A cloud KMS or a PKCS#11
HSM is the same shape one step out — the wrapping key lives in the HSM and
`Decrypt` is a call — but systemd cannot reach either, so it is an integration
to write rather than a flag to set. It is worth writing where egress runs on GCP
or AWS with an attached identity: the wrapping key is then non-exportable AND
there is no key file on the host at all, which is stronger than the host key
above.

**Nothing is kept, so replicas are interchangeable.** Egress holds no credential
and no session; what it keeps is configuration and a bounded cache. Run as many
as the load wants, behind whatever balancer, and delete a suspect one instead of
investigating it — there is nothing on it to investigate. It does one job:
attach a credential to a described call and return what the upstream said.

**Memory is pinned, so a key cannot be swapped to disk.** The unit grants
`LimitMEMLOCK=infinity` and the process calls `mlockall(MCL_CURRENT|MCL_FUTURE)`
before it opens the store — before the credential exists, because locking after
a secret is in memory locks it too late. Without the grant it refuses to start.
That is deliberate: "best effort" would mean the guarantee holds on some hosts
and not others, with nothing to say which, and the operator learning it from a
forensics report. Swap was the last way a key reached a disk; the unit already
refuses core dumps, mounts no writable path and hides /proc, and this service
writes no file.

**Memory encryption is reported, never assumed.** Pinning keeps a key off the
disk and does nothing about the DRAM, which root on a live box, a DMA-capable
port or a cold-boot attack still reaches. `MemoryEncryption()` reads
`/sys/kernel/coco/status` and reports `sev-snp`, `tdx` or `none` in the boot
line, so a deployment that needs one can be held to it.

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
egress being used. That is what the meter, the per-principal quota and the
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
register the derived identity with KMS under egress's own path. It must not
exist in a cluster Secret, a repo, or CI. Grant that identity read on the
provider credentials and nothing else.

The check that matters: no caller's KMS identity may read the provider paths. A
caller's KMS credentials usually sit in a process environment its siblings
share, so an identity that can read provider keys from there closes nothing.

## Cutover — order is load-bearing

Wherever a provider key is live in more than one place, remove none of them
before egress serves, or every caller 401s.

1. **Serve.** Start egress. `EGRESS_AUDIENCE` set, KMS reachable, credentials
   resolving. It refuses to open a listener without them.
2. **Seal.** Write each provider key into KMS under the egress identity's tree
   (`POST /v1/enroll` — write-only: no route reads one back). Nothing is deleted
   yet; both paths work.
3. **Prove.** Point one caller at egress and confirm a real call round-trips,
   streaming included. Not a health check: a status code is not a working call.
   For a cloud provider, `POST /v1/fetch` with a read of the account answering
   200 is the proof.
4. **Cut.** Repoint the callers. This is a URL change only where the caller
   honours a provider base URL; a client that hardcodes a vendor endpoint keeps
   dialing the vendor with its key in the header while its configuration claims
   otherwise. One place in the caller that authorizes an outbound call makes the
   cut a swap of that one thing.
5. **Delete** every other copy of each key — at its source first: a Secret that a
   KMS operator syncs is rewritten from KMS on its resync interval, so deleting
   the Secret alone accomplishes nothing.
6. **Rotate.** Reissue every key at the vendor. Values that sat in process
   environments and readable Secrets are disclosed, not merely stale; revoke
   rather than replace.

Steps 1-3 are reversible. Step 5 is not, until step 6 completes.

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
