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
# on the host, once per credential — the plaintext never lands on disk
systemd-creds encrypt --with-key=tpm2 --tpm2-pcrs=7+11 - /etc/egress/creds/<name>
# the unit receives it decrypted into its own credential directory, memory only
LoadCredentialEncrypted=<name>:/etc/egress/creds/<name>
```

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

**Egress can always spend.** Custody stops a key being taken; it does not stop
the door being used. That is what the meter, the per-principal quota and the
vendor-side cap are for, and they remain load-bearing rather than decorative.

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
4. **Cut.** Repoint callers. `OPENROUTER_URL` is already a plain env value in
   cloud's Deployment, so this is a URL change, not a new flag.
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
