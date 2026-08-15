# Deploying egress

Egress runs on a host we provision, not in DOKS. That is a correctness property:
a DO API token reaches every pod, secret and volume in the cluster, and every DO
team member holds one — measured, `kubectl auth can-i get secrets -A
--as-group=do-role-name:Member` answers yes. A credential broker inside that
blast radius has not moved the credential anywhere useful.

## The host

A droplet with a LUKS root whose passphrase is entered by a person at boot and
never stored in any cloud. A snapshot, a detached volume and DO's own password
reset then all yield ciphertext — the last because it must write `/etc/shadow`,
which is inside the encrypted volume.

Unlocking is manual by design. Automating it would put the passphrase somewhere
a cloud API can read, which is the thing being avoided. A reboot needs a human.

```
adduser --system --group --no-create-home egress
install -m0755 egress /usr/local/bin/egress
install -d -m0700 /etc/egress
install -m0400 env /etc/egress/env          # from env.example, filled in
install -m0644 egress.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now egress
```

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
