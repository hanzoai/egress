# Using egress

Egress answers a request for a **call**, never for a key. A caller describes the
request it wants made; egress attaches the credential and returns what the
upstream said. The credential is never in the caller, never in its environment,
and never on the cluster.

```
your service ──asks for a call──▶ egress ──holds the key──▶ OpenAI / Anthropic /
             ◀──── response ─────        (KMS custody)       OpenRouter / DO / …
```

Two consequences worth having in mind before anything else:

- **A stolen caller credential buys metered calls through our own meter** — rate
  limited, attributed, audited, revocable in one place — rather than a vendor
  bearer that spends without limit, off our network, invisibly.
- **Reading a caller pod yields nothing that spends.** That is the property; if
  a design still needs the key locally, it has not adopted egress, it has moved
  the key.

## Calling it from Go

Every SDK worth using takes an `*http.Client` — `godo.NewClient(c)`,
`hcloud.WithHTTPClient(c)`, and the OpenAI/Anthropic clients likewise — so this
is a transport swap, not a rewrite:

```go
import "github.com/hanzoai/egress/spend"

hc := spend.Client(spend.Config{
    Network:  "tcp",                  // or "unix"
    Address:  "egress.hanzo.ai:9653", // or /run/hanzo/egress.sock
    Token:    token,                  // see below — an IAM access token
    Provider: "OpenAI",               // which upstream to spend at
    Account:  "",                     // "" = the only account for that provider
    Deadline: time.Minute,
})
```

The request's host is discarded: only the method, path, query, headers and body
travel. Egress decides which upstream that is from `Provider`, because an address
is not what makes an upstream payable.

## Reaching a database

A database is not a request and an answer — you open a connection and keep it —
so what egress brokers there is the whole session. The swap is the same shape
one layer down: your driver is unchanged and the URL comes from the SDK.

```go
import "github.com/hanzoai/egress/spend"

url := spend.Session(spend.Config{
    Network:  "unix",                          // or "tcp"
    Address:  "/run/hanzo/.s.PGSQL.5432",      // what egress bound
    Token:    token,                           // the same IAM access token
    Provider: "sql",                           // which base
    Database: "books",
    Deadline: 10 * time.Second,
})
pool, err := pgxpool.New(ctx, url)
```

What that builds is an ordinary connection URL, so a service that reads
`DATABASE_URL` needs no code at all:

```
postgres://sql:<IAM access token>@/books?host=/run/hanzo&sslmode=disable
```

**The password field carries your IAM token, not a database password.** A
postgres client has one field for a secret, so that is the field it travels in,
and egress verifies it exactly as it verifies a bearer on any other route. Your
service holds an identity that expires; it never holds a database password.

Two consequences to design for:

- **A session ends when the token does.** That is the property — a connection
  that outlived its authorization is one nobody re-authorized — so build the URL
  where your pool opens a connection rather than once at boot. `pgxpool` has
  `BeforeConnect`; `database/sql` has a connector.
- **`sslmode=disable` is on the leg to egress and not on the leg to the
  database.** Egress reaches a database that is not ours over TLS, verified,
  with no setting that says otherwise. Put the egress socket where only your
  service can reach it.

`Provider` names the base. `sql` is hanzo-sql and is reached with no credential
at all — egress connects over the trust between it and the base, and presents
your **org** as the database role. Any other name is looked up in your own
custody: enrol the whole connection URL once and egress dials it with the
credential attached.

```
POST /v1/enroll  {"provider":"analytics","key":"postgres://reader:…@db.example:5432/facts"}
```

That URL must name a host on the public internet. A sealed origin naming a
loopback or private address is refused, because egress would otherwise be a
tunnel to whatever answers there.

## Identifying yourself

`Token` is an **IAM access token**, not a credential invented for egress. Egress
verifies it exactly as every service verifies a caller: `iss` against the issuer,
`aud` against the audience, signature against the published JWKS.

Mint it from the identity your service already has — its `clientId` and
`clientSecret` — and scope it to egress with RFC 8707 `resource`:

```
POST https://hanzo.id/v1/iam/oauth/token
Authorization: Basic base64(clientId:clientSecret)      # client_secret_basic
grant_type=client_credentials&resource=hanzo-egress
```

Hold the result until shortly before it expires and mint again; replace it early,
because a token that dies in flight is a 401 the caller cannot tell from a
revoked identity. `hanzoai/visor` does this in `egress_identity.go` — copy that
shape rather than inventing a second one.

**Do not put a long-lived bearer in a config value.** It does not expire, nobody
rotates it, and it says nothing about who is calling — which is the one question
egress exists to answer before it spends money.

## Configuring an instance

Every option is a flag with an environment fallback, so an instance is described
entirely by its unit file. There is no orchestrator to ask.

| flag | env | default | what it decides |
|---|---|---|---|
| `-listen` | `EGRESS_LISTEN` | `:9653` | inbound ZAP address. Bind to the interface callers reach, never `0.0.0.0` on a public host. |
| `-issuer` | `EGRESS_ISSUER` | `https://hanzo.id` | the `iss` every token must name |
| `-jwks` | `EGRESS_JWKS` | — | where that issuer publishes its keys. Under the IAM prefix, not the host root. |
| `-audience` | `EGRESS_AUDIENCE` | — | the `aud` a token must carry. **No default on purpose**: a service accepting any audience accepts a token minted for a different app. |
| `-kms` | `EGRESS_KMS` | — | credential store. `zap://` from inside the cluster, `https://` from outside. |
| `-kms-org` | `EGRESS_KMS_ORG` | `hanzo` | tenant holding the custody tree |
| `-kms-path` | `EGRESS_KMS_PATH` | `hanzo/egress` | this service's own identity path |
| `-recipient` | `EGRESS_RECIPIENT` | — | this host's PUBLIC sealing key, `age1pq1…`. Public by construction — whoever holds it can seal a credential and open none. |
| `-iam` | `EGRESS_IAM` | — | IAM endpoint, for the https store transport |
| `-client-id` | `EGRESS_CLIENT_ID` | — | this service's machine identity. An identifier, not a secret. |
| `-postgres` | `EGRESS_POSTGRES` | — | where database clients connect: `/run/hanzo/.s.PGSQL.5432` or `host:port`. Empty brokers no sessions. The caller's token crosses this leg, so keep it on a socket or a link you trust. |
| `-rpm` | `EGRESS_RPM` | `600` | calls per minute per principal |
| `-deadline` | `EGRESS_DEADLINE` | `5m` | one upstream call's bound |

Secrets are never flags or environment variables. The mnemonic, the sealing
identity and the store's client secret arrive as systemd credentials:

```
systemd-creds encrypt --with-key=host --name=identity - /etc/egress/identity.cred
LoadCredentialEncrypted=identity:/etc/egress/identity.cred
```

`--with-key` is `host` (default, no special hardware), `tpm2` (a board that has
one, optionally under a PCR policy) or `auto`. Egress reads
`$CREDENTIALS_DIRECTORY` either way and never learns which was used.

## What one instance guarantees

- **Nothing is kept.** No credential, no session; what it holds is configuration
  and a bounded cache. So replicas are interchangeable: run as many as the load
  wants behind any balancer, and delete a suspect one rather than investigate it.
- **Nothing reaches disk.** It writes no file, refuses core dumps, mounts no
  writable path, and pins every page with `mlockall(MCL_CURRENT|MCL_FUTURE)`
  before the store opens — so a key cannot be paged to swap. Without
  `LimitMEMLOCK=infinity` it refuses to start rather than serve without that.
- **Memory encryption is reported, not assumed.** The boot line names `sev-snp`,
  `tdx` or `none`. Pinning keeps a key off the disk and does nothing about DRAM.
- **It does one job.** Attach a credential to a described call, return the answer,
  meter it. Anything else belongs somewhere else.

## Scaling

Stateless, so horizontal. Put N behind a balancer; a caller's token is verified
against the issuer's JWKS by whichever instance answers, and custody is the
store's rather than the instance's. There is no sticky session to preserve and no
warm cache worth keeping — a new instance is useful the moment it is listening.

## Adding an upstream

Egress already knows where each cloud it can pay for answers; that is a fact
about the upstream, not a choice a host makes. Set `EGRESS_URLS` only to MOVE one
— a regional or sovereign endpoint:

```
EGRESS_URLS=digitalocean=https://api.digitalocean.com
```

It cannot admit an upstream egress cannot pay for, because an address is not what
makes one payable. A malformed entry refuses to start.

A base of ours moves the same way, and is spelled as an address rather than a
URL because there is nobody to be in it and nothing to prove — which is the
whole of what makes it a base of ours. That is also what lets it name a socket,
which is how a co-located egress reaches `hanzo-sql` with no `pg_hba` change at
all:

```
EGRESS_URLS=sql=/var/run/postgresql
EGRESS_URLS=sql=hanzo-sql.hanzo.svc.cluster.local:5432
```

## Cutover, and why the order is load-bearing

Every provider key in the estate is live in more than one place. Remove one
before egress serves and the fleet 401s. See `deploy/README.md` for the full
sequence; the short of it is: **serve → seal → prove → cut → revoke**, and
"prove" means a real call round-tripping, streaming included. A status code is
not a working call.
