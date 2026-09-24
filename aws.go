package egress

// aws.go carries AWS.
//
// AWS does not take a bearer. A request is signed (SigV4) with a secret key over
// a scope — service, region, date — and only the signature travels, so egress
// holds the key, signs the request it builds itself, and sends a signature that
// is good for that one request at that one endpoint. The service and region come
// from the endpoint's own name, and the endpoint is one this host admits (-aws)
// or the call is refused.
//
// Custody holds a descriptor, JSON, in one of two forms:
//
//	{"roleArn":"arn:aws:iam::532217001883:role/hanzo-compute"}
//	{"accessKeyId":"AKIA…","secretAccessKey":"…"}
//
// A role is the preferred form, because then no long-lived AWS key exists
// anywhere. Egress assumes it with AssumeRoleWithWebIdentity, presenting its OWN
// Hanzo IAM token — the identity the role trusts — and never the caller's. The
// temporary credentials that buys live in this process's memory, which
// LockMemory pins, and are replaced before they expire.
//
// A role holds no secret, which is why the platform's descriptor may be written
// in the clear. It is also why a role is honoured only from the platform's own
// custody. Every role egress assumes is assumed with the SAME identity, so a
// role that trusts egress cannot tell which tenant egress is acting for; a
// descriptor a caller could write would let any caller name any role that
// trusts egress, the platform's included. So a caller cannot enrol a role, and a
// role found anywhere a caller can write is refused.
//
// A key pair is for an account that cannot trust a web identity. It is spent
// only sealed to this host, and opened for the one call that spends it.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
	"github.com/zap-proto/zip"
)

// amazon is AWS as a custody segment: slug("AWS").
const amazon = "aws"

// endpoint is one AWS API endpoint and the scope a signature for it carries.
type endpoint struct {
	host    string // ec2.us-east-1.amazonaws.com
	service string // ec2
	region  string // us-east-1
}

// endpointForm is <service>.<region>.amazonaws.com. The service is one label of
// letters and digits, because that label is also the signing name: a FIPS or
// dual-stack host spells the service differently from the name it signs with,
// and such a host is refused rather than signed for wrongly.
var endpointForm = regexp.MustCompile(`^([a-z][a-z0-9]*)\.([a-z]{2}(?:-[a-z]+)+-[0-9]+)\.amazonaws\.com$`)

// endpointOf reads the signing scope out of an endpoint's name.
func endpointOf(host string) (endpoint, bool) {
	m := endpointForm.FindStringSubmatch(host)
	if m == nil {
		return endpoint{}, false
	}
	return endpoint{host: host, service: m[1], region: m[2]}, true
}

// admitted is the endpoints this host signs for, by host.
func admitted(hosts []string) map[string]endpoint {
	out := make(map[string]endpoint, len(hosts))
	for _, h := range hosts {
		if at, ok := endpointOf(strings.ToLower(h)); ok {
			out[at.host] = at
		}
	}
	return out
}

// descriptor is what custody holds for one AWS account.
type descriptor struct {
	RoleArn         string `json:"roleArn"`
	AccessKeyID     string `json:"accessKeyId"`
	SecretAccessKey string `json:"secretAccessKey"`
}

var (
	roleForm  = regexp.MustCompile(`^arn:aws(?:-[a-z]+)*:iam::[0-9]{12}:role/[A-Za-z0-9+=,.@_/-]{1,512}$`)
	keyIDForm = regexp.MustCompile(`^[A-Z0-9]{16,128}$`)
)

// errDescriptor says what a descriptor must be and never what one was: a JSON
// parser's error quotes the byte it stopped at, and that byte may be a key's.
var errDescriptor = errors.New(`egress: an aws credential is {"roleArn":"arn:aws:iam::…:role/…"} or {"accessKeyId":"…","secretAccessKey":"…"}`)

// account reads a descriptor. It is strict — one form, no other field, nothing
// after it — because a value that is almost a descriptor is a mistake somebody
// should hear about, not a credential to guess at.
func account(value []byte) (descriptor, error) {
	dec := json.NewDecoder(bytes.NewReader(value))
	dec.DisallowUnknownFields()
	var d descriptor
	if dec.Decode(&d) != nil || dec.More() {
		return descriptor{}, errDescriptor
	}
	switch {
	case d.RoleArn != "" && d.AccessKeyID == "" && d.SecretAccessKey == "" && roleForm.MatchString(d.RoleArn):
		return d, nil
	case d.RoleArn == "" && keyIDForm.MatchString(d.AccessKeyID) &&
		d.SecretAccessKey != "" && !strings.ContainsAny(d.SecretAccessKey, " \t\r\n"):
		return d, nil
	}
	return descriptor{}, errDescriptor
}

// form names which of the two a descriptor is, for the record.
func (d descriptor) form() string {
	if d.RoleArn != "" {
		return "role"
	}
	return "key"
}

// accountRef is where the platform's own AWS account is filed: at the KMS
// store's own coordinate for an org's cloud account, path cloud/aws/<label>,
// name `credential`. The store scopes every read to the org of the identity
// making it — this host's, the platform's — so the org is not a segment here.
func accountRef(label string) string {
	return "cloud/" + amazon + "/" + label + "/credential"
}

// resolveAWS finds the account a principal spends for label, and which custody
// paid. A tenant's own sealed key pair wins, as every provider's own key does.
// Then, for a principal of the platform's own org and a label the configuration
// lists as a platform account, the platform's account.
func (s *Server) resolveAWS(ctx context.Context, p Principal, label string) (descriptor, string, error) {
	own, err := s.custody.read(ctx, ownRef(p, amazon, label))
	if err != nil {
		return descriptor{}, "", err
	}
	if own != "" {
		d, err := account([]byte(own))
		if err != nil {
			return descriptor{}, "", err
		}
		if d.RoleArn != "" {
			return descriptor{}, "", zip.Errorf(http.StatusForbidden,
				"egress: a role is assumed with egress's own identity, so only the platform's custody may name one")
		}
		return d, ScopeUser, nil
	}
	if p.Org != s.cfg.KMSOrg || !s.shares(p, amazon, label) {
		return descriptor{}, "", ErrNoCredential
	}
	ref := accountRef(label)
	raw, err := s.custody.unsealed(ctx, ref)
	if err != nil || raw == nil {
		if err == nil {
			err = ErrNoCredential
		}
		return descriptor{}, "", err
	}
	if _, ok := record(raw); ok {
		opened, err := s.custody.read(ctx, ref)
		if err != nil {
			return descriptor{}, "", err
		}
		d, err := account([]byte(opened))
		return d, ScopeOrg, err
	}
	d, err := account(raw)
	if err != nil {
		return descriptor{}, "", err
	}
	if d.RoleArn == "" {
		return descriptor{}, "", fmt.Errorf("%w: an aws key pair is spent only sealed, and %s is in the clear", ErrNotSealed, ref)
	}
	return d, ScopeOrg, nil
}

// lease is how long an assumed role's credentials last: the shortest AWS
// grants, so what this process holds is worth a quarter of an hour to whoever
// takes it.
const lease = 15 * time.Minute

// early is how long before they expire held credentials are replaced, so a call
// never goes out on credentials that lapse in flight.
const early = 5 * time.Minute

// mostRoles bounds how many assumed roles one replica holds at once.
const mostRoles = 256

// roles holds the credentials assumed roles bought, one per org, account and
// role. It is the one place egress keeps a credential between calls, and what it
// keeps is temporary: the role itself is re-read from custody on every call, so
// a descriptor removed from KMS stops the next call, and what is held here
// expires on its own within a quarter of an hour.
type roles struct {
	mu   sync.Mutex
	held map[string]*assumed
}

// assumed is one role's credentials, replaced before they expire.
type assumed struct {
	cache *aws.CredentialsCache
	used  time.Time
}

// credentials is what signs one call for d: the key pair itself, or what the
// role it names buys.
func (s *Server) credentials(ctx context.Context, p Principal, label string, d descriptor, at endpoint) (aws.Credentials, error) {
	if d.RoleArn == "" {
		return aws.Credentials{AccessKeyID: d.AccessKeyID, SecretAccessKey: d.SecretAccessKey, Source: "egress"}, nil
	}
	key := p.Org + "\x00" + label + "\x00" + d.RoleArn
	now := time.Now()
	s.roles.mu.Lock()
	a, ok := s.roles.held[key]
	if !ok {
		if len(s.roles.held) >= mostRoles {
			for k, old := range s.roles.held {
				if now.Sub(old.used) > lease {
					delete(s.roles.held, k)
				}
			}
		}
		a = &assumed{cache: aws.NewCredentialsCache(s.assume(p, d.RoleArn, label, at.region),
			func(o *aws.CredentialsCacheOptions) { o.ExpiryWindow = early })}
		s.roles.held[key] = a
	}
	a.used = now
	s.roles.mu.Unlock()
	return a.cache.Retrieve(ctx)
}

// errRole is a role that could not be assumed. What the caller is told is the
// code STS answered and nothing it said, because the exchange carried this
// service's own token.
var errRole = errors.New("egress: aws: the account's role was not assumed")

// assume exchanges this service's own IAM token for the role's credentials.
//
// The exchange is unsigned — AssumeRoleWithWebIdentity takes no AWS credential,
// which is the point of it — so the STS client carries none and is built from
// explicit options, never from the environment: nothing here reads
// AWS_ACCESS_KEY_ID, a profile, or the instance metadata service. The session is
// named for the account, which is what CloudTrail shows beside every call.
func (s *Server) assume(p Principal, role, label, region string) aws.CredentialsProviderFunc {
	return func(ctx context.Context) (aws.Credentials, error) {
		token, err := s.self.token(ctx)
		if err != nil {
			s.log.Warn("role", "org", p.Org, "account", label, "role", role, "error", err.Error())
			return aws.Credentials{}, fmt.Errorf("%w: egress's own identity was refused", errRole)
		}
		client := sts.New(sts.Options{
			Region:       region,
			BaseEndpoint: aws.String("https://sts." + region + ".amazonaws.com"),
			HTTPClient:   s.fetcher,
			Credentials:  aws.AnonymousCredentials{},
		})
		out, err := client.AssumeRoleWithWebIdentity(ctx, &sts.AssumeRoleWithWebIdentityInput{
			RoleArn:          aws.String(role),
			RoleSessionName:  aws.String(label),
			WebIdentityToken: aws.String(token),
			DurationSeconds:  aws.Int32(int32(lease / time.Second)),
		})
		if err != nil {
			code := "no answer"
			var api smithy.APIError
			if errors.As(err, &api) {
				code = api.ErrorCode()
			}
			s.log.Warn("role", "org", p.Org, "account", label, "role", role, "refused", code)
			return aws.Credentials{}, fmt.Errorf("%w (%s)", errRole, code)
		}
		c := out.Credentials
		if c == nil || c.AccessKeyId == nil || c.SecretAccessKey == nil || c.SessionToken == nil || c.Expiration == nil {
			return aws.Credentials{}, fmt.Errorf("%w (incomplete answer)", errRole)
		}
		s.log.Info("role", "org", p.Org, "account", label, "role", role, "until", c.Expiration.UTC().Format(time.RFC3339))
		return aws.Credentials{
			AccessKeyID:     *c.AccessKeyId,
			SecretAccessKey: *c.SecretAccessKey,
			SessionToken:    *c.SessionToken,
			Source:          "egress",
			CanExpire:       true,
			Expires:         *c.Expiration,
		}, nil
	}
}

// signed attaches a SigV4 signature for at to a request egress built. The key
// signs and stays; what goes on the request is the signature, the scope, the
// access key's id and, for a role, its session token.
func signed(c aws.Credentials, at endpoint) func(*http.Request, []byte) error {
	return func(r *http.Request, body []byte) error {
		sum := sha256.Sum256(body)
		return v4.NewSigner().SignHTTP(r.Context(), c, r, hex.EncodeToString(sum[:]), at.service, at.region, time.Now().UTC())
	}
}

// secrets are the parts of c that must never leave this process, the id
// included: it is not what signs, but it names the key that does.
func secrets(c aws.Credentials) []string {
	return []string{c.SecretAccessKey, c.SessionToken, c.AccessKeyID}
}

// quoted reports whether an answer carries the key or the session token
// verbatim. AWS never returns either, so an answer that does is not AWS's to
// hand on, and it is refused whole rather than edited.
func quoted(read []byte, c aws.Credentials) bool {
	for _, s := range []string{c.SecretAccessKey, c.SessionToken} {
		if s != "" && bytes.Contains(read, []byte(s)) {
			return true
		}
	}
	return false
}

// action is the Query API action a form body asks for, for the record: the
// path of every EC2 call is "/", so the path alone does not say what was done.
func action(kind string, body []byte) string {
	if !strings.HasPrefix(kind, "application/x-www-form-urlencoded") {
		return ""
	}
	form, err := url.ParseQuery(string(body))
	if err != nil {
		return ""
	}
	a := form.Get("Action")
	if len(a) == 0 || len(a) > 64 || !segment(a) {
		return ""
	}
	return a
}
