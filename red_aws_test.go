package egress

import (
	"net/http"
	"testing"

	"github.com/hanzoai/egress/spend"
	"github.com/hanzoai/jwt"
)

// The platform's AWS account is compute's, and only compute's.
//
// IAM's client_credentials grant takes RFC 8707 `resource` from any client with
// no allowlist (iam forge/main internal/oidc/token.go:280-283, jwt.go:395-398),
// and stamps `owner` with the minting application's Organization. So every
// application filed under org hanzo — chat, bot, mcp, sandbox, zrok, console,
// commerce, … — mints a token egress verifies as Org "hanzo", and a user whose
// home org is hanzo gets one through token exchange. Each of them reaches
// resolveAWS's platform branch, which asks only p.Org == KMSOrg.
func TestRedThePlatformAccountIsNotEveryHanzoPrincipals(t *testing.T) {
	for name, bearer := range map[string]func(*testing.T, jwt.Key) string{
		"another hanzo program": func(t *testing.T, key jwt.Key) string { return program(t, key, "hanzo-chat", "hanzo") },
		"the code sandbox":      func(t *testing.T, key jwt.Key) string { return program(t, key, "hanzo-sandbox", "hanzo") },
		"a hanzo person": func(t *testing.T, key jwt.Key) string {
			return token(t, key, func(c *jwt.Claims) { c.Owner, c.Subject = "hanzo", "u-9" })
		},
	} {
		t.Run(name, func(t *testing.T) {
			st := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
			s, key, f, _ := awsServing(t, st)
			code, body, out := fetchedAs(t, s, bearer(t, key), describeInstances())
			if code == http.StatusOK {
				t.Fatalf("%s spent the platform AWS account as hanzo-compute (upstream %d, scope %q): %s",
					name, out.Status, out.Scope, body)
			}
			if n := len(f.seen(ec2Host)); n != 0 {
				t.Fatalf("%s reached EC2 %d times", name, n)
			}
		})
	}
}

// STS is not an endpoint egress signs for. Admitted, it lets a caller call STS
// as the assumed role: AssumeRole answers with a fresh key pair and session
// token in the body, which egress hands back because quoted() looks only for
// the signer's own secret. The configuration check accepts it today, and the
// comment in deploy/env.example is the only thing saying not to.
func TestRedSTSIsNotAnEndpointEgressSignsFor(t *testing.T) {
	c := Config{
		Listen: ":0", Issuer: issuer, JWKS: "https://hanzo.id/jwks", Audience: audience,
		KMS: "zap://kms:9999", KMSOrg: "hanzo", KMSPath: "hanzo/egress", Recipient: aRecipient(),
		RPM: 1, Deadline: 1, IAM: "https://hanzo.id", ClientID: egressID,
		AWS: []string{ec2Host, stsHost},
	}
	if err := c.Check(); err == nil {
		t.Error("a configuration admitting sts.us-east-1.amazonaws.com was accepted")
	}

	st := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
	s, key, f, _ := awsServing(t, st)
	s.amazon = admitted([]string{ec2Host, stsHost}) // what c.Check() let through
	in := spend.Fetch{
		Provider: "AWS", Label: hostedLabel, Method: http.MethodPost, Path: "/",
		Raw:  []byte("Action=AssumeRole&RoleArn=arn%3Aaws%3Aiam%3A%3A532217001883%3Arole%2Fanother&RoleSessionName=x&Version=2011-06-15"),
		Type: "application/x-www-form-urlencoded; charset=utf-8",
		Host: stsHost,
	}
	_, _, _ = fetchedAs(t, s, computeToken(t, key), in)
	for _, c := range f.seen(stsHost) {
		if c.auth != "" {
			t.Fatalf("egress signed a caller's %s to STS as the platform role", c.form.Get("Action"))
		}
	}
}
