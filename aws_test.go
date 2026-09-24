package egress

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/egress/spend"
	"github.com/hanzoai/jwt"
)

// The hosted account, as the operator filed it.
const (
	ec2Host     = "ec2.us-east-1.amazonaws.com"
	stsHost     = "sts.us-east-1.amazonaws.com"
	iamHost     = "hanzo.id"
	hostedRole  = "arn:aws:iam::532217001883:role/hanzo-compute"
	hostedLabel = "hanzo-compute"
	// egressID and egressSecret are egress's own IAM client credential. The
	// secret carries characters that survive only form-encoding under Basic.
	egressID     = "hanzo-egress"
	egressSecret = "egr+ss%/client-secret"
	// staticID and staticSecret are a key pair an account that cannot trust a
	// web identity is enrolled with.
	staticID     = "AKIASTATICKEY0000001"
	staticSecret = "static/SECRET+key/never-shown-0123456789"
)

// roleDescriptor is the platform's descriptor, in the clear as the operator
// wrote it.
var roleDescriptor = `{"roleArn":"` + hostedRole + `"}`

func staticDescriptor() string {
	return `{"accessKeyId":"` + staticID + `","secretAccessKey":"` + staticSecret + `"}`
}

// awsCall is one request the fake AWS answered.
type awsCall struct {
	host   string
	form   url.Values
	auth   string // the Authorization header, verbatim
	basic  string // the IAM client a token mint authenticated as
	keyID  string // the access key a signed request used
	token  string // X-Amz-Security-Token
	scope  string // region/service of the signature
	failed string // why the fake refused it, if it did
}

// fakeAWS is IAM, STS and EC2 on one TLS server, told apart by Host. Each
// checks what the real one would: IAM the client credential, STS that the web
// identity is a token IAM minted for egress and that the call is unsigned, EC2 a
// SigV4 signature it recomputes itself from the key it knows.
type fakeAWS struct {
	server *httptest.Server

	mu     sync.Mutex
	calls  []awsCall
	tokens map[string]bool   // web identity tokens IAM minted for egress
	keys   map[string]issued // access key id -> what signs with it
	life   time.Duration     // how long the next role credentials last
	refuse string            // an STS error code to answer with, once
	next   int
}

type issued struct {
	secret  string
	session string
	until   time.Time
}

func newFakeAWS(t *testing.T) *fakeAWS {
	t.Helper()
	f := &fakeAWS{
		tokens: map[string]bool{},
		keys:   map[string]issued{staticID: {secret: staticSecret, until: time.Now().Add(24 * time.Hour)}},
		life:   time.Hour,
	}
	f.server = httptest.NewTLSServer(http.HandlerFunc(f.serve))
	t.Cleanup(f.server.Close)
	return f
}

func (f *fakeAWS) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	form, _ := url.ParseQuery(string(body))
	call := awsCall{host: r.Host, form: form, auth: r.Header.Get("Authorization"), token: r.Header.Get("X-Amz-Security-Token")}

	f.mu.Lock()
	defer f.mu.Unlock()
	defer func() { f.calls = append(f.calls, call) }()

	switch r.Host {
	case iamHost:
		user, pass, _ := r.BasicAuth()
		id, _ := url.QueryUnescape(user)
		secret, _ := url.QueryUnescape(pass)
		call.basic = id
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path != "/v1/iam/oauth/token" || id != egressID || secret != egressSecret ||
			form.Get("grant_type") != "client_credentials" || form.Has("resource") {
			call.failed = "iam refused"
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
			return
		}
		f.next++
		tok := fmt.Sprintf("egress-web-identity-%d", f.next)
		f.tokens[tok] = true
		_, _ = fmt.Fprintf(w, `{"access_token":%q,"token_type":"Bearer","expires_in":3600}`, tok)

	case stsHost:
		w.Header().Set("Content-Type", "text/xml")
		switch {
		case call.auth != "":
			call.failed = "sts call was signed"
		case form.Get("Action") != "AssumeRoleWithWebIdentity":
			call.failed = "not AssumeRoleWithWebIdentity"
		case !f.tokens[form.Get("WebIdentityToken")]:
			call.failed = "web identity was not egress's own"
		case form.Get("RoleArn") != hostedRole:
			call.failed = "wrong role"
		case form.Get("RoleSessionName") != hostedLabel:
			call.failed = "wrong session name"
		}
		if n, err := strconv.Atoi(form.Get("DurationSeconds")); err != nil || n < 900 || n > 3600 {
			call.failed = "duration out of range"
		}
		if f.refuse != "" {
			call.failed = f.refuse
			f.refuse = ""
		}
		if call.failed != "" {
			w.WriteHeader(http.StatusForbidden)
			_, _ = fmt.Fprintf(w, `<ErrorResponse><Error><Type>Sender</Type><Code>%s</Code><Message>refused %s</Message></Error><RequestId>1</RequestId></ErrorResponse>`,
				codeFor(call.failed), form.Get("WebIdentityToken"))
			return
		}
		f.next++
		id := fmt.Sprintf("ASIAROLEKEY%09d", f.next)
		key := issued{
			secret:  fmt.Sprintf("role-secret-%d-ABCDEFGHIJKLMNOP", f.next),
			session: fmt.Sprintf("role-session-token-%d-QRSTUVWXYZ", f.next),
			until:   time.Now().Add(f.life).UTC().Truncate(time.Second),
		}
		f.keys[id] = key
		_, _ = fmt.Fprintf(w, `<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><AssumeRoleWithWebIdentityResult><Credentials><AccessKeyId>%s</AccessKeyId><SecretAccessKey>%s</SecretAccessKey><SessionToken>%s</SessionToken><Expiration>%s</Expiration></Credentials><SubjectFromWebIdentityToken>admin/hanzo-egress</SubjectFromWebIdentityToken><AssumedRoleUser><Arn>%s/%s</Arn><AssumedRoleId>AROA:%s</AssumedRoleId></AssumedRoleUser></AssumeRoleWithWebIdentityResult><ResponseMetadata><RequestId>sts-1</RequestId></ResponseMetadata></AssumeRoleWithWebIdentityResponse>`,
			id, key.secret, key.session, key.until.Format(time.RFC3339), hostedRole, hostedLabel, hostedLabel)

	case ec2Host:
		id, scope, err := verify(r, body, func(id string) (string, bool) {
			k, ok := f.keys[id]
			return k.secret, ok
		})
		call.keyID, call.scope = id, scope
		k := f.keys[id]
		switch {
		case err != nil:
			call.failed = err.Error()
		case scope != "us-east-1/ec2":
			call.failed = "signed for " + scope
		case !time.Now().Before(k.until):
			call.failed = "key expired"
		case k.session != call.token:
			call.failed = "session token does not belong to the key"
		}
		w.Header().Set("Content-Type", "text/xml;charset=UTF-8")
		if call.failed != "" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`<Response><Errors><Error><Code>AuthFailure</Code><Message>AWS was not able to validate the provided access credentials</Message></Error></Errors><RequestID>1</RequestID></Response>`))
			return
		}
		_, _ = fmt.Fprintf(w, `<DescribeInstancesResponse xmlns="http://ec2.amazonaws.com/doc/2016-11-15/"><requestId>r-1</requestId><reservationSet/><action>%s</action></DescribeInstancesResponse>`, form.Get("Action"))

	default:
		call.failed = "unknown host " + r.Host
		w.WriteHeader(http.StatusMisdirectedRequest)
	}
}

func codeFor(failed string) string {
	if failed == "AccessDenied" || failed == "InvalidIdentityToken" {
		return failed
	}
	return "AccessDenied"
}

// seen returns the calls answered for host, or every call.
func (f *fakeAWS) seen(host string) []awsCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []awsCall
	for _, c := range f.calls {
		if host == "" || c.host == host {
			out = append(out, c)
		}
	}
	return out
}

// every returns every secret the fake handed out or knows: the tokens IAM
// minted, the role keys and session tokens STS issued, the static secret and
// egress's own client secret.
func (f *fakeAWS) every() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := []string{staticSecret, egressSecret}
	for tok := range f.tokens {
		out = append(out, tok)
	}
	for id, k := range f.keys {
		out = append(out, k.secret)
		if k.session != "" {
			out = append(out, k.session, id)
		}
	}
	return out
}

// verify checks a SigV4 signature the way AWS does, written from the
// specification rather than borrowed from the signer under test: the canonical
// request, the string to sign, the derived key, and a constant-time compare.
func verify(r *http.Request, body []byte, secretOf func(string) (string, bool)) (keyID, scope string, err error) {
	auth := r.Header.Get("Authorization")
	rest, ok := strings.CutPrefix(auth, "AWS4-HMAC-SHA256 ")
	if !ok {
		return "", "", errors.New("unsigned")
	}
	parts := map[string]string{}
	for _, p := range strings.Split(rest, ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(p), "=")
		parts[k] = v
	}
	cred := strings.Split(parts["Credential"], "/")
	if len(cred) != 5 || cred[4] != "aws4_request" {
		return "", "", errors.New("malformed credential")
	}
	keyID, date, region, service := cred[0], cred[1], cred[2], cred[3]
	scope = region + "/" + service
	secret, ok := secretOf(keyID)
	if !ok {
		return keyID, scope, errors.New("unknown key " + keyID)
	}
	stamp := r.Header.Get("X-Amz-Date")
	at, err := time.Parse("20060102T150405Z", stamp)
	if err != nil || !strings.HasPrefix(stamp, date) || time.Since(at).Abs() > 5*time.Minute {
		return keyID, scope, errors.New("bad date")
	}
	signedHeaders := strings.Split(parts["SignedHeaders"], ";")
	for _, must := range []string{"host", "x-amz-date"} {
		if !contains(signedHeaders, must) {
			return keyID, scope, errors.New(must + " is not signed")
		}
	}
	if r.Header.Get("X-Amz-Security-Token") != "" && !contains(signedHeaders, "x-amz-security-token") {
		return keyID, scope, errors.New("session token is not signed")
	}
	var headers strings.Builder
	for _, h := range signedHeaders {
		var v string
		switch h {
		case "host":
			v = r.Host
		case "content-length":
			v = strconv.FormatInt(r.ContentLength, 10)
		default:
			v = strings.Join(strings.Fields(strings.Join(r.Header.Values(h), ",")), " ")
		}
		headers.WriteString(h + ":" + v + "\n")
	}
	q := r.URL.Query()
	names := make([]string, 0, len(q))
	for k := range q {
		names = append(names, k)
	}
	sort.Strings(names)
	var query []string
	for _, k := range names {
		for _, v := range q[k] {
			query = append(query, awsEscape(k)+"="+awsEscape(v))
		}
	}
	sum := sha256.Sum256(body)
	canonical := strings.Join([]string{
		r.Method, r.URL.EscapedPath(), strings.Join(query, "&"),
		headers.String(), parts["SignedHeaders"], hex.EncodeToString(sum[:]),
	}, "\n")
	digest := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + stamp + "\n" + date + "/" + region + "/" + service + "/aws4_request\n" + hex.EncodeToString(digest[:])
	k := mac([]byte("AWS4"+secret), date)
	k = mac(k, region)
	k = mac(k, service)
	k = mac(k, "aws4_request")
	want := hex.EncodeToString(mac(k, toSign))
	if !hmac.Equal([]byte(want), []byte(parts["Signature"])) {
		return keyID, scope, errors.New("signature does not match")
	}
	return keyID, scope, nil
}

func mac(key []byte, data string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(data))
	return h.Sum(nil)
}

func awsEscape(s string) string {
	return strings.ReplaceAll(url.QueryEscape(s), "+", "%20")
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// logged is a log a test can read back.
type logged struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (l *logged) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.Write(p)
}

func (l *logged) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.buf.String()
}

// awsServing is egress admitting the hosted EC2 endpoint, with its own IAM
// identity, over st, and every outbound dial landing on the fake. The certificate
// is still verified — against the fake's own, under the name it was issued for —
// so a request that reached anything else would fail rather than pass.
func awsServing(t *testing.T, st Secrets) (*Server, jwt.Key, *fakeAWS, *logged) {
	t.Helper()
	s, key := servingOver(t, st, 1000, func(c *Config) {
		c.AWS = []string{ec2Host}
		c.IAM = "https://" + iamHost
		c.ClientID = egressID
	})
	f := newFakeAWS(t)
	s.self.secret = func() (string, error) { return egressSecret, nil }

	roots := x509.NewCertPool()
	roots.AddCert(f.server.Certificate())
	transport := s.fetcher.Transport.(*http.Transport)
	transport.TLSClientConfig = &tls.Config{RootCAs: roots, ServerName: "example.com"}
	target := f.server.Listener.Addr().String()
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch addr {
		case iamHost + ":443", stsHost + ":443", ec2Host + ":443":
			return (&net.Dialer{}).DialContext(ctx, network, target)
		}
		return nil, fmt.Errorf("a test tried to reach %s", addr)
	}

	logs := &logged{}
	s.log = slog.New(slog.NewJSONHandler(logs, nil))
	return s, key, f, logs
}

// computeToken is the caller: compute's own program identity, in the platform
// org.
func computeToken(t *testing.T, key jwt.Key) string {
	return program(t, key, "hanzo-visor", "hanzo")
}

// describeInstances is the Fetch the EC2 SDK makes through spend.Client.
func describeInstances() spend.Fetch {
	return spend.Fetch{
		Provider: "AWS", Label: hostedLabel, Method: http.MethodPost, Path: "/",
		Raw:  []byte("Action=DescribeInstances&Version=2016-11-15"),
		Type: "application/x-www-form-urlencoded; charset=utf-8",
		Host: ec2Host,
	}
}

func fetchedAs(t *testing.T, s *Server, bearer string, in spend.Fetch) (int, string, spend.Fetched) {
	t.Helper()
	code, body := ask(t, s, http.MethodPost, "/v1/fetch", bearer, in)
	var out spend.Fetched
	if code == http.StatusOK {
		if err := json.Unmarshal([]byte(body), &out); err != nil {
			t.Fatalf("answer is not a spend.Fetched: %v — %s", err, body)
		}
	}
	return code, body, out
}

// clean fails the test if any secret the fake knows appears in any of texts.
func clean(t *testing.T, f *fakeAWS, texts ...string) {
	t.Helper()
	for _, secret := range f.every() {
		for _, text := range texts {
			if strings.Contains(text, secret) {
				t.Fatalf("%q reached a caller or a log:\n%s", secret, text)
			}
		}
	}
}

// The preferred form, end to end. The platform's descriptor is a role in the
// clear; egress mints its OWN IAM token (client_credentials, no resource),
// presents it to STS unsigned for that role, and signs the EC2 call with what STS
// issued — for the endpoint's own service and region. The caller's token is
// never the web identity, and nothing secret comes back or is logged.
func TestAnAWSRoleIsAssumedWithEgressOwnIdentity(t *testing.T) {
	st := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
	s, key, f, logs := awsServing(t, st)
	caller := computeToken(t, key)

	code, body, out := fetchedAs(t, s, caller, describeInstances())
	if code != http.StatusOK {
		t.Fatalf("code = %d, body %s", code, body)
	}
	if out.Status != http.StatusOK || out.Scope != ScopeOrg {
		t.Fatalf("answer = %+v", out)
	}
	if out.Type != "text/xml;charset=UTF-8" || !bytes.Contains(out.Raw, []byte("<action>DescribeInstances</action>")) {
		t.Fatalf("the XML answer was not carried faithfully: type %q raw %s", out.Type, out.Raw)
	}
	if present(out.Body) {
		t.Errorf("a raw request was also answered in Body: %s", out.Body)
	}

	mints := f.seen(iamHost)
	if len(mints) != 1 || mints[0].basic != egressID || mints[0].failed != "" {
		t.Fatalf("IAM mints = %+v, want one client_credentials grant for %s", mints, egressID)
	}
	exchanges := f.seen(stsHost)
	if len(exchanges) != 1 || exchanges[0].failed != "" {
		t.Fatalf("STS exchanges = %+v, want one accepted", exchanges)
	}
	if web := exchanges[0].form.Get("WebIdentityToken"); web == caller || !strings.HasPrefix(web, "egress-web-identity-") {
		t.Fatalf("the web identity was %q — not egress's own token", web)
	}
	calls := f.seen(ec2Host)
	if len(calls) != 1 || calls[0].failed != "" {
		t.Fatalf("EC2 calls = %+v, want one with a valid signature", calls)
	}
	if !strings.HasPrefix(calls[0].keyID, "ASIAROLEKEY") || calls[0].token == "" {
		t.Fatalf("EC2 was signed with %q (session %q), not the role's credentials", calls[0].keyID, calls[0].token)
	}
	if calls[0].form.Get("Action") != "DescribeInstances" {
		t.Fatalf("the form did not arrive whole: %v", calls[0].form)
	}
	clean(t, f, body, logs.String())
	if !strings.Contains(logs.String(), `"action":"DescribeInstances"`) || !strings.Contains(logs.String(), `"form":"role"`) {
		t.Errorf("the spend was not recorded with its action and form:\n%s", logs)
	}
}

// What a role buys is kept until shortly before it expires: many calls, one
// exchange. Credentials that lapse inside the refresh window are never used
// again, and a fresh token is minted for the exchange that replaces them.
func TestAnAssumedRoleIsReplacedBeforeItExpires(t *testing.T) {
	st := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
	s, key, f, _ := awsServing(t, st)
	caller := computeToken(t, key)

	for range 3 {
		if code, body, _ := fetchedAs(t, s, caller, describeInstances()); code != http.StatusOK {
			t.Fatalf("code = %d, body %s", code, body)
		}
	}
	if n := len(f.seen(stsHost)); n != 1 {
		t.Fatalf("three calls made %d role exchanges, want 1", n)
	}

	// A new account label is a new session, and this one lasts four minutes:
	// inside the five-minute window, so each call replaces it.
	f.mu.Lock()
	f.life = 4 * time.Minute
	f.mu.Unlock()
	s.roles.mu.Lock()
	s.roles.held = map[string]*assumed{}
	s.roles.mu.Unlock()
	before := len(f.seen(stsHost))
	for range 3 {
		if code, body, _ := fetchedAs(t, s, caller, describeInstances()); code != http.StatusOK {
			t.Fatalf("code = %d, body %s", code, body)
		}
	}
	exchanges := f.seen(stsHost)[before:]
	if len(exchanges) != 3 {
		t.Fatalf("credentials inside the refresh window were reused: %d exchanges for three calls", len(exchanges))
	}
	tokens := map[string]bool{}
	for _, e := range exchanges {
		tokens[e.form.Get("WebIdentityToken")] = true
	}
	if len(tokens) != 3 {
		t.Fatalf("a web identity token was presented twice")
	}
	keys := map[string]bool{}
	for _, c := range f.seen(ec2Host)[3:] {
		keys[c.keyID] = true
	}
	if len(keys) != 3 {
		t.Fatalf("three calls were signed with %d keys, want a fresh one each", len(keys))
	}
}

// STS refusing the role is reported by its code and nothing it said, because
// what it said may quote the token egress presented.
func TestARefusedRoleSaysOnlyTheCode(t *testing.T) {
	st := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
	s, key, f, logs := awsServing(t, st)
	f.refuse = "AccessDenied"

	code, body, _ := fetchedAs(t, s, computeToken(t, key), describeInstances())
	if code == http.StatusOK {
		t.Fatalf("a refused role was served: %s", body)
	}
	if !strings.Contains(body, "AccessDenied") {
		t.Errorf("the refusal does not carry STS's code: %s", body)
	}
	if n := len(f.seen(ec2Host)); n != 0 {
		t.Fatalf("EC2 was called %d times without a role", n)
	}
	clean(t, f, body, logs.String())
}

// A key pair is the second form, and the platform's is spent only sealed: in
// the clear it is refused before anything is signed, sealed it signs.
func TestAnAWSKeyPairIsSpentOnlySealed(t *testing.T) {
	t.Run("in the clear", func(t *testing.T) {
		held := newStore(map[string]string{accountRef(hostedLabel): staticDescriptor()})
		store, _ := sealedOver(t, held)
		s, key, f, logs := awsServing(t, store)

		code, body, _ := fetchedAs(t, s, computeToken(t, key), describeInstances())
		if code == http.StatusOK {
			t.Fatalf("a key pair in the clear was spent: %s", body)
		}
		if n := len(f.seen("")); n != 0 {
			t.Fatalf("a refused key pair reached AWS %d times", n)
		}
		clean(t, f, body, logs.String())
	})

	t.Run("sealed", func(t *testing.T) {
		held := newStore(nil)
		store, _ := sealedOver(t, held)
		if err := store.PutSecret(context.Background(), accountRef(hostedLabel), []byte(staticDescriptor())); err != nil {
			t.Fatal(err)
		}
		if strings.Contains(held.at(accountRef(hostedLabel)), staticSecret) {
			t.Fatal("the store holds the key in the clear")
		}
		s, key, f, logs := awsServing(t, store)

		code, body, out := fetchedAs(t, s, computeToken(t, key), describeInstances())
		if code != http.StatusOK || out.Status != http.StatusOK {
			t.Fatalf("code = %d, body %s", code, body)
		}
		calls := f.seen(ec2Host)
		if len(calls) != 1 || calls[0].failed != "" || calls[0].keyID != staticID || calls[0].token != "" {
			t.Fatalf("EC2 calls = %+v, want one signed with the static key", calls)
		}
		if n := len(f.seen(stsHost)) + len(f.seen(iamHost)); n != 0 {
			t.Fatalf("a key pair made %d identity calls", n)
		}
		clean(t, f, body, logs.String())
	})

	t.Run("a role, sealed", func(t *testing.T) {
		held := newStore(nil)
		store, _ := sealedOver(t, held)
		if err := store.PutSecret(context.Background(), accountRef(hostedLabel), []byte(roleDescriptor)); err != nil {
			t.Fatal(err)
		}
		s, key, f, _ := awsServing(t, store)
		if code, body, _ := fetchedAs(t, s, computeToken(t, key), describeInstances()); code != http.StatusOK {
			t.Fatalf("a sealed role was refused: %d %s", code, body)
		}
		if calls := f.seen(ec2Host); len(calls) != 1 || calls[0].failed != "" {
			t.Fatalf("EC2 calls = %+v", calls)
		}
	})

	t.Run("a role in the clear, under the seal", func(t *testing.T) {
		held := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
		store, _ := sealedOver(t, held)
		s, key, f, _ := awsServing(t, store)
		if code, body, _ := fetchedAs(t, s, computeToken(t, key), describeInstances()); code != http.StatusOK {
			t.Fatalf("the platform's role was refused: %d %s", code, body)
		}
		if calls := f.seen(ec2Host); len(calls) != 1 || calls[0].failed != "" {
			t.Fatalf("EC2 calls = %+v", calls)
		}
	})
}

// A tenant's own key pair, enrolled through egress, is spent for that tenant
// and paid as theirs.
func TestATenantsOwnAWSKeyPairIsSpentForThem(t *testing.T) {
	held := newStore(nil)
	store, _ := sealedOver(t, held)
	s, key, f, logs := awsServing(t, store)
	caller := token(t, key, nil) // alice, org acme

	code, body := ask(t, s, http.MethodPost, "/v1/enroll", caller, Enroll{Provider: "AWS", Label: "mine", Key: staticDescriptor()})
	if code != http.StatusOK {
		t.Fatalf("enroll = %d %s", code, body)
	}
	in := describeInstances()
	in.Label = "mine"
	code, body, out := fetchedAs(t, s, caller, in)
	if code != http.StatusOK || out.Scope != ScopeUser {
		t.Fatalf("code = %d, scope %q, body %s", code, out.Scope, body)
	}
	if calls := f.seen(ec2Host); len(calls) != 1 || calls[0].keyID != staticID || calls[0].failed != "" {
		t.Fatalf("EC2 calls = %+v", calls)
	}
	clean(t, f, body, logs.String())
}

// The confused deputy. Every role egress assumes is assumed as egress, so a role
// named anywhere a caller can write would let that caller have egress assume
// any role that trusts it. Enrolment refuses one, a role found at a caller's own
// path is refused, and the platform's account is not another org's to spend.
func TestARoleIsNeverTakenFromACaller(t *testing.T) {
	t.Run("enrol", func(t *testing.T) {
		st := newStore(nil)
		s, key, _, _ := awsServing(t, st)
		code, body := ask(t, s, http.MethodPost, "/v1/enroll", token(t, key, nil),
			Enroll{Provider: "AWS", Label: hostedLabel, Key: roleDescriptor})
		if code != http.StatusForbidden {
			t.Fatalf("a role was enrolled: %d %s", code, body)
		}
		if len(st.held) != 0 {
			t.Fatalf("a refused enrolment wrote %v", st.held)
		}
	})

	t.Run("planted at a caller's own path", func(t *testing.T) {
		st := newStore(map[string]string{ownRef(alice, amazon, hostedLabel): roleDescriptor})
		s, key, f, _ := awsServing(t, st)
		code, body, _ := fetchedAs(t, s, token(t, key, nil), describeInstances())
		if code != http.StatusForbidden {
			t.Fatalf("a role at a caller's own path = %d %s", code, body)
		}
		if n := len(f.seen("")); n != 0 {
			t.Fatalf("a planted role reached IAM, STS or EC2 %d times", n)
		}
	})

	t.Run("another org", func(t *testing.T) {
		st := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
		s, key, f, _ := awsServing(t, st)
		code, body, _ := fetchedAs(t, s, program(t, key, "their-app", "acme"), describeInstances())
		if code == http.StatusOK {
			t.Fatalf("another org spent the platform's account: %s", body)
		}
		if n := len(f.seen("")); n != 0 {
			t.Fatalf("another org's call reached AWS %d times", n)
		}
	})
}

// Only an endpoint this host admits is signed for, and only an AWS call names
// one. Nothing is read from custody for a request that is refused here.
func TestOnlyAnAdmittedAWSEndpointIsSigned(t *testing.T) {
	st := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
	s, key, f, _ := awsServing(t, st)
	caller := computeToken(t, key)

	for _, host := range []string{"", "ec2.us-west-2.amazonaws.com", "sts.us-east-1.amazonaws.com",
		"evil.example", "ec2.us-east-1.amazonaws.com.evil.example", "127.0.0.1", "EC2.US-EAST-1.AMAZONAWS.COM:444"} {
		in := describeInstances()
		in.Host = host
		if code, body, _ := fetchedAs(t, s, caller, in); code == http.StatusOK {
			t.Errorf("host %q was served: %s", host, body)
		}
	}
	for _, path := range []string{"//evil.example/", "https://evil.example/", "/\\evil.example"} {
		in := describeInstances()
		in.Path = path
		if code, body, _ := fetchedAs(t, s, caller, in); code == http.StatusOK {
			t.Errorf("path %q was served: %s", path, body)
		}
	}
	dig := spend.Fetch{Provider: "DigitalOcean", Method: "GET", Path: "/v2/droplets", Host: ec2Host}
	if code, body, _ := fetchedAs(t, s, caller, dig); code == http.StatusOK {
		t.Errorf("a bearer cloud was sent to a host the caller named: %s", body)
	}
	if n := len(f.seen("")); n != 0 {
		t.Fatalf("a refused request reached AWS %d times", n)
	}
	if st.count() != 0 {
		t.Fatalf("a refused request read custody %d times", st.count())
	}
}

// A descriptor that is not one is refused, and the refusal never quotes it: a
// JSON parser names the byte it stopped at, and that byte may be a key's.
func TestADescriptorIsReadStrictlyAndNeverQuoted(t *testing.T) {
	for name, value := range map[string]string{
		"truncated":   `{"accessKeyId":"` + staticID + `","secretAccessKey":"` + staticSecret,
		"both forms":  `{"roleArn":"` + hostedRole + `","accessKeyId":"` + staticID + `","secretAccessKey":"` + staticSecret + `"}`,
		"extra field": `{"accessKeyId":"` + staticID + `","secretAccessKey":"` + staticSecret + `","sessionToken":"x"}`,
		"half a pair": `{"accessKeyId":"` + staticID + `"}`,
		"not a role":  `{"roleArn":"arn:aws:iam::532217001883:user/` + staticSecret + `"}`,
		"trailing":    `{"roleArn":"` + hostedRole + `"}` + staticSecret,
		"bare secret": staticSecret,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := account([]byte(value))
			if err == nil {
				t.Fatalf("%s was read as a descriptor", name)
			}
			if strings.Contains(err.Error(), staticSecret[:6]) || strings.Contains(err.Error(), "SECRET") {
				t.Fatalf("the refusal quoted the value: %v", err)
			}

			st := newStore(map[string]string{ownRef(alice, amazon, hostedLabel): value})
			s, key, f, logs := awsServing(t, st)
			code, body, _ := fetchedAs(t, s, token(t, key, nil), describeInstances())
			if code == http.StatusOK {
				t.Fatalf("served: %s", body)
			}
			clean(t, f, body, logs.String())
		})
	}
	for _, good := range []string{roleDescriptor, staticDescriptor(), " " + roleDescriptor + "\n"} {
		if _, err := account([]byte(good)); err != nil {
			t.Errorf("account(%s) = %v", good, err)
		}
	}
}

// The configuration refuses what it cannot sign for, and a role path without an
// identity to assume it with.
func TestAnAWSConfigurationIsChecked(t *testing.T) {
	base := func() Config {
		return Config{
			Listen: ":0", Issuer: issuer, JWKS: "https://hanzo.id/jwks", Audience: audience,
			KMS: "zap://kms:9999", KMSOrg: "hanzo", KMSPath: "hanzo/egress", Recipient: aRecipient(),
			RPM: 1, Deadline: 1, IAM: "https://hanzo.id", ClientID: egressID, AWS: []string{ec2Host},
		}
	}
	if err := func() error { c := base(); return c.Check() }(); err != nil {
		t.Fatalf("the hosted configuration was refused: %v", err)
	}
	for name, edit := range map[string]func(*Config){
		"not amazonaws":     func(c *Config) { c.AWS = []string{"ec2.us-east-1.evil.example"} },
		"no region":         func(c *Config) { c.AWS = []string{"ec2.amazonaws.com"} },
		"fips":              func(c *Config) { c.AWS = []string{"ec2-fips.us-east-1.amazonaws.com"} },
		"a url":             func(c *Config) { c.AWS = []string{"https://ec2.us-east-1.amazonaws.com"} },
		"no identity":       func(c *Config) { c.ClientID = "" },
		"no iam":            func(c *Config) { c.IAM = "" },
		"cleartext iam":     func(c *Config) { c.IAM = "http://hanzo.id" },
		"an uppercase host": func(c *Config) { c.AWS = []string{"EC2.us-east-1.amazonaws.com"} },
	} {
		t.Run(name, func(t *testing.T) {
			c := base()
			edit(&c)
			if err := c.Check(); err == nil {
				t.Fatal("accepted")
			}
		})
	}
	for host, want := range map[string]endpoint{
		ec2Host:                                {host: ec2Host, service: "ec2", region: "us-east-1"},
		"ec2.us-gov-west-1.amazonaws.com":      {host: "ec2.us-gov-west-1.amazonaws.com", service: "ec2", region: "us-gov-west-1"},
		"lightsail.eu-central-1.amazonaws.com": {host: "lightsail.eu-central-1.amazonaws.com", service: "lightsail", region: "eu-central-1"},
	} {
		if got, ok := endpointOf(host); !ok || got != want {
			t.Errorf("endpointOf(%q) = %+v, %v", host, got, ok)
		}
	}
}

// Through the real listener, the way compute reaches it: an SDK-shaped form
// POST handed to spend.Client comes back as the XML AWS answered, with its
// Content-Type, and the caller held nothing that signs.
func TestAnAWSCallThroughSpendComesBackAsAWSAnsweredIt(t *testing.T) {
	st := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
	s, key, f, _ := awsServing(t, st)

	client := spend.Client(spend.Config{
		Network: "tcp", Address: listening(t, s),
		Token:    computeToken(t, key),
		Provider: "AWS", Account: hostedLabel,
	})
	resp, err := client.Post("https://"+ec2Host+"/", "application/x-www-form-urlencoded; charset=utf-8",
		strings.NewReader("Action=DescribeInstances&Version=2016-11-15"))
	if err != nil {
		t.Fatalf("the call did not reach egress: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	read, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Content-Type") != "text/xml;charset=UTF-8" {
		t.Fatalf("status %d type %q body %s", resp.StatusCode, resp.Header.Get("Content-Type"), read)
	}
	if !bytes.HasPrefix(read, []byte("<DescribeInstancesResponse")) {
		t.Fatalf("body = %s", read)
	}
	if calls := f.seen(ec2Host); len(calls) != 1 || calls[0].failed != "" {
		t.Fatalf("EC2 calls = %+v", calls)
	}
	clean(t, f, string(read))
}

// Egress never answers to its own identity. The token it shows STS carries the
// audience it accepts, so a copy of one presented here is refused before
// anything is read — on a route and on a session alike.
func TestEgressOwnTokenIsNotACaller(t *testing.T) {
	st := newStore(map[string]string{accountRef(hostedLabel): roleDescriptor})
	s, key, f, _ := awsServing(t, st)
	own := program(t, key, egressID, "hanzo")

	if code, body, _ := fetchedAs(t, s, own, describeInstances()); code != http.StatusUnauthorized {
		t.Fatalf("egress's own token was served: %d %s", code, body)
	}
	if _, err := s.caller(context.Background(), "Bearer "+own); err == nil {
		t.Fatal("a session would be opened for egress's own token")
	}
	if n := len(f.seen("")) + st.count(); n != 0 {
		t.Fatalf("egress's own token reached custody or AWS %d times", n)
	}
	// Another program of the same org is still a caller.
	if code, body, _ := fetchedAs(t, s, computeToken(t, key), describeInstances()); code != http.StatusOK {
		t.Fatalf("compute was refused: %d %s", code, body)
	}
}
