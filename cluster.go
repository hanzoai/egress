package egress

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Where the kubelet places this pod's identity and the cluster's certificate
// authority. Both are tmpfs, written by the kubelet, and the token is rotated
// under us — which is why it is read at use rather than at startup.
const (
	accountDir = "/var/run/secrets/kubernetes.io/serviceaccount"
	caFile     = accountDir + "/ca.crt"
	tokenFile  = accountDir + "/token"
)

// Cluster returns a client that trusts the cluster's certificate authority and
// presents this pod's own identity.
//
// It exists for one call: asking the cluster to authenticate a caller's token.
// The API server answers that for an identity it knows, so egress must say who
// it is in order to learn who anyone else is.
//
// It is deliberately NOT the client used to reach KMS or a vendor. A client that
// attaches this pod's cluster identity should only ever talk to the cluster.
func Cluster() (*http.Client, error) {
	pem, err := os.ReadFile(caFile)
	if err != nil {
		return nil, fmt.Errorf("cluster: read authority: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("cluster: authority is not a certificate")
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &identified{
			base: &http.Transport{
				TLSClientConfig:     &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
				TLSHandshakeTimeout: 10 * time.Second,
			},
		},
	}, nil
}

// identified attaches this pod's current token to each request. The kubelet
// rewrites that file as the token nears expiry, so it is read per request rather
// than captured once — a token cached at startup stops working within the hour.
type identified struct{ base http.RoundTripper }

func (i *identified) RoundTrip(r *http.Request) (*http.Response, error) {
	token, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("cluster: read identity: %w", err)
	}
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+strings.TrimSpace(string(token)))
	return i.base.RoundTrip(r)
}
