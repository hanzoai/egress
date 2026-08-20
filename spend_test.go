package egress

import (
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/hanzoai/egress/spend"
)

// listening puts the real server on a real ZAP listener, which is how a caller
// reaches it in production. The two halves are written in one repo and could
// still disagree about the wire; this is what stops that being found in a
// cluster.
func listening(t *testing.T, s *Server) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()
	go func() { _ = s.App().Listen(addr) }()
	t.Cleanup(func() { _ = s.App().Shutdown() })
	waitFor(t, addr)
	return addr
}

// An SDK handed spend.Client makes its calls through egress, and the credential
// is attached there. This is the whole design in one test: the caller writes an
// ordinary HTTP request, the far end sees the key, and the process in the middle
// never held one.
func TestAnSDKSpendsThroughEgress(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 100)

	var saw, path string
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, r *http.Request) {
		saw, path = r.Header.Get("Authorization"), r.URL.RequestURI()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"droplets":[{"id":7}]}`))
	})

	client := spend.Client(spend.Config{
		Network: "tcp", Address: listening(t, s),
		Token:    token(t, key, nil),
		Provider: "DigitalOcean",
	})

	// The base URL is whatever the SDK was configured with. Egress discards the
	// host and uses its own, which is what makes it impossible for a caller to
	// choose the far end — so this one is deliberately not where the request
	// lands.
	resp, err := client.Get("https://api.digitalocean.com/v2/droplets?page=2")
	if err != nil {
		t.Fatalf("the call did not reach egress: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if saw != "Bearer dop_v1_secret" {
		t.Errorf("the cloud got Authorization %q — the credential was not attached at egress", saw)
	}
	if path != "/v2/droplets?page=2" {
		t.Errorf("the cloud got path %q", path)
	}
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d", resp.StatusCode)
	}
	read, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(read) != `{"droplets":[{"id":7}]}` {
		t.Errorf("body = %s", read)
	}
	// An SDK unmarshals the body it was given. If that stopped being the cloud's
	// own bytes, every SDK on this path would break at once.
	var out struct {
		Droplets []struct{ ID int } `json:"droplets"`
	}
	if err := json.Unmarshal(read, &out); err != nil || len(out.Droplets) != 1 || out.Droplets[0].ID != 7 {
		t.Errorf("an SDK could not read the answer: %v — %s", err, read)
	}
}

// A write reaches the cloud with its body, and the cloud's status comes back as
// itself — which is what an SDK checks to decide whether the thing was created.
func TestAnSDKWritesThroughEgress(t *testing.T) {
	s, key := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 100)

	var sent string
	upstream(t, s, "digitalocean", func(w http.ResponseWriter, r *http.Request) {
		read, _ := io.ReadAll(r.Body)
		sent = string(read)
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"droplet":{"id":9}}`))
	})

	client := spend.Client(spend.Config{
		Network: "tcp", Address: listening(t, s),
		Token:    token(t, key, nil),
		Provider: "DigitalOcean",
	})

	resp, err := client.Post("https://api.digitalocean.com/v2/droplets", "application/json",
		strings.NewReader(`{"name":"web-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	if sent != `{"name":"web-1"}` {
		t.Errorf("the cloud got body %q", sent)
	}
	if resp.StatusCode != http.StatusCreated {
		t.Errorf("status = %d, want the cloud's own 201", resp.StatusCode)
	}
}

// Without a token egress refuses, and the refusal reaches the SDK as an error
// rather than as an empty success. A cloud call that silently returns nothing is
// how a fleet appears to have no machines.
func TestAnSDKWithNoTokenIsRefused(t *testing.T) {
	s, _ := serving(t, newStore(map[string]string{
		orgRef(alice, "digitalocean", "default"): "dop_v1_secret",
	}), 100)
	upstream(t, s, "digitalocean", func(http.ResponseWriter, *http.Request) {
		t.Error("an upstream call was made for an unidentified caller")
	})

	client := spend.Client(spend.Config{
		Network: "tcp", Address: listening(t, s), Provider: "DigitalOcean",
	})

	resp, err := client.Get("https://api.digitalocean.com/v2/droplets")
	if err == nil {
		_ = resp.Body.Close()
		t.Fatalf("an unidentified caller was served: %d", resp.StatusCode)
	}
	if !strings.Contains(err.Error(), "refused") {
		t.Errorf("the SDK cannot tell what happened: %v", err)
	}
}
