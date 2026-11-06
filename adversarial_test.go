package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanzoai/egress/spend"
	"github.com/hanzoai/jwt"
	"github.com/zap-proto/zip"
)

// syncBuf is a concurrency-safe buffer for capturing structured audit logs under -race.
type syncBuf struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuf) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuf) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// TestAdversarialTenantAndWorkloadIsolationUnderExhaustion proves P1 #3:
// scoping the in-flight ceiling by organization and workload alongside the
// global ceiling prevents one noisy or malicious tenant/workload from
// exhausting broker capacity for other tenants or sibling workloads.
func TestAdversarialTenantAndWorkloadIsolationUnderExhaustion(t *testing.T) {
	evilWorker1 := Principal{Org: "evil", Kind: Persons, Name: "u-evil-1"}
	evilWorker2 := Principal{Org: "evil", Kind: Persons, Name: "u-evil-2"}
	evilWorker3 := Principal{Org: "evil", Kind: Persons, Name: "u-evil-3"}
	st := newStore(map[string]string{
		orgRef(evilWorker1, "dummy", "default"): "sk-evil-org-key",
		orgRef(alice, "dummy", "default"):       "sk-acme-org-key",
	})
	s, key := serving(t, st, 1000)
	// Configure tight per-org (2) and per-workload (1) limits with a larger global ceiling (8).
	s.flights = newFlights(8, 2, 1)

	// Worker 1 acquires its 1 allowed per-workload slot.
	rel1, ok := s.acquireCall(evilWorker1)
	if !ok {
		t.Fatal("evilWorker1 first slot was refused")
	}
	defer rel1()

	// A second concurrent call from evilWorker1 is refused by the per-workload cap (1),
	// before custody is ever read.
	evilTok1 := token(t, key, func(c *jwt.Claims) { c.Owner = "evil"; c.Subject = "u-evil-1"; c.Id = "u-evil-1" })
	_, body := ask(t, s, http.MethodPost, "/v1/call", evilTok1, call())
	if !strings.Contains(body, "too many calls in flight") {
		t.Fatalf("per-workload ceiling did not refuse second call from evilWorker1: %s", body)
	}
	if st.count() != 0 {
		t.Fatalf("custody was read %d times while per-workload ceiling was full", st.count())
	}

	// Worker 2 in the same org ("evil") is still admitted because per-org cap is 2.
	rel2, ok := s.acquireCall(evilWorker2)
	if !ok {
		t.Fatal("evilWorker2 slot was refused by sibling workload")
	}
	defer rel2()

	// Worker 3 in "evil" is now refused by the per-organization cap (2), before custody is read.
	if _, ok := s.acquireCall(evilWorker3); ok {
		t.Fatal("evilWorker3 exceeded per-organization ceiling")
	}
	evilTok3 := token(t, key, func(c *jwt.Claims) { c.Owner = "evil"; c.Subject = "u-evil-3"; c.Id = "u-evil-3" })
	_, body = ask(t, s, http.MethodPost, "/v1/call", evilTok3, call())
	if !strings.Contains(body, "too many calls in flight") {
		t.Fatalf("per-organization ceiling did not refuse evilWorker3: %s", body)
	}
	if st.count() != 0 {
		t.Fatalf("custody was read %d times while per-org ceiling was full", st.count())
	}

	// Meanwhile, tenant "acme" is completely unaffected and completes its call normally.
	acmeTok := token(t, key, nil)
	code, body := ask(t, s, http.MethodPost, "/v1/call", acmeTok, call())
	if code != http.StatusOK || !strings.Contains(body, "event: meter") {
		t.Fatalf("saturated evil org blocked acme org: %d %s", code, body)
	}

	// Releasing evilWorker1's slot immediately allows evilWorker3 to proceed.
	rel1()
	code, body = ask(t, s, http.MethodPost, "/v1/call", evilTok3, call())
	if code != http.StatusOK || !strings.Contains(body, "event: meter") {
		t.Fatalf("evilWorker3 did not succeed after slot release: %d %s", code, body)
	}
}

// TestAdversarialPostgresSessionPerOrgAndWorkloadIsolation proves P1 #3 for
// long-lived brokered Postgres sessions: one tenant saturating its session cap
// cannot block another tenant from opening database sessions.
func TestAdversarialPostgresSessionPerOrgAndWorkloadIsolation(t *testing.T) {
	base := answering(t, "", nil)
	s, key := serving(t, newStore(nil), 1000)
	ours(s, base)
	s.sessionFlights = newFlights(16, 2, 1)
	addr := brokering(t, s)

	evil1 := token(t, key, func(c *jwt.Claims) { c.Owner = "evil"; c.Subject = "u-evil-1"; c.Id = "u-evil-1" })
	evil2 := token(t, key, func(c *jwt.Claims) { c.Owner = "evil"; c.Subject = "u-evil-2"; c.Id = "u-evil-2" })
	evil3 := token(t, key, func(c *jwt.Claims) { c.Owner = "evil"; c.Subject = "u-evil-3"; c.Id = "u-evil-3" })
	acme := token(t, key, nil)

	conn1, err := opening(t, addr, "sql", "books", evil1)
	if err != nil {
		t.Fatalf("evil1 first session refused: %v", err)
	}
	defer func() { _ = conn1.Close(context.Background()) }()

	// Second concurrent session from evil1 exceeds per-workload cap (1).
	if dup, err := opening(t, addr, "sql", "books", evil1); err == nil {
		_ = dup.Close(context.Background())
		t.Fatal("evil1 opened a second concurrent session past per-workload limit")
	}

	// evil2 opens the second slot for org "evil" (per-org cap = 2).
	conn2, err := opening(t, addr, "sql", "books", evil2)
	if err != nil {
		t.Fatalf("evil2 session refused: %v", err)
	}
	defer func() { _ = conn2.Close(context.Background()) }()

	// evil3 exceeds org "evil"'s cap (2) and is refused.
	if third, err := opening(t, addr, "sql", "books", evil3); err == nil {
		_ = third.Close(context.Background())
		t.Fatal("evil3 opened a third concurrent session past per-organization limit")
	}

	// Tenant "acme" still opens and uses a session without interference.
	acmeConn, err := opening(t, addr, "sql", "books", acme)
	if err != nil {
		t.Fatalf("saturated evil org blocked acme session: %v", err)
	}
	if got := answer(t, acmeConn, "select 1"); got != "the base answered" {
		t.Fatalf("acme session carried %q", got)
	}
}

// TestAdversarialPerRunAuditLogsCarryDecisionDestinationAndRedactedIdentity
// proves P1 #5: every permitted or blocked call emits a structured audit log
// with destination, policy decision ("allow" or "deny"), run ID, and a
// deterministically redacted principal identity — never raw subject IDs or secrets.
func TestAdversarialPerRunAuditLogsCarryDecisionDestinationAndRedactedIdentity(t *testing.T) {
	const (
		rawSubject = "u-sensitive-subject-identifier-987654"
		secretKey  = "sk-live-AuditSecretValue99887766"
		runID      = "run-adversarial-audit-42"
	)

	var logs syncBuf
	cloudUpstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer cloudUpstream.Close()

	st := newStore(map[string]string{
		orgRef(alice, "dummy", "default"):        secretKey,
		orgRef(alice, "digitalocean", "default"): secretKey,
	})
	s, key := serving(t, st, 100)
	s.log = slog.New(slog.NewJSONHandler(&logs, nil))
	s.cfg.URLs = map[string]string{"digitalocean": cloudUpstream.URL}
	s.fetcher = cloudUpstream.Client()

	validTok := token(t, key, func(c *jwt.Claims) {
		c.Owner = "acme"
		c.Subject = rawSubject
		c.Id = rawSubject
	})
	expectedRedacted := (Principal{Org: "acme", Kind: Persons, Name: rawSubject}).redacted()

	doReq := func(method, path, auth string, payload any) int {
		var body []byte
		if payload != nil {
			body, _ = json.Marshal(payload)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Hanzo-Run-Id", runID)
		if auth != "" {
			req.Header.Set("Authorization", "Bearer "+auth)
		}
		resp, err := s.App().Test(req, zip.TestConfig{Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		return resp.StatusCode
	}

	// 1. Anonymous request -> denied at gate.
	if code := doReq(http.MethodPost, "/v1/call", "", call()); code != http.StatusUnauthorized {
		t.Fatalf("anonymous call code = %d, want 401", code)
	}
	// 2. Permitted model call -> allowed.
	if code := doReq(http.MethodPost, "/v1/call", validTok, call()); code != http.StatusOK {
		t.Fatalf("permitted call code = %d, want 200", code)
	}
	// 3. Denied fetch (SSRF path traversal attempt) -> denied.
	if code := doReq(http.MethodPost, "/v1/fetch", validTok, spend.Fetch{
		Provider: "DigitalOcean", Method: "GET", Path: "https://169.254.169.254/latest/meta-data/",
	}); code != http.StatusBadRequest {
		t.Fatalf("SSRF fetch code = %d, want 400", code)
	}
	// 4. Permitted fetch -> allowed.
	if code := doReq(http.MethodPost, "/v1/fetch", validTok, spend.Fetch{
		Provider: "DigitalOcean", Method: "GET", Path: "/v2/account",
	}); code != http.StatusOK {
		t.Fatalf("permitted fetch code = %d, want 200", code)
	}

	rawLogs := logs.String()
	if strings.Contains(rawLogs, rawSubject) {
		t.Errorf("audit log leaked unredacted subject %q:\n%s", rawSubject, rawLogs)
	}
	for _, piece := range []string{secretKey, "AuditSecret", "99887766"} {
		if strings.Contains(rawLogs, piece) {
			t.Errorf("audit log leaked secret substring %q:\n%s", piece, rawLogs)
		}
	}

	var allowCount, denyCount int
	for _, line := range strings.Split(strings.TrimSpace(rawLogs), "\n") {
		if line == "" {
			continue
		}
		var rec map[string]any
		if err := json.Unmarshal([]byte(line), &rec); err != nil {
			t.Fatalf("log line is not valid JSON: %v (%s)", err, line)
		}
		decision, _ := rec["decision"].(string)
		dest, _ := rec["destination"].(string)
		principal, _ := rec["principal"].(string)
		loggedRun, _ := rec["run"].(string)

		if decision != "allow" && decision != "deny" {
			t.Errorf("record missing policy decision: %s", line)
		}
		if dest == "" {
			t.Errorf("record missing destination: %s", line)
		}
		if loggedRun != runID {
			t.Errorf("record run = %q, want %q: %s", loggedRun, runID, line)
		}
		if principal != "anonymous" && principal != expectedRedacted {
			t.Errorf("record principal = %q, want %q or anonymous: %s", principal, expectedRedacted, line)
		}
		if decision == "allow" {
			allowCount++
		} else {
			denyCount++
		}
	}
	if allowCount < 2 || denyCount < 2 {
		t.Fatalf("expected at least 2 allow and 2 deny audit records, got allow=%d deny=%d:\n%s",
			allowCount, denyCount, rawLogs)
	}
}
