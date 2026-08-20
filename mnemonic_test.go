package egress

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// THE IDENTITY IS NOT IN THE ENVIRONMENT, and this is the test that keeps it out.
//
// The store SDK will take the mnemonic from LUX_MNEMONIC, which put the one
// secret every provider credential hangs off into a plaintext file and into this
// process's environment — where /proc/<pid>/environ hands it to anything running
// as root. Invariant 3 forbids exactly that, and the identity was the one
// credential exempting itself from the rule it exists to enforce.
func TestTheIdentityIsNeverTakenFromTheEnvironment(t *testing.T) {
	t.Setenv("LUX_MNEMONIC", "these words must never be read from here")
	t.Setenv("MNEMONIC", "nor these")
	t.Setenv("CREDENTIALS_DIRECTORY", "")

	got, err := sealed("mnemonic")
	if err == nil {
		t.Fatalf("read %q with no sealed credential present — the environment was trusted", got)
	}
	if strings.Contains(err.Error(), "must never be read") {
		t.Error("the refusal quoted the secret back")
	}
}

// Under systemd the value comes from the credential directory, which is
// memory-backed and readable only by this unit.
func TestTheIdentityComesFromTheSealedCredential(t *testing.T) {
	dir := t.TempDir()
	const want = "abandon abandon abandon abandon abandon about"
	if err := os.WriteFile(filepath.Join(dir, "mnemonic"), []byte(want+"\n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	t.Setenv("LUX_MNEMONIC", "a different value that must lose")

	got, err := sealed("mnemonic")
	if err != nil {
		t.Fatalf("sealed credential present and unreadable: %v", err)
	}
	if got != want {
		t.Errorf("read %q, want the sealed value", got)
	}
}

// An empty credential is a refusal, not an empty identity. A service that
// derived an identity from "" would authenticate as something, and that
// something is not us.
func TestAnEmptySealedCredentialIsRefused(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mnemonic"), []byte("   \n"), 0o400); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", dir)
	if _, err := sealed("mnemonic"); err == nil {
		t.Error("an empty mnemonic was accepted")
	}
}

// THE ENDPOINT PICKS THE GATE, and getting this wrong is what a deploy pays for.
// zap:// is a direct dial the public edge does not carry, so from off the cluster
// — which is where this service lives — https is the reachable transport and it
// authenticates by machine identity instead of by envelope signature.
func TestTheEndpointDecidesTheTransport(t *testing.T) {
	for _, c := range []struct {
		endpoint string
		zap      bool
	}{
		{"zap://kms.hanzo.ai:9999", true},
		{"ZAP://kms.hanzo.ai:9999", true},
		{"zap+mdns://_kms._tcp", true},
		{"https://kms.hanzo.ai", false},
		{"http://kms.hanzo.svc.cluster.local:8443", false},
	} {
		if got := overZAP(c.endpoint); got != c.zap {
			t.Errorf("overZAP(%q) = %v, want %v", c.endpoint, got, c.zap)
		}
	}
}
