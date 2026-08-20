package egress

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hanzoai/kms/sdk/go/kmsclient"
)

// vault is KMS behind the Secrets seam. hanzoai/ai holds the same seam over an
// in-process store because ai runs inside a binary that embeds KMS; egress does
// not run there, so the same two methods are a signed ZAP call across the
// network instead. The shape is identical on purpose — the code above this line
// cannot tell the difference, and a test supplies a store of its own.
type vault struct {
	to *kmsclient.Client
}

// Vault opens the credential store named by cfg, signing every call with an
// identity derived from this host's mnemonic. It fails closed: without an
// identity there is no way to prove who is reading, and a store that cannot
// tell is not one to read from.
func Vault(cfg Config) (Secrets, func(), error) {
	// TWO TRANSPORTS, TWO GATES, AND THE ENDPOINT DECIDES WHICH.
	//
	// zap:// signs every call with a mnemonic-derived identity and the store
	// verifies the envelope. http(s):// exchanges a machine identity for a
	// bearer at IAM. They are not interchangeable and neither is a fallback for
	// the other: a missing credential fails here rather than quietly trying the
	// other door with the wrong one.
	//
	// This process runs off the cluster, where the ZAP port is not carried by
	// the public edge — so https is the reachable one from here, and zap:// is
	// for a caller inside.
	store := kmsclient.Config{Endpoint: cfg.KMS, Org: cfg.KMSOrg}

	var identity *kmsclient.Identity
	if overZAP(cfg.KMS) {
		m, err := sealed("mnemonic")
		if err != nil {
			return nil, nil, fmt.Errorf("egress: %w", err)
		}
		identity, err = kmsclient.NewIdentity(m, cfg.KMSPath)
		if err != nil {
			return nil, nil, fmt.Errorf("egress: %w", err)
		}
		store.Identity = identity
	} else {
		if cfg.IAM == "" || cfg.ClientID == "" {
			return nil, nil, errors.New("egress: an http store endpoint needs -iam and -client-id")
		}
		secret, err := sealed("client-secret")
		if err != nil {
			return nil, nil, fmt.Errorf("egress: %w", err)
		}
		store.IAMEndpoint, store.ClientID, store.ClientSecret = cfg.IAM, cfg.ClientID, secret
	}

	to, err := kmsclient.New(store)
	if err != nil {
		identity.Wipe()
		return nil, nil, fmt.Errorf("egress: open store: %w", err)
	}

	// The store keeps what it is given; the seal decides what that is worth.
	// Every credential crossing this line is already sealed to this host, so KMS
	// holds ciphertext and the key that opens it never left the TPM. See
	// envelope.go for why that is the arrangement rather than trusting the store.
	me, err := sealed("identity")
	if err != nil {
		_ = to.Close()
		identity.Wipe()
		return nil, nil, fmt.Errorf("egress: %w", err)
	}
	held, err := Envelope(&vault{to: to}, cfg.Recipient, me)
	if err != nil {
		_ = to.Close()
		identity.Wipe()
		return nil, nil, err
	}
	return held, func() {
		_ = to.Close()
		identity.Wipe()
	}, nil
}

// overZAP reports whether the endpoint names the signing transport.
func overZAP(endpoint string) bool {
	e := strings.ToLower(endpoint)
	return strings.HasPrefix(e, "zap://") || strings.HasPrefix(e, "zap+mdns://")
}

// sealed reads one secret on this host — it derives the identity that
// unlocks every provider credential — and it is read from a SEALED CREDENTIAL,
// never from the environment.
//
// The store SDK will take it from LUX_MNEMONIC, and that was how this ran. It
// put the one secret everything else hangs off into a plaintext file and into
// this process's environment, where /proc/<pid>/environ hands it to anything
// running as root. Invariant 3 says no file and no environment variable; the
// identity was the one credential exempting itself from the rule it exists to
// enforce.
//
// systemd decrypts a LoadCredentialEncrypted unit credential with the TPM and
// places it in a per-service directory that is memory-backed and readable only
// by this unit. So the value is ciphertext on disk, plaintext only in this
// process, and absent from the environment entirely. That property does not
// depend on an encrypted root, which is why it holds on a host that has none.
//
// No environment fallback. One way to hold it, or the service does not start.
func sealed(name string) (string, error) {
	dir := os.Getenv("CREDENTIALS_DIRECTORY")
	if dir == "" {
		return "", fmt.Errorf("no CREDENTIALS_DIRECTORY: run under systemd with LoadCredentialEncrypted=%s:/etc/egress/%s.cred", name, name)
	}
	raw, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		return "", fmt.Errorf("read the sealed %s: %w", name, err)
	}
	v := strings.TrimSpace(string(raw))
	if v == "" {
		return "", fmt.Errorf("the sealed %s is empty", name)
	}
	return v, nil
}

// GetSecret reads one credential by reference.
func (v *vault) GetSecret(ctx context.Context, ref string) ([]byte, error) {
	path, name := split(ref)
	value, err := v.to.Get(ctx, path, name)
	if err != nil {
		return nil, err
	}
	return []byte(value), nil
}

// PutSecret seals one credential at a reference.
func (v *vault) PutSecret(ctx context.Context, ref string, value []byte) error {
	path, name := split(ref)
	return v.to.Put(ctx, path, name, string(value))
}

// split separates a flat reference into the path it lives under and the name it
// is stored as — the last segment is the name, everything before it the path.
func split(ref string) (path, name string) {
	ref = strings.Trim(ref, "/")
	if i := strings.LastIndex(ref, "/"); i >= 0 {
		return ref[:i], ref[i+1:]
	}
	return "", ref
}
