package egress

import (
	"context"
	"fmt"
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
	identity, err := kmsclient.IdentityFromEnv(cfg.KMSPath)
	if err != nil {
		return nil, nil, fmt.Errorf("egress: %w", err)
	}
	to, err := kmsclient.New(kmsclient.Config{
		Endpoint: cfg.KMS,
		Identity: identity,
		Org:      cfg.KMSOrg,
	})
	if err != nil {
		identity.Wipe()
		return nil, nil, fmt.Errorf("egress: open store: %w", err)
	}
	return &vault{to: to}, func() {
		_ = to.Close()
		identity.Wipe()
	}, nil
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
