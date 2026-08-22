package egress

// What KMS holds, and what only this host can read.
//
// A credential store protects a credential from everyone outside it. It cannot
// protect one from itself: whoever administers the store, or the cluster it runs
// in, holds whatever opens it. `kubectl exec`, a node's disk, a provider API
// token that can read the volume — each of those is the whole store, and none of
// them is a break-in.
//
// So the value KMS keeps is not the credential. It is the credential sealed to
// THIS SERVICE, under a key that exists only here, on one machine, encrypted at
// rest and decrypted only into this process's memory.
// KMS stores it, replicates it, backs it up, decides who may ask for it — and
// cannot read a byte of it. The store's operator and the store's contents stop
// being the same authority.
//
// Sealing needs only the recipient, `age1pq1…`, which is public: it can live in
// a flag, a manifest, a commit. So the cluster ENROLS credentials it will never
// be able to read. That asymmetry is the whole design; everything else here is
// bookkeeping around it.
//
// Nothing falls back. A value that does not open is an error, because the two
// ways this could be lenient — treat an unopenable value as plaintext, or read
// the credential from somewhere less guarded — are each a way for a key to be
// spent from outside the seal.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	kms "github.com/luxfi/kms/pkg/store"
)

// envelope is the credential store with the sealing key in front of it. It is a
// Secrets that wraps a Secrets, so custody above it is unchanged and a test can
// still supply a plain map — what differs is only whether the bytes crossing the
// network mean anything to whoever reads them.
type envelope struct {
	in       Secrets
	to       string // the recipient. Public: it seals and cannot open.
	identity string // this host's identity. It opens, and lives only here, in memory.
}

// sealEnv is the environment component of a sealed credential's coordinate.
// The coordinate is bound into the seal, so a record copied to another path or
// name stops opening — a store that shuffles rows cannot serve one tenant's key
// under another's name. Egress keeps no environments of its own; this names the
// plane the credential belongs to and is the same on both sides of the seal.
const sealEnv = "egress"

// ErrNotSealed is what a stored value that is not a sealed record gets. It is a
// refusal, and deliberately not a guess: treating an unrecognised value as a
// credential would spend, upstream, whatever a store happened to contain.
var ErrNotSealed = errors.New("egress: the stored value is not sealed to this service")

// Envelope puts the sealing key in front of a store. The recipient seals, the
// identity opens, and both are checked here rather than at the first call that
// needs them — a service that cannot open its own credentials should fail while
// it is starting, not on a customer's request.
func Envelope(in Secrets, recipient, identity string) (Secrets, error) {
	if in == nil {
		return nil, errors.New("egress: no store to seal into")
	}
	if recipient == "" || identity == "" {
		return nil, errors.New("egress: sealing needs both a recipient and this host's identity")
	}
	// Prove the pair belongs together NOW. A recipient and an identity that are
	// not two halves of one key are indistinguishable from a working
	// configuration until the first credential fails to open, which is a
	// customer's request and an unreadable error. One round trip here answers it.
	e := &envelope{in: in, to: recipient, identity: identity}
	sec, err := kms.SealTo(recipient, "egress", "self", sealEnv, []byte("self"))
	if err != nil {
		return nil, fmt.Errorf("egress: recipient: %w", err)
	}
	if _, err := kms.OpenWith(identity, sec); err != nil {
		return nil, fmt.Errorf("egress: this host's identity does not open what its recipient seals: %w", err)
	}
	return e, nil
}

// GetSecret fetches a sealed record and opens it. The plaintext exists from this
// line until the call that spends it returns, and is written nowhere.
func (e *envelope) GetSecret(ctx context.Context, ref string) ([]byte, error) {
	raw, err := e.in.GetSecret(ctx, ref)
	if err != nil {
		return nil, err
	}
	var sec kms.Secret
	if err := json.Unmarshal(raw, &sec); err != nil || sec.Scheme == "" {
		return nil, fmt.Errorf("%w: %s", ErrNotSealed, ref)
	}
	// THE COORDINATE MUST COME FROM WHERE THE RECORD WAS FOUND, not from inside
	// it. The seal binds path/name/env, but a record carries its own copy of all
	// three — so a record moved to another tenant's reference brings its AAD
	// along and opens exactly as before. Comparing the two is what turns that
	// binding into a boundary: a credential is spendable only at the reference
	// it was sealed for.
	path, name := split(ref)
	if sec.Path != path || sec.Name != name || sec.Env != sealEnv {
		return nil, fmt.Errorf("egress: the record at %s was sealed for %s/%s@%s", ref, sec.Path, sec.Name, sec.Env)
	}
	return kms.OpenWith(e.identity, &sec)
}

// PutSecret seals a credential and stores the sealed record. What crosses the
// network, and what the store then holds, is already ciphertext — so a store
// that is compromised between here and disk yields nothing.
func (e *envelope) PutSecret(ctx context.Context, ref string, value []byte) error {
	path, name := split(ref)
	sec, err := kms.SealTo(e.to, path, name, sealEnv, value)
	if err != nil {
		return fmt.Errorf("egress: seal %s: %w", ref, err)
	}
	raw, err := json.Marshal(sec)
	if err != nil {
		return fmt.Errorf("egress: seal %s: %w", ref, err)
	}
	return e.in.PutSecret(ctx, ref, raw)
}
