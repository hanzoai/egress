package egress

import (
	"runtime"
	"testing"
	"time"

	"github.com/hanzoai/kms/sdk/go/kmsclient"
	"github.com/luxfi/keys"
)

// TestTheIdentityKeepsItsKeyPastTheFirstSignature pins the property every
// credential read here rests on. Egress signs one envelope per read, and the
// identity that signs them is derived once at boot and used for the life of
// the process. An identity that surrenders its signing key to the collector
// after the first signature serves one call and then reads nothing — and it
// does so quietly, because the second signature is produced without error and
// simply does not verify.
//
// The identity is a luxfi/keys service identity reached through the KMS
// client, so this is a guard on a dependency rather than on code in this
// repository. That is the point: the property is not visible from here at
// compile time, and a bump that lost it would otherwise be found in
// production.
func TestTheIdentityKeepsItsKeyPastTheFirstSignature(t *testing.T) {
	const mnemonic = "abandon abandon abandon abandon abandon abandon " +
		"abandon abandon abandon abandon abandon about"

	identity, err := kmsclient.NewIdentity(mnemonic, "hanzo/egress")
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Wipe()

	first := []byte("read the customer's own key")
	if _, err := identity.Sign(first); err != nil {
		t.Fatalf("first signature: %v", err)
	}

	// Whatever the first signature left unreachable, collect it and let its
	// finalizer run. Under the fault this is the moment the key is lost.
	for i := 0; i < 4; i++ {
		runtime.GC()
		time.Sleep(time.Millisecond)
	}

	second := []byte("read the tenant's shared key")
	signature, err := identity.Sign(second)
	if err != nil {
		t.Fatalf("second signature: %v", err)
	}
	if err := keys.VerifyServiceEnvelope(identity.PublicKey, identity.FullDigest, second, signature); err != nil {
		t.Fatalf("the second signature does not verify — the identity lost its key after the first: %v", err)
	}
}
