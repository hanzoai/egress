package egress

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	record "github.com/luxfi/kms/pkg/store"
)

const sealedRef = "orgs/acme/users/u-7/connectors/openai/default"

// aRecipient is one public sealing key for the whole test package. Config.Check
// requires one, and minting is not free, so every fixture that only needs the
// configuration to be coherent shares this.
var aRecipient = sync.OnceValue(func() string {
	_, to, err := kms.Recipient()
	if err != nil {
		panic(err)
	}
	return to
})

func recipientPair(t *testing.T) (identity, recipient string) {
	t.Helper()
	identity, recipient, err := kms.Recipient()
	if err != nil {
		t.Fatal(err)
	}
	return identity, recipient
}

// sealedOver puts a freshly minted sealing key in front of a store a test owns.
func sealedOver(t *testing.T, in Secrets) (Secrets, string) {
	t.Helper()
	identity, recipient := recipientPair(t)
	s, err := Envelope(in, recipient, identity)
	if err != nil {
		t.Fatal(err)
	}
	return s, recipient
}

// The round trip, and what the store is left holding.
func TestACredentialGoesInSealedAndComesBackOut(t *testing.T) {
	held := newStore(nil)
	sealed, _ := sealedOver(t, held)
	key := []byte("sk-live-the-actual-credential")

	if err := sealed.PutSecret(context.Background(), sealedRef, key); err != nil {
		t.Fatal(err)
	}

	raw := held.at(sealedRef)
	if bytes.Contains([]byte(raw), key) {
		t.Fatal("the credential is present in what the store holds")
	}
	var rec kms.Secret
	if err := json.Unmarshal([]byte(raw), &rec); err != nil {
		t.Fatalf("what the store holds is not a sealed record: %v", err)
	}
	if rec.Scheme != kms.ModeRecipient {
		t.Fatalf("scheme = %q, want %q", rec.Scheme, kms.ModeRecipient)
	}

	got, err := sealed.GetSecret(context.Background(), sealedRef)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, key) {
		t.Fatalf("opened %q, want %q", got, key)
	}
}

// THE PROPERTY. Everything the cluster has — the stored bytes and the public
// recipient — opens nothing. This is the claim about a cluster that can be
// exec'd into, written as a test.
func TestHoldingTheStoreIsNotHoldingTheCredential(t *testing.T) {
	held := newStore(nil)
	sealed, recipient := sealedOver(t, held)
	if err := sealed.PutSecret(context.Background(), sealedRef, []byte("sk-live-credential")); err != nil {
		t.Fatal(err)
	}

	var rec kms.Secret
	if err := json.Unmarshal([]byte(held.at(sealedRef)), &rec); err != nil {
		t.Fatal(err)
	}
	if _, err := kms.OpenWith(recipient, &rec); err == nil {
		t.Fatal("the recipient the cluster holds opened the credential")
	}
	other, _ := recipientPair(t)
	if _, err := kms.OpenWith(other, &rec); err == nil {
		t.Fatal("another host's identity opened the credential")
	}
}

// A record copied to another tenant's reference must not open there. The seal
// binds the coordinate, but a record carries its own copy of it — so this holds
// only because the reference asked for is the one checked.
func TestARecordMovedToAnotherReferenceDoesNotOpen(t *testing.T) {
	held := newStore(nil)
	sealed, _ := sealedOver(t, held)
	if err := sealed.PutSecret(context.Background(), sealedRef, []byte("acme's credential")); err != nil {
		t.Fatal(err)
	}

	elsewhere := "orgs/globex/users/u-9/connectors/openai/default"
	if err := held.PutSecret(context.Background(), elsewhere, []byte(held.at(sealedRef))); err != nil {
		t.Fatal(err)
	}
	if _, err := sealed.GetSecret(context.Background(), elsewhere); err == nil {
		t.Fatal("a credential opened at a reference it was not sealed for")
	}
}

// A value that is not a sealed record is refused, never spent. Anything else
// sends whatever the store happened to hold to a vendor as a credential.
func TestAnUnsealedValueIsRefused(t *testing.T) {
	held := newStore(map[string]string{sealedRef: "sk-live-plaintext"})
	sealed, _ := sealedOver(t, held)

	_, err := sealed.GetSecret(context.Background(), sealedRef)
	if err == nil {
		t.Fatal("an unsealed value was returned as a credential")
	}
	if !strings.Contains(err.Error(), ErrNotSealed.Error()) {
		t.Fatalf("want ErrNotSealed, got: %v", err)
	}
}

// A mismatched pair is caught while starting, not on a customer's request.
func TestAMismatchedPairDoesNotStart(t *testing.T) {
	_, recipient := recipientPair(t)
	otherIdentity, _ := recipientPair(t)

	if _, err := Envelope(newStore(nil), recipient, otherIdentity); err == nil {
		t.Fatal("started with an identity that does not open what the recipient seals")
	}
	if _, err := Envelope(newStore(nil), "", "x"); err == nil {
		t.Fatal("started with no recipient")
	}
	if _, err := Envelope(newStore(nil), "x", ""); err == nil {
		t.Fatal("started with no identity")
	}
	if _, err := Envelope(nil, recipient, otherIdentity); err == nil {
		t.Fatal("started with no store")
	}
}

// Absence must still read as absence through the seal, because custody depends
// on telling "this tenant brought no key" from "the store could not answer".
func TestAbsenceSurvivesTheSeal(t *testing.T) {
	sealed, _ := sealedOver(t, newStore(nil))
	_, err := sealed.GetSecret(context.Background(), sealedRef)
	if err == nil {
		t.Fatal("a missing credential came back as a value")
	}
	if !absent(err) {
		t.Fatalf("a missing credential no longer reads as absent: %v", err)
	}
}
