// Copyright (C) 2019-2026, Hanzo Industries Inc. All rights reserved.

package egress

import "context"

// RefusingStore is a credential store that holds nothing and refuses every
// read. It lets egress run as a pure network firewall on a host that has no
// spend identity: the firewall serves, and every spend call fails closed with
// ErrNoCredential rather than the process not starting at all. A firewall that
// also spends is given a real store instead.
type RefusingStore struct{}

func (RefusingStore) GetSecret(context.Context, string) ([]byte, error) {
	return nil, ErrNoCredential
}
func (RefusingStore) PutSecret(context.Context, string, []byte) error {
	return ErrNoCredential
}
