// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

//go:build !linux

package egress

import "errors"

// LockMemory refuses off Linux. mlockall is what keeps a provider key out of
// swap, and this service's whole claim is that a credential never reaches a
// disk — so a platform where that cannot be enforced is a platform it does not
// serve on, rather than one it serves on quietly without the guarantee.
func LockMemory() error {
	return errors.New("lock memory: only Linux can pin these pages, and without pinning a provider key is swappable")
}

// MemoryEncryption is unknown off Linux.
func MemoryEncryption() string { return "unknown" }
