// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

package egress

import (
	"runtime"
	"strings"
	"testing"
)

// The claim this service makes is that a provider key never reaches a disk, and
// swap is the last way it could. So the lock either holds or the process does
// not serve — and when it cannot hold, the refusal has to name the grant that
// fixes it, because "cannot allocate memory" from mlockall reads like a machine
// out of RAM rather than a missing capability.
func TestMemoryIsLockedOrTheRefusalSaysHow(t *testing.T) {
	err := LockMemory()
	if err == nil {
		if runtime.GOOS != "linux" {
			t.Fatalf("LockMemory succeeded on %s, where these pages cannot be pinned", runtime.GOOS)
		}
		return // locked: the guarantee holds on this host
	}
	if runtime.GOOS != "linux" {
		return // refusing off Linux is the documented answer
	}
	// It failed on Linux, which is allowed — an unprivileged test process has a
	// small RLIMIT_MEMLOCK. What is not allowed is a refusal nobody can act on.
	for _, want := range []string{"LimitMEMLOCK", "CAP_IPC_LOCK", "swap"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q, so a reader cannot act on it: %v", want, err)
		}
	}
}

// Memory encryption is reported, never assumed. Locking keeps a key off the
// disk and says nothing about the DRAM, so a deployment that needs SEV-SNP or
// TDX has to be able to read which is in force rather than trust that it is.
func TestMemoryEncryptionIsReported(t *testing.T) {
	got := MemoryEncryption()
	if strings.TrimSpace(got) == "" {
		t.Fatal("MemoryEncryption() is empty — it must say 'none' rather than say nothing, " +
			"or an absent guarantee reads as an unasked question")
	}
	t.Logf("memory encryption on this host: %s", got)
}
