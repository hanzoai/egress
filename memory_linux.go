// Copyright 2026 Hanzo AI, Inc.
// SPDX-License-Identifier: MIT OR Apache-2.0

//go:build linux

package egress

import (
	"fmt"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// LockMemory pins every page this process has and every page it will get, so no
// provider key is ever written to swap.
//
// THIS IS THE LAST WAY A CREDENTIAL REACHED DISK. The unit already refuses core
// dumps, mounts no writable path and hides /proc, and this service writes no
// file — but none of that governs the kernel, which may page anonymous memory
// out whenever it likes. A key held only in RAM is still a key on a disk once it
// has been swapped, and it stays there after the process is gone.
//
// MCL_FUTURE matters as much as MCL_CURRENT: the credential does not exist yet
// when this runs. It is called before the store is opened for exactly that
// reason — locking after a secret is in memory locks it too late.
//
// Failing here is fatal by design. "Best effort" would mean the guarantee this
// service is built on holds on some hosts and not others, with nothing to say
// which, and the operator finding out from a disk forensics report.
func LockMemory() error {
	if err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE); err != nil {
		return fmt.Errorf("lock memory: %w — a provider key would be swappable. "+
			"Grant the lock (LimitMEMLOCK=infinity in the unit, or CAP_IPC_LOCK) rather than "+
			"running without it", err)
	}
	return nil
}

// MemoryEncryption names the CPU's memory encryption, or "none".
//
// Locking keeps a key off the disk; it does nothing about the DRAM itself, which
// root on a live box, a DMA-capable port or a cold-boot attack still reaches.
// SEV-SNP and TDX close that, and this reports which is in force so a deployment
// can be held to it rather than assumed.
func MemoryEncryption() string {
	// The guest view: the kernel publishes what confidential computing is active.
	if b, err := os.ReadFile("/sys/kernel/coco/status"); err == nil {
		if s := strings.TrimSpace(string(b)); s != "" {
			return s
		}
	}
	if b, err := os.ReadFile("/proc/cpuinfo"); err == nil {
		flags := string(b)
		switch {
		case strings.Contains(flags, "sev_snp"):
			return "sev-snp"
		case strings.Contains(flags, "tdx_guest"):
			return "tdx"
		}
	}
	return "none"
}
