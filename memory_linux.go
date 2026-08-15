package egress

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Confine keeps the credential inside this process's memory, where it was put.
//
// Two ways a value in RAM reaches a disk without anyone writing it there:
//
//	the kernel pages it out to swap
//	the kernel writes a core file when the process dies badly
//
// Core files are refused unconditionally — nothing is given up by doing so.
// Locking pages is conditional, for a reason worth stating: MCL_FUTURE makes
// every LATER allocation count against RLIMIT_MEMLOCK, so locking under an
// allowance smaller than this container may grow to turns the next allocation
// past the ceiling into a failure. That arrives as a death under load looking
// like a random out-of-memory, which is a worse outcome than not locking — the
// failure is silent, delayed, and lands on paid traffic.
//
// So the allowance is checked first and locking is skipped when it cannot cover
// the container. Kubernetes runs with swap off, which is the guarantee this
// reinforces rather than replaces.
func Confine() error {
	// No core file can carry what a core file is never written.
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}

	var allowed syscall.Rlimit
	if err := syscall.Getrlimit(syscall.RLIMIT_MEMLOCK, &allowed); err != nil {
		return fmt.Errorf("read memlock allowance: %w", err)
	}
	if allowed.Cur != unlimited {
		ceiling, known := memoryLimit()
		if !known {
			return fmt.Errorf("memlock allowance is %d bytes and this container's limit is unknown; not locking", allowed.Cur)
		}
		if allowed.Cur < ceiling {
			return fmt.Errorf("memlock allowance %d is below the container limit %d; locking would fail an allocation later", allowed.Cur, ceiling)
		}
	}

	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
		return fmt.Errorf("lock memory: %w", err)
	}
	return nil
}

// unlimited is RLIM_INFINITY as the Rlimit fields carry it.
const unlimited = ^uint64(0)

// memoryLimit reports how large this container may grow, from the cgroup the
// kubelet set. "max" means uncapped, which no finite allowance can cover.
func memoryLimit() (uint64, bool) {
	for _, path := range []string{
		"/sys/fs/cgroup/memory.max",                   // cgroup v2
		"/sys/fs/cgroup/memory/memory.limit_in_bytes", // cgroup v1
	} {
		raw, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		v := strings.TrimSpace(string(raw))
		if v == "max" {
			return 0, false
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			continue
		}
		return n, true
	}
	return 0, false
}
