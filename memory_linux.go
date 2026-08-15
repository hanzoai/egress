package egress

import (
	"fmt"
	"syscall"
)

// Confine keeps the credential inside this process's memory, where it was put.
//
// Two ways a value in RAM reaches a disk without anyone writing it there:
//
//	the kernel pages it out to swap
//	the kernel writes a core file when the process dies badly
//
// Both are closed here. Locking the whole address space rather than one buffer
// is deliberate — Go's collector copies and moves values, so the page a
// credential occupies is not one this code can name and keep hold of. The
// process is small; locking all of it costs little and leaves nothing to miss.
//
// Kubernetes already runs with swap off, so this is a second latch on a door
// that should be shut; it earns its place by not depending on that being true.
func Confine() error {
	// No core file can carry what a core file is never written.
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return fmt.Errorf("disable core dumps: %w", err)
	}
	// MCL_FUTURE covers pages this process has not allocated yet, which is where
	// a credential fetched after boot will live.
	if err := syscall.Mlockall(syscall.MCL_CURRENT | syscall.MCL_FUTURE); err != nil {
		return fmt.Errorf("lock memory: %w", err)
	}
	return nil
}
