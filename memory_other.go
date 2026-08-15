//go:build !linux

package egress

import "fmt"

// Confine reports that this platform cannot make the guarantee. Egress runs on
// Linux; elsewhere this exists so the package builds and tests for developers,
// and it says so rather than returning success it cannot deliver.
func Confine() error {
	return fmt.Errorf("memory cannot be confined on this platform")
}
