//go:build redteam

package containment

import (
	"os"
	"syscall"
	"testing"
)

func TestWaitPIDGoneDoesNotTreatEPERMAsGone(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can signal pid 1; EPERM fixture unavailable")
	}
	if err := syscall.Kill(1, 0); err != syscall.EPERM {
		t.Skipf("pid 1 did not produce EPERM in this environment: %v", err)
	}
	if err := waitPIDGone(1, 0); err == nil {
		t.Fatal("waitPIDGone treated EPERM as extinction proof")
	}
}
