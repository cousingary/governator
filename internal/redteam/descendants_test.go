//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestAttack8DetachedSetsidChildCannotWriteAfterApproval is report P0-4 /
// §9 attack 8: the backend creates the permitted output, launches a
// detached (setsid + double-fork) child, and exits normally with a valid
// transcript. The child sleeps briefly, then writes into the live
// repository after Governator has already recorded APPROVED. Fixed by S2:
// a descendant-owning containment primitive (cgroup v2 scope / systemd
// transient scope / PID namespace) that freezes, kills, and waits for
// confirmed extinction of the whole owned process tree before final-state
// capture -- so no descendant can still be alive, let alone writing, once
// the run is recorded complete.
func TestAttack8DetachedSetsidChildCannotWriteAfterApproval(t *testing.T) {
	root := fixtureRepo(t)
	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(`
setsid sh -c 'sleep 2; printf leak > `+filepath.Join(root, "escaped-after-approval.txt")+`' < /dev/null > /dev/null 2>&1 &
`))

	rec := runGoverned(t, t.TempDir(), bin, c)
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED (the detached child must not block the well-behaved run), got status=%s message=%s", rec.Status, rec.Message)
	}

	// Give the detached child every chance to win the race; the containment
	// primitive must have already killed it before Run returned.
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(filepath.Join(root, "escaped-after-approval.txt")); !os.IsNotExist(err) {
		t.Fatalf("detached descendant wrote into the live root after APPROVED: err=%v", err)
	}
}
