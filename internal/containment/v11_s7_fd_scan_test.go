// v11_s7_fd_scan_test.go implements Sol11 rc5 Session 7's P1-3 mandatory
// red-team corpus (agents/governator-sol-upgrade11.md "P1-3: Workspace
// file-descriptor scanning skips indeterminate processes",
// agents/governator-sol-upgrade11-rc5-plan.md Session 7, manifest case
// 190 / report: "a cgroup-scoped FD-scan case where an unreadable relevant
// process fails closed").
//
// The pre-P1-3 defect: scanWorkspaceFD treated ANY error reading
// /proc/<pid>/fd -- the process having genuinely exited (ENOENT), a
// permission/hidepid restriction (EACCES/EPERM), or any other indeterminate
// condition -- identically, via a bare `if readErr != nil { continue }`.
// That silently reported "clean" for a process Extinguish could not
// actually verify, which is exactly the unsafe direction to guess in a
// proof gating DESCENDANTS_TERMINATED. The fix (1) scopes the scan via a
// `relevant` predicate to processes this specific Extinguish call can
// attribute to the just-torn-down scope, and (2) for a relevant process,
// distinguishes confirmed absence (ENOENT) from any other, indeterminate
// read failure -- which now fails scanWorkspaceFD closed (a non-nil error)
// instead of silently continuing.
package containment

import (
	"os"
	"testing"
)

// TestV11Case45FDScanIndeterminatePermissionDeniedFailsClosed proves the
// indeterminate branch: pid 1 (init/systemd) always exists and is always
// listed as a /proc entry, but an unprivileged process cannot read
// /proc/1/fd on a normal Linux host (EACCES) -- exactly the
// "permission/unreadable ⇒ indeterminate ⇒ fail closed" case the report
// requires. relevant is set to attribute pid 1 to the scope under test,
// mirroring how Extinguish's cgroup/pid-namespace/degraded branches build
// their own relevant predicate for a real launch.
func TestV11Case45FDScanIndeterminatePermissionDeniedFailsClosed(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: /proc/1/fd is readable, cannot exercise the permission-denied path on this host")
	}
	if _, err := os.ReadDir("/proc/1/fd"); err == nil {
		t.Skip("/proc/1/fd is readable in this environment, cannot exercise the permission-denied path on this host")
	}

	relevant := func(pid int) bool { return pid == 1 }
	clean, err := scanWorkspaceFD(t.TempDir(), relevant)
	if err == nil {
		t.Fatalf("expected scanWorkspaceFD to fail closed (non-nil error) when a relevant process's fd directory could not be read, got clean=%v err=nil", clean)
	}
}

// TestV11Case45CounterpartUnrelatedUnreadableProcessNeverBlocksScan is the
// necessary negative control: pid 1 being unreadable must NOT fail the scan
// when relevant does not attribute it to the scope under test -- an
// unrelated host process is out of scope for this proof entirely (see
// scanWorkspaceFD's doc comment), not an indeterminate observation about
// it. Absent this control, case 45 alone could not distinguish "relevant
// processes fail closed on indeterminate" from "the scan fails closed on
// literally anything unreadable it stumbles across," which would make an
// ordinary busy host's routine, permission-denied processes spuriously fail
// every extinction proof.
func TestV11Case45CounterpartUnrelatedUnreadableProcessNeverBlocksScan(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: /proc/1/fd is readable, cannot exercise the permission-denied path on this host")
	}
	if _, err := os.ReadDir("/proc/1/fd"); err == nil {
		t.Skip("/proc/1/fd is readable in this environment, cannot exercise the permission-denied path on this host")
	}

	relevant := func(pid int) bool { return false }
	clean, err := scanWorkspaceFD(t.TempDir(), relevant)
	if err != nil {
		t.Fatalf("expected an unrelated unreadable process (relevant=false) to never block the scan, got err=%v", err)
	}
	if !clean {
		t.Fatalf("expected clean=true when nothing is attributed to this scope, got clean=%v", clean)
	}
}
