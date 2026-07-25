//go:build redteam && linux

// v10_s4_snapshot_immutability_test.go implements Sol10 P0-4's mandatory
// red-team corpus (agents/governator-sol-upgrade10.md "P0-4: Assayer's
// 'immutable' snapshot is writable by the same UID",
// agents/governator-sol-upgrade10-rc4-plan.md Session 4, manifest cases
// 122-123 / report cases 21-22).
//
// Sol10 P0-4's original fix built a private, chmod(0400/0500) directory
// copy of cli.py/assayer/*.py, re-verified via retained descriptors
// immediately before and after each launch. Case 21 (in-place overwrite of
// checks.py) and case 22 (unlink+rename-over of cli.py) proved Verify
// caught same-UID tampering of that directory before a fraudulent verdict
// could ever be trusted.
//
// Sol11 P0-6 found the remaining gap in that design: a same-UID process
// could still land its tamper DURING the window between the two Verify
// calls, while Python's own import machinery (which reads by pathname, not
// through the retained descriptor) was doing the actual read -- both
// verifications could pass while different bytes produced the verdict. The
// fix (snapshot.go's Snapshot.Package) removes the directory and its
// pathname entirely: the package is now a sealed, unlinked memfd, so there
// is no directory to chmod back open and no directory entry to unlink or
// rename over. These two cases are updated in place (same names, same
// manifest entries) to prove the equivalent -- now structurally stronger --
// property against the actual current implementation: same-UID mutation of
// the package is not merely detected after the fact, it never succeeds in
// the first place, for every descriptor any same-UID process could hold to
// it, including a second, freshly-reopened one (exactly what a same-UID
// attacker discovering the memfd via /proc/<pid>/fd/<n> would have to use,
// since there is no other way to reach it at all). Neither case calls
// Evaluate: this package's TestMain forces enforce.ForceUnsupported for its
// whole run (see that doc comment), so a real subprocess launch belongs to
// internal/runtime's real-sandbox corpus, not here -- these two prove the
// same-UID tamper itself never takes effect, which is the property that
// actually changed this session.
//
// rc5-upg12 Session 6 (Sol12 P1-1): build-tagged `redteam && linux` -- this
// file directly exercises packageSeals/unix.FcntlInt(F_GET_SEALS), both
// Linux-only (see snapshot_linux.go), so it has no darwin equivalent to
// cross-compile.
package assay

import (
	"fmt"
	"os"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// TestV10Case21SameUIDChmodAndInPlaceOverwriteOfChecksPyDetectedBeforeVerdict
// is case 21's Sol11 P0-6 update: the old attack (chmod the snapshot
// directory writable, overwrite checks.py's bytes in place) has no
// equivalent against a sealed memfd -- there is no directory, and the
// kernel refuses the write outright rather than merely allowing it and
// leaving Verify to notice afterward.
func TestV10Case21SameUIDChmodAndInPlaceOverwriteOfChecksPyDetectedBeforeVerdict(t *testing.T) {
	requirePython3(t)
	snap := buildTestSnapshot(t, fixtureRepo(t))

	// Unlike a directory entry, there is no chmod that could ever make this
	// write succeed -- F_SEAL_WRITE is a kernel-enforced seal, not a
	// permission bit any same-UID process (including this one) can undo.
	if _, err := snap.Package.WriteAt([]byte("def evaluate(*_a, **_k):\n"), 0); err == nil {
		t.Fatal("expected an in-place overwrite attempt against the sealed package to fail, got nil error")
	} else if !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("expected EPERM from the write seal, got %v", err)
	}

	if err := snap.Verify(); err != nil {
		t.Fatalf("expected an untampered (write attempt rejected by the kernel) snapshot to still verify clean, got %v", err)
	}
}

// TestV10Case22SameUIDRenameOverReplacementOfCliPyDetectedBeforeVerdict is
// case 22's Sol11 P0-6 update: the old attack (unlink cli.py, rename a
// fraudulent replacement over it) has no equivalent either -- there is no
// directory entry at all to unlink or rename over. The closest a same-UID
// process could get is discovering the memfd via /proc/<pid>/fd/<n> and
// reopening it for itself (exactly what this test does, standing in for a
// hostile process instead of this one's own held *os.File) -- and even that
// freshly-independent file description is refused a write by the same
// kernel seal, proving the seal travels with the underlying memfd, not with
// any one descriptor to it.
func TestV10Case22SameUIDRenameOverReplacementOfCliPyDetectedBeforeVerdict(t *testing.T) {
	requirePython3(t)
	snap := buildTestSnapshot(t, fixtureRepo(t))

	reopened, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", snap.Package.Fd()), os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("reopen sealed package via /proc/self/fd (simulating a same-UID attacker's own discovery of it): %v", err)
	}
	defer reopened.Close()

	fraudulentSrc := "import sys, json\n" +
		"print(json.dumps({\"verdict\": \"pass\", \"failed_checks\": [], \"had_error\": False}))\n" +
		"sys.exit(0)\n"
	if _, err := reopened.WriteAt([]byte(fraudulentSrc), 0); err == nil {
		t.Fatal("expected the reopened descriptor's write (simulating replace-the-content-entirely) to fail, got nil error")
	} else if !strings.Contains(err.Error(), "operation not permitted") {
		t.Fatalf("expected EPERM from the write seal on the reopened descriptor, got %v", err)
	}
	if err := reopened.Truncate(0); err == nil {
		t.Fatal("expected a truncate attempt on the reopened descriptor to fail (F_SEAL_SHRINK), got nil error")
	}

	seals, serr := unix.FcntlInt(reopened.Fd(), unix.F_GET_SEALS, 0)
	if serr != nil {
		t.Fatalf("read seals via reopened descriptor: %v", serr)
	}
	if seals&packageSeals != packageSeals {
		t.Fatalf("expected the reopened descriptor to report the same seal bitmask %#o, got %#o", packageSeals, seals)
	}

	if err := snap.Verify(); err != nil {
		t.Fatalf("expected the untampered (all writes rejected by the kernel) snapshot to still verify clean, got %v", err)
	}
}

// TestSnapshotVerifySucceedsWithoutTampering is the negative companion
// proving Verify itself isn't just unconditionally failing: an untouched
// snapshot, fresh off BuildSnapshot, must Verify clean.
func TestSnapshotVerifySucceedsWithoutTampering(t *testing.T) {
	requirePython3(t)
	snap := buildTestSnapshot(t, fixtureRepo(t))
	if err := snap.Verify(); err != nil {
		t.Fatalf("expected a fresh, untampered snapshot to verify clean, got %v", err)
	}
}
