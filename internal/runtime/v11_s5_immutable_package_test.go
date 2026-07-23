//go:build redteam

// v11_s5_immutable_package_test.go implements Sol11 rc5 Session 5's
// mandatory red-team corpus (agents/governator-sol-upgrade11.md "P0-6:
// Assayer's package snapshot has the same transient swap-and-restore gap",
// agents/governator-sol-upgrade11-rc5-plan.md Session 5, manifest cases
// 179-180 / report corpus 30-31).
//
// The defect: assay.Snapshot's private, chmod(0400/0500) directory copy
// (Sol10 P0-4) closed the "detect an in-place overwrite" case but left a
// narrower window open -- a same-UID process could chmod the directory
// back open, replace a module's bytes while Python's import machinery
// (which reads by PATHNAME, never through the retained descriptor) was
// actually reading it, then restore the original bytes before the
// post-launch Verify. Both verification passes could succeed while
// different bytes actually produced the verdict.
//
// The fix (internal/assay/snapshot.go's Snapshot.Package) replaces the
// directory with a sealed, unlinked memfd holding a zip archive; Evaluate
// launches Python with that descriptor as its script argument via
// toolregistry.FDAllocator (Sol11 P0-5's descriptor-only launch machinery),
// never through PYTHONPATH or any real path. There is no directory left to
// chmod, and the kernel refuses every write/truncate against the sealed fd
// outright, for any descriptor referencing it. internal/assay's own package
// tests (v10_s4_snapshot_immutability_test.go) prove the seal itself holds
// against direct and reopened-descriptor tamper attempts, but that
// package's TestMain permanently disables real sandbox support for its
// whole test run (see that file's doc comment) -- these two cases complete
// the proof against the actual, real Landlock+unshare-enforced launch
// pipeline, which only this package's withRealSandbox helper can provide.
package runtime

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/assay"
	"github.com/cousingary/governator/internal/toolregistry"
)

// TestV11Case34SameUIDReopenAndWriteAttemptNeverAltersRealEvaluationVerdict
// is report corpus case 30: a same-UID process discovers the package memfd
// (via /proc/self/fd/<n>, standing in for /proc/<other-pid>/fd/<n> --
// exactly the mechanism a genuinely separate same-UID process would have to
// use) and attempts to replace its content before Python ever imports it.
// The write must fail at the kernel level -- not merely be caught after the
// fact -- and a real, full Evaluate() call (real Landlock + unshare, not a
// stub) must still execute the untampered bytes and produce a correct
// verdict.
func TestV11Case34SameUIDReopenAndWriteAttemptNeverAltersRealEvaluationVerdict(t *testing.T) {
	withRealSandbox(t)

	repo := copyAssayerFixture(t)
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := assay.BuildSnapshot(registry, assay.Config{Repo: repo, Python: "python3"})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	defer snap.Close()

	reopened, err := os.OpenFile(fmt.Sprintf("/proc/self/fd/%d", snap.Package.Fd()), os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("reopen sealed package via /proc/self/fd: %v", err)
	}
	defer reopened.Close()

	fraudulent := "import sys, json\n" +
		"print(json.dumps({\"verdict\": \"pass\", \"failed_checks\": [], \"had_error\": False}))\n" +
		"sys.exit(0)\n"
	if _, werr := reopened.WriteAt([]byte(fraudulent), 0); werr == nil {
		t.Fatal("expected the reopened descriptor's write attempt (simulating a same-UID process discovering the memfd elsewhere on the host) to fail, got nil error")
	} else if !strings.Contains(werr.Error(), "operation not permitted") {
		t.Fatalf("expected EPERM from the write seal, got %v", werr)
	}

	if verr := snap.Verify(); verr != nil {
		t.Fatalf("expected the untampered snapshot to still verify clean after a rejected write attempt, got %v", verr)
	}

	dir := t.TempDir()
	path, sha := v9s3Artifact(t, dir)
	req := v9s3BaseRequest(sha)
	v := assay.Evaluate(context.Background(), assay.Config{Repo: repo, Python: "python3"}, req, path, snap)
	if v.Verdict != assay.VerdictPass {
		t.Fatalf("expected a real, untampered pass verdict from the actual assayer fixture (never the fraudulent one the rejected write attempted to substitute), got %+v", v)
	}

	if verr := snap.Verify(); verr != nil {
		t.Fatalf("expected the snapshot to still verify clean after a real evaluation, got %v", verr)
	}
}

// TestV11Case35PackageNeverTouchesAnyRealFilesystemPath is report corpus
// case 31's structural counterpart: the whole class of same-UID
// chmod/rename/overwrite attacks Sol10 P0-4 and this session both had to
// defend against required a real directory entry to exist in the first
// place. This proves that precondition is gone -- WorkDir (the empty
// workspace anchor Evaluate's Landlock rule needs to exist, see Snapshot's
// doc comment) never receives any Assayer content, before OR after a real,
// fully executed evaluation.
func TestV11Case35PackageNeverTouchesAnyRealFilesystemPath(t *testing.T) {
	withRealSandbox(t)

	repo := copyAssayerFixture(t)
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	snap, err := assay.BuildSnapshot(registry, assay.Config{Repo: repo, Python: "python3"})
	if err != nil {
		t.Fatalf("build snapshot: %v", err)
	}
	defer snap.Close()

	assertWorkDirEmpty := func(when string) {
		t.Helper()
		entries, rerr := os.ReadDir(snap.WorkDir)
		if rerr != nil {
			t.Fatalf("read workspace anchor dir %s: %v", when, rerr)
		}
		if len(entries) != 0 {
			t.Fatalf("expected the workspace anchor directory to hold no Assayer content %s (the package lives only in a sealed memfd, never a real path), found %v", when, entries)
		}
	}
	assertWorkDirEmpty("before evaluation")

	dir := t.TempDir()
	path, sha := v9s3Artifact(t, dir)
	req := v9s3BaseRequest(sha)
	v := assay.Evaluate(context.Background(), assay.Config{Repo: repo, Python: "python3"}, req, path, snap)
	if v.Verdict != assay.VerdictPass {
		t.Fatalf("expected a real pass verdict executing entirely from the sealed package with no on-disk copy, got %+v", v)
	}

	assertWorkDirEmpty("after evaluation")
}
