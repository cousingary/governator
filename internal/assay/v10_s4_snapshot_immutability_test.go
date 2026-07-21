//go:build redteam

// v10_s4_snapshot_immutability_test.go implements Sol10 P0-4's mandatory
// red-team corpus (agents/governator-sol-upgrade10.md "P0-4: Assayer's
// 'immutable' snapshot is writable by the same UID",
// agents/governator-sol-upgrade10-rc4-plan.md Session 4, manifest cases
// 122-123 / report cases 21-22).
//
// BuildSnapshot's mode 0400/0500 lockdown is not immutability against a
// process sharing this OS user: it can chmod the directory back open and
// then overwrite a file in place (case 21, exercised here against
// assayer/checks.py) or unlink/rename a replacement over one (case 22,
// exercised here against cli.py). Both cases prove the mutation is caught
// by Snapshot.Verify BEFORE assay.Evaluate ever reaches the subprocess
// launch -- no external sandbox (Landlock/unshare) is needed to observe
// this, which is exactly the point: mode bits were never a real kernel
// boundary here, so the actual defense (retained-descriptor
// reverification) has to work whether or not this host can also provide
// one.
package assay

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureRepo(t *testing.T) string {
	t.Helper()
	repo, err := filepath.Abs(filepath.Join("testdata", "assayer_fixture"))
	if err != nil {
		t.Fatal(err)
	}
	return repo
}

// TestV10Case21SameUIDChmodAndInPlaceOverwriteOfChecksPyDetectedBeforeVerdict
// simulates a same-UID process that discovers the private snapshot
// directory, chmods assayer/checks.py back writable, and overwrites its
// bytes in place (same directory entry, same inode -- the content-hash
// check, not the dev/inode check, must catch this one).
func TestV10Case21SameUIDChmodAndInPlaceOverwriteOfChecksPyDetectedBeforeVerdict(t *testing.T) {
	requirePython3(t)
	repo := fixtureRepo(t)
	snap := buildTestSnapshot(t, repo)

	target := filepath.Join(snap.Dir, "assayer", "checks.py")
	if err := os.Chmod(target, 0o644); err != nil {
		t.Fatalf("simulate same-UID chmod back open: %v", err)
	}
	if err := os.WriteFile(target, []byte("def evaluate(*_a, **_k):\n    return {\"verdict\": \"pass\"}\n"), 0o644); err != nil {
		t.Fatalf("simulate same-UID in-place overwrite: %v", err)
	}

	if err := snap.Verify(); err == nil {
		t.Fatal("expected Verify to detect the in-place overwrite of checks.py, got nil error")
	} else if !strings.Contains(err.Error(), AssayerSnapshotMutated) || !strings.Contains(err.Error(), "checks.py") {
		t.Fatalf("expected %s naming checks.py, got %v", AssayerSnapshotMutated, err)
	}

	artifactDir := t.TempDir()
	path, sha := writeArtifact(t, artifactDir, "content")
	req := baseRequest(sha)

	v := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, req, path, snap)
	if v.Verdict != VerdictError || !v.HadError {
		t.Fatalf("expected error verdict for a tampered snapshot, got %+v", v)
	}
	if !strings.Contains(v.Reason, AssayerSnapshotMutated) {
		t.Fatalf("expected reason to cite %s, got %q", AssayerSnapshotMutated, v.Reason)
	}
}

// TestV10Case22SameUIDRenameOverReplacementOfCliPyDetectedBeforeVerdict
// simulates a same-UID process that chmods the snapshot directory back
// writable, unlinks cli.py, and renames a completely different file over
// it -- a fresh directory entry with a different inode (the dev/inode
// check, not the content-hash check, must catch this one), engineered to
// print a fraudulent passing verdict if it were ever actually imported and
// run.
func TestV10Case22SameUIDRenameOverReplacementOfCliPyDetectedBeforeVerdict(t *testing.T) {
	requirePython3(t)
	repo := fixtureRepo(t)
	snap := buildTestSnapshot(t, repo)

	fraudulent := filepath.Join(t.TempDir(), "fraudulent_cli.py")
	fraudulentSrc := "import sys, json\n" +
		"print(json.dumps({\"verdict\": \"pass\", \"failed_checks\": [], \"had_error\": False}))\n" +
		"sys.exit(0)\n"
	if err := os.WriteFile(fraudulent, []byte(fraudulentSrc), 0o644); err != nil {
		t.Fatal(err)
	}

	if err := os.Chmod(snap.Dir, 0o700); err != nil {
		t.Fatalf("simulate same-UID chmod of snapshot dir back open: %v", err)
	}
	target := filepath.Join(snap.Dir, "cli.py")
	if err := os.Remove(target); err != nil {
		t.Fatalf("simulate same-UID unlink of cli.py: %v", err)
	}
	if err := os.Rename(fraudulent, target); err != nil {
		t.Fatalf("simulate same-UID rename-over of cli.py: %v", err)
	}

	if err := snap.Verify(); err == nil {
		t.Fatal("expected Verify to detect the rename-over replacement of cli.py, got nil error")
	} else if !strings.Contains(err.Error(), AssayerSnapshotMutated) || !strings.Contains(err.Error(), "cli.py") {
		t.Fatalf("expected %s naming cli.py, got %v", AssayerSnapshotMutated, err)
	}

	artifactDir := t.TempDir()
	path, sha := writeArtifact(t, artifactDir, "content")
	req := baseRequest(sha)

	v := Evaluate(context.Background(), Config{Repo: repo, Python: "python3"}, req, path, snap)
	if v.Verdict != VerdictError || !v.HadError {
		t.Fatalf("expected error verdict for a tampered snapshot (never the fraudulent pass), got %+v", v)
	}
	if !strings.Contains(v.Reason, AssayerSnapshotMutated) {
		t.Fatalf("expected reason to cite %s, got %q", AssayerSnapshotMutated, v.Reason)
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
