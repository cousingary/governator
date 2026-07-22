package stage

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// effectPaths extracts just the Path field, for assertions that only care
// which paths were reported (operation-specific assertions check Operation
// directly).
func effectPaths(effects []WriteEffect) []string {
	paths := make([]string, len(effects))
	for i, e := range effects {
		paths[i] = e.Path
	}
	return paths
}

func effectByPath(t *testing.T, effects []WriteEffect, path string) WriteEffect {
	t.Helper()
	for _, e := range effects {
		if e.Path == path {
			return e
		}
	}
	t.Fatalf("no WriteEffect for %s in %v", path, effects)
	return WriteEffect{}
}

// TestReconcileWriteSetDetectsNewAndChangedFiles is the Sol9 P1-5 unit-level
// check for stage-level ActualWriteSet: it must be a real before/after
// reconciliation of the declared write roots, not the declared roots
// restated as if they were observed. A new file and a modified file both
// count as writes; an untouched file must not.
func TestReconcileWriteSetDetectsNewAndChangedFiles(t *testing.T) {
	dir := t.TempDir()
	untouched := filepath.Join(dir, "untouched.txt")
	modified := filepath.Join(dir, "modified.txt")
	if err := os.WriteFile(untouched, []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modified, []byte("before"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotWriteRoots([]string{dir}, nil)

	// mtime is no longer part of the fingerprint at all (Sol10 P1-2), so no
	// sleep is needed here to clear coarse mtime resolution -- content
	// SHA-256 alone must distinguish the rewrite.
	created := filepath.Join(dir, "created.txt")
	if err := os.WriteFile(created, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modified, []byte("after-is-longer"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := effectPaths(reconcileWriteSet(before, []string{dir}, nil))
	sort.Strings(got)
	want := []string{created, modified}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reconcileWriteSet paths = %v, want %v (untouched.txt must not appear)", got, want)
	}
	effects := reconcileWriteSet(before, []string{dir}, nil)
	if got := effectByPath(t, effects, created).Operation; got != "created" {
		t.Fatalf("created.txt operation = %q, want created", got)
	}
	if got := effectByPath(t, effects, modified).Operation; got != "modified" {
		t.Fatalf("modified.txt operation = %q, want modified", got)
	}
}

// TestReconcileWriteSetCoversDeclaredFiles mirrors the directory case for a
// single declared write file (the WriteFiles half of a declared write
// root), independent of any containing directory.
func TestReconcileWriteSetCoversDeclaredFiles(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "RESULT.json")
	if err := os.WriteFile(target, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotWriteRoots(nil, []string{target})
	if err := os.WriteFile(target, []byte(`{"status":"complete"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	got := reconcileWriteSet(before, nil, []string{target})
	if len(got) != 1 || got[0].Path != target || got[0].Operation != "modified" {
		t.Fatalf("reconcileWriteSet = %+v, want one modified effect for %s", got, target)
	}
}

// TestReconcileWriteSetEmptyWhenNothingChanges guards against a
// reconciliation that reports every declared path as "written" regardless
// of whether anything actually happened underneath it.
func TestReconcileWriteSetEmptyWhenNothingChanges(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "stable.txt"), []byte("stable"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotWriteRoots([]string{dir}, nil)
	got := reconcileWriteSet(before, []string{dir}, nil)
	if len(got) != 0 {
		t.Fatalf("reconcileWriteSet reported unchanged files as written: %v", got)
	}
}

// TestReconcileWriteSetReportsDeletedFiles is Sol10 P1-2 manifest case 136
// (report P1-2 / rc4 Session 7): the prior reconciliation only ever walked
// the AFTER-state snapshot, so a path present before and absent after (a
// stage deleting a file it no longer needs) was never reported at all --
// the effect ledger silently under-counted every deletion a stage made.
func TestReconcileWriteSetReportsDeletedFiles(t *testing.T) {
	dir := t.TempDir()
	kept := filepath.Join(dir, "kept.txt")
	removed := filepath.Join(dir, "removed.txt")
	if err := os.WriteFile(kept, []byte("stays"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(removed, []byte("goes"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotWriteRoots([]string{dir}, nil)
	if err := os.Remove(removed); err != nil {
		t.Fatal(err)
	}

	got := reconcileWriteSet(before, []string{dir}, nil)
	if len(got) != 1 {
		t.Fatalf("reconcileWriteSet = %+v, want exactly one effect (the deletion)", got)
	}
	if got[0].Path != removed || got[0].Operation != "deleted" {
		t.Fatalf("reconcileWriteSet = %+v, want a single deleted effect for %s", got, removed)
	}
}

// TestReconcileWriteSetDetectsSameSizeRewriteWithRestoredMtime is Sol10
// P1-2 manifest case 137: the prior fingerprint was size+mtime, so a stage
// that rewrites a file with same-length content and then restores the
// original mtime (or a filesystem coarse enough that the rewrite lands in
// the same mtime tick) reported no change at all. Content SHA-256 must
// catch this regardless of size or timestamp.
func TestReconcileWriteSetDetectsSameSizeRewriteWithRestoredMtime(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "same-size.txt")
	original := []byte("AAAAAAAAAA")
	if err := os.WriteFile(target, original, 0o644); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	originalModTime := info.ModTime()
	before := snapshotWriteRoots([]string{dir}, nil)

	rewritten := []byte("BBBBBBBBBB") // same length, different bytes
	if len(rewritten) != len(original) {
		t.Fatalf("test fixture bug: rewritten length %d != original length %d", len(rewritten), len(original))
	}
	if err := os.WriteFile(target, rewritten, 0o644); err != nil {
		t.Fatal(err)
	}
	// Restore the exact original mtime -- the prior size+mtime fingerprint
	// would see an identical pair to "before" and report no change.
	if err := os.Chtimes(target, originalModTime, originalModTime); err != nil {
		t.Fatal(err)
	}

	got := reconcileWriteSet(before, []string{dir}, nil)
	if len(got) != 1 || got[0].Path != target || got[0].Operation != "modified" {
		t.Fatalf("reconcileWriteSet = %+v, want a single modified effect for %s (same size, restored mtime, different content)", got, target)
	}
}

// TestReconcileWriteSetAttributesRename is Sol10 P1-2's rename-attribution
// requirement: a path that disappears and a different path that appears
// with the same underlying file (same device+inode, since a real rename(2)
// within one write root's filesystem preserves it) must be reported as one
// "renamed" effect, not an unrelated created+deleted pair.
func TestReconcileWriteSetAttributesRename(t *testing.T) {
	dir := t.TempDir()
	from := filepath.Join(dir, "old-name.txt")
	to := filepath.Join(dir, "new-name.txt")
	if err := os.WriteFile(from, []byte("rename-me"), 0o644); err != nil {
		t.Fatal(err)
	}
	before := snapshotWriteRoots([]string{dir}, nil)
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}

	got := reconcileWriteSet(before, []string{dir}, nil)
	if len(got) != 1 {
		t.Fatalf("reconcileWriteSet = %+v, want exactly one effect (the rename), not a separate created+deleted pair", got)
	}
	if got[0].Path != to || got[0].Operation != "renamed" || got[0].RenamedFrom != from {
		t.Fatalf("reconcileWriteSet = %+v, want one renamed effect from %s to %s", got, from, to)
	}
}
