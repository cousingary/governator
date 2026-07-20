package stage

import (
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"
)

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

	// mtime resolution on some filesystems is coarse; sleep past it so a
	// same-second rewrite is still detected via the size delta at minimum.
	time.Sleep(10 * time.Millisecond)
	created := filepath.Join(dir, "created.txt")
	if err := os.WriteFile(created, []byte("new"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(modified, []byte("after-is-longer"), 0o644); err != nil {
		t.Fatal(err)
	}

	got := reconcileWriteSet(before, []string{dir}, nil)
	sort.Strings(got)
	want := []string{created, modified}
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("reconcileWriteSet = %v, want %v (untouched.txt must not appear)", got, want)
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
	if len(got) != 1 || got[0] != target {
		t.Fatalf("reconcileWriteSet = %v, want [%s]", got, target)
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
