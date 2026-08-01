package runtime

import (
	"os"
	"path/filepath"
	goruntime "runtime"
	"testing"

	"github.com/cousingary/governator/internal/pathsafe"
)

// TestOpenBeneathRefusesParentComponentSymlink is Sol P1-7's regression test
// / report §9 attack 22: the pre-existing no-follow helpers in artifacts.go
// opened an already-joined absolute path with a bare O_NOFOLLOW, which only
// ever guards the FINAL path component. An attacker who replaces a PARENT
// directory component with a symlink pointing outside baseDir sailed
// straight through undetected -- there was no flag that could protect a
// component that isn't the last one. Proves the fix: openBeneath (openat2
// RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS) refuses the
// open outright when a non-final component is a symlink, and the escape
// target is never touched.
func TestOpenBeneathRefusesParentComponentSymlink(t *testing.T) {
	base := t.TempDir()
	escapeTarget := t.TempDir()

	// The attacker's parent-component symlink: base/staged is a symlink
	// pointing entirely outside base, at another real directory.
	if err := os.Symlink(escapeTarget, filepath.Join(base, "staged")); err != nil {
		t.Fatal(err)
	}

	f, err := pathsafe.OpenBeneath(base, "staged/escaped.txt", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err == nil {
		f.Close()
		t.Fatal("expected OpenBeneath to refuse a path through a symlinked parent component")
	}

	if _, statErr := os.Stat(filepath.Join(escapeTarget, "escaped.txt")); !os.IsNotExist(statErr) {
		t.Fatal("escape target was written despite openBeneath returning an error")
	}
}

// TestOpenBeneathRefusesParentComponentSymlinkEvenAfterPriorSafeResolution
// proves this holds even in the exact TOCTOU shape the report describes: a
// caller resolves/validates a path when the parent is still a real
// directory (mirroring an earlier "scan" step), the parent is then swapped
// for a symlink, and the LATER open (the actual read/write) must still be
// refused -- there is no cached "this was safe" state that survives the
// swap, because every openBeneath call re-resolves from scratch.
func TestOpenBeneathRefusesParentComponentSymlinkEvenAfterPriorSafeResolution(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("ordinary beneath-open success requires Linux openat2")
	}
	base := t.TempDir()
	escapeTarget := t.TempDir()
	parent := filepath.Join(base, "artifacts")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}

	// A first, legitimate write while "artifacts" is still a real directory
	// -- this is the safe state a scan step would have observed.
	if err := writeNewBeneath(base, "artifacts/first.txt", []byte("ok"), 0600); err != nil {
		t.Fatalf("expected the legitimate first write to succeed, got: %v", err)
	}

	// The attack: the parent directory is replaced with a symlink between
	// that earlier safe state and the next open.
	if err := os.RemoveAll(parent); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(escapeTarget, parent); err != nil {
		t.Fatal(err)
	}

	if err := writeNewBeneath(base, "artifacts/second.txt", []byte("escape"), 0600); err == nil {
		t.Fatal("expected the second write to be refused once the parent became a symlink")
	}
	if _, statErr := os.Stat(filepath.Join(escapeTarget, "second.txt")); !os.IsNotExist(statErr) {
		t.Fatal("escape target was written despite the parent-component symlink swap")
	}
}

// TestOpenBeneathAllowsOrdinaryNestedPaths is the negative-case complement:
// legitimate multi-level relative paths beneath a real directory tree must
// keep working -- P1-7's fix must not turn every ordinary artifact write
// into a refusal.
func TestOpenBeneathAllowsOrdinaryNestedPaths(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("ordinary beneath-open success requires Linux openat2")
	}
	base := t.TempDir()
	if err := os.MkdirAll(filepath.Join(base, "a", "b"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeNewBeneath(base, "a/b/file.txt", []byte("hello"), 0600); err != nil {
		t.Fatalf("expected an ordinary nested write to succeed, got: %v", err)
	}
	data, _, err := readRegularBeneath(base, "a/b/file.txt")
	if err != nil {
		t.Fatalf("expected an ordinary nested read to succeed, got: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("unexpected content: %q", data)
	}
}

// TestOpenBeneathRefusesFinalComponentSymlink covers the classic
// final-component case too (the one O_NOFOLLOW already handled) to confirm
// the openat2-based replacement didn't regress it.
func TestOpenBeneathRefusesFinalComponentSymlink(t *testing.T) {
	base := t.TempDir()
	escapeTarget := filepath.Join(t.TempDir(), "target.txt")
	if err := os.WriteFile(escapeTarget, []byte("real"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(escapeTarget, filepath.Join(base, "link.txt")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readRegularBeneath(base, "link.txt"); err == nil {
		t.Fatal("expected openBeneath to refuse a final-component symlink")
	}
}
