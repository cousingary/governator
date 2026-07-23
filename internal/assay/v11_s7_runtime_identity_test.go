//go:build redteam

// v11_s7_runtime_identity_test.go implements Sol11 rc5 Session 7's P1-1
// mandatory red-team corpus (agents/governator-sol-upgrade11.md "P1-1:
// Python runtime identity omits executable bytecode and symlinks",
// agents/governator-sol-upgrade11-rc5-plan.md Session 7, manifest cases
// 183-185 / report corpus 34-36).
//
// The pre-P1-1 defect: hashPathTree deliberately skipped __pycache__
// directories and symlinks when hashing StdlibReadRoots for
// RuntimeManifest.RuntimeHash/DependencyHash -- so a same-path .pyc change,
// a retargeted symlink, or a native extension reached only through a
// symlink could all change what Evaluate's subprocess actually imports
// while the frozen runtime identity stayed byte-for-byte unchanged. The fix
// walks __pycache__ like any other directory and resolves symlinks,
// hashing both the symlink's own target identity and the resolved target's
// content under the symlink's own logical path (see hashPathTree's doc
// comment in snapshot.go). Each case here drives hashPathTree directly
// against a throwaway fixture root, matching cases 27/28's existing
// pattern (TestV10Case27/28 in v10_s5_managed_runtime_test.go) rather than
// this host's real stdlib, which may not be writable, and mutating it
// would leak a side effect into shared host state for the run's duration.
package assay

import (
	"os"
	"path/filepath"
	"testing"
)

// TestV11Case38MaliciousPycChangeWithoutSourceChangeInvalidatesReplay is
// corpus 34: a .pyc file inside __pycache__ changes while no .py source
// anywhere in the tree changes. Before the fix, __pycache__ was skipped
// entirely, so this tamper was invisible to the frozen tree hash even
// though Python can and does execute a cached .pyc without ever re-reading
// its source.
func TestV11Case38MaliciousPycChangeWithoutSourceChangeInvalidatesReplay(t *testing.T) {
	root := t.TempDir()
	srcFile := filepath.Join(root, "mod.py")
	if err := os.WriteFile(srcFile, []byte("VALUE = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pycacheDir := filepath.Join(root, "__pycache__")
	if err := os.MkdirAll(pycacheDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pycFile := filepath.Join(pycacheDir, "mod.cpython-312.pyc")
	if err := os.WriteFile(pycFile, []byte("ORIGINAL BYTECODE BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}

	before, err := hashPathTree([]string{root})
	if err != nil {
		t.Fatalf("hash tree before pyc tamper: %v", err)
	}
	if before == "" {
		t.Fatal("expected a non-empty hash for a non-empty fixture")
	}

	// Tamper ONLY the cached bytecode -- the .py source is untouched.
	if err := os.WriteFile(pycFile, []byte("TAMPERED BYTECODE BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}

	after, err := hashPathTree([]string{root})
	if err != nil {
		t.Fatalf("hash tree after pyc tamper: %v", err)
	}
	if after == before {
		t.Fatal("expected the tree hash to change when a __pycache__ .pyc file's bytes change, even with the .py source untouched -- Python can execute a cached .pyc directly")
	}
}

// TestV11Case39SymlinkRetargetWithIdenticalBytesElsewhereInvalidatesReplay
// is corpus 35: a symlinked module changes WHICH target it points to, while
// the new target's bytes happen to be byte-identical to some unrelated
// content -- so a hash that only ever followed the symlink to hash content,
// and never recorded the symlink's own target identity, would see the same
// bytes hashed under the same logical path and report no change at all.
// hashPathTree must record the symlink's resolved target path itself as
// part of the tree's identity, not merely the bytes found there.
func TestV11Case39SymlinkRetargetWithIdenticalBytesElsewhereInvalidatesReplay(t *testing.T) {
	root := t.TempDir()
	targetA := filepath.Join(t.TempDir(), "targetA.py")
	targetB := filepath.Join(t.TempDir(), "targetB.py")
	identicalContent := []byte("SENTINEL = 'same-bytes-both-targets'\n")
	if err := os.WriteFile(targetA, identicalContent, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(targetB, identicalContent, 0o644); err != nil {
		t.Fatal(err)
	}

	link := filepath.Join(root, "module.py")
	if err := os.Symlink(targetA, link); err != nil {
		t.Fatal(err)
	}

	before, err := hashPathTree([]string{root})
	if err != nil {
		t.Fatalf("hash tree before retarget: %v", err)
	}
	if before == "" {
		t.Fatal("expected a non-empty hash for a non-empty fixture")
	}

	// Retarget the symlink to a DIFFERENT file with IDENTICAL bytes -- a
	// content-only hash would see nothing change here.
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetB, link); err != nil {
		t.Fatal(err)
	}

	after, err := hashPathTree([]string{root})
	if err != nil {
		t.Fatalf("hash tree after retarget: %v", err)
	}
	if after == before {
		t.Fatal("expected the tree hash to change when a symlink is retargeted to a different path, even with byte-identical content at both targets -- hashing content alone silently missed the retarget")
	}
}

// TestV11Case40NativeExtensionReachedThroughSymlinkChangeInvalidatesReplay
// is corpus 36: a native extension (.so) reached only through a symlink
// changes bytes at its real, resolved location. Before the fix, symlinks
// were skipped outright, so a native extension a stdlib layout reaches only
// through a symlink (common for platform-specific lib-dynload layouts)
// could change underneath the frozen runtime identity with zero effect on
// the recorded hash.
func TestV11Case40NativeExtensionReachedThroughSymlinkChangeInvalidatesReplay(t *testing.T) {
	root := t.TempDir()
	realExtDir := t.TempDir()
	realExt := filepath.Join(realExtDir, "_socket.cpython-312-x86_64-linux-gnu.so")
	if err := os.WriteFile(realExt, []byte("ORIGINAL NATIVE EXTENSION BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "_socket.cpython-312-x86_64-linux-gnu.so")
	if err := os.Symlink(realExt, link); err != nil {
		t.Fatal(err)
	}

	before, err := hashPathTree([]string{root})
	if err != nil {
		t.Fatalf("hash tree before native extension tamper: %v", err)
	}
	if before == "" {
		t.Fatal("expected a non-empty hash for a non-empty fixture")
	}

	if err := os.WriteFile(realExt, []byte("TAMPERED NATIVE EXTENSION BYTES"), 0o644); err != nil {
		t.Fatal(err)
	}

	after, err := hashPathTree([]string{root})
	if err != nil {
		t.Fatalf("hash tree after native extension tamper: %v", err)
	}
	if after == before {
		t.Fatal("expected the tree hash to change when a native extension reached only through a symlink changes bytes at its real location")
	}
}
