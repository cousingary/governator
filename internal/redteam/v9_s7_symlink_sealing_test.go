//go:build redteam

// v9_s7_symlink_sealing_test.go is Sol redteam v9's rc3 Session 7 corpus
// (agents/governator-sol-upgrade9-rc3-plan.md Session 7,
// agents/governator-sol-upgrade9.md P1-3 + P1-4): report cases 6, 33, 34,
// 35, 36, 37.
//
// P1-3 was that internal/enforce/landlock.go's writeCarveOuts validated
// lexical containment (filepath.Abs/Rel) and then inspected the declared
// write-dir/write-file path with os.Stat, which follows symlinks -- a
// declared path lexically inside the workspace could be, or gain a parent
// that became, a symlink resolving outside the workspace while still
// passing the lexical check. Every write root (and the workspace argument
// itself) is now resolved through internal/pathsafe's openat2
// (RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS) against a
// held directory descriptor, so any symlink anywhere in the path -- final
// component or a parent -- is refused as one atomic kernel operation, and
// the Landlock rule is built from the real path that resolution actually
// produced.
//
// Cases 33-36 drive the real gov __sandbox_exec entry point (the same
// binary/argv shape enforce.Plan.Wrap composes in production) directly,
// rather than the higher-level contract pipeline -- this is the exact
// boundary P1-3 is about, and matches the mechanism-level testing style
// v9_s5's cases 4/5 used for the analogous P0-6 handle-swap corpus.
//
// P1-4 (case 6) was that SealedExecutablePath/SealedExecutablePathIn only
// chmod a private temp copy (0500/0400), which denies accidental writes
// from a correctly-confined stage but does not stop another process with
// the same UID from chmod'ing the directory/file back open, replacing the
// file, or recreating the directory contents. Kernel content sealing
// (memfd_create+F_ADD_SEALS) was evaluated and rejected: linkat(2)
// publishing a sealed memfd's anonymous inode into a real, PATH-
// discoverable/Landlock-restrictable directory fails with EXDEV
// (cross-device link) on this host, verified empirically, because the two
// live on different filesystems/superblocks. Every SealedExecutablePath/
// SealedExecutablePathIn caller instead now receives a *toolregistry.
// SealedCopy that retains an open read-only descriptor plus a golden
// dev/inode/sha256 record from the moment the copy is published, and every
// call site calls its Verify method immediately before the launch that
// will reference the copy by path -- catching both an in-place content
// mutation and a directory-entry swap as a fail-closed error instead of
// silently launching tampered bytes.
package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
)

// sandboxExecCmd builds a real `gov __sandbox_exec` invocation -- the exact
// hidden entry point enforce.Plan.Wrap composes in production -- so these
// cases exercise the genuine Landlock ruleset construction and kernel
// enforcement, not a mock of it.
func sandboxExecCmd(t *testing.T, workspace string, readOnly bool, writeDirs, writeFiles []string, target string, targetArgs ...string) *exec.Cmd {
	t.Helper()
	args := []string{enforce.SandboxExecArg, "--workspace", workspace}
	if readOnly {
		args = append(args, "--readonly")
	}
	for _, d := range writeDirs {
		args = append(args, "--write-dir", d)
	}
	for _, f := range writeFiles {
		args = append(args, "--write-file", f)
	}
	args = append(args, "--", target)
	args = append(args, targetArgs...)
	cmd := exec.Command(govBinary(t), args...)
	cmd.Dir = workspace
	return cmd
}

func requireSandboxExecHost(t *testing.T) string {
	t.Helper()
	if !enforce.Supported() {
		t.Skip("conditional: this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	return sh
}

// TestV9Case33WriteRootSymlinkOutsideWorkspaceRefused is report case 33: a
// declared write-dir that is itself a symlink pointing outside the
// workspace must be refused, not silently followed into an RW grant on the
// escape target.
func TestV9Case33WriteRootSymlinkOutsideWorkspaceRefused(t *testing.T) {
	sh := requireSandboxExecHost(t)
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	outside := filepath.Join(parent, "outside")
	for _, d := range []string{workspace, outside} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	carveout := filepath.Join(workspace, "carveout")
	if err := os.Symlink(outside, carveout); err != nil {
		t.Fatal(err)
	}

	cmd := sandboxExecCmd(t, workspace, true, []string{carveout}, nil, sh, "-c", "echo pwned > "+filepath.Join(carveout, "escaped.txt"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected symlinked write-dir to be refused, got success: %s", out)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "escaped.txt")); !os.IsNotExist(statErr) {
		t.Fatal("escape target was written despite a symlinked write-dir")
	}
}

// TestV9Case34ParentDirectoryBecomesSymlinkRefused is report case 34: the
// declared write-dir's leaf component is real, but a PARENT component
// beneath the workspace has been replaced with a symlink escaping outside
// -- the lexical containment check (filepath.Rel on the declared string)
// cannot see this, only real kernel path resolution can.
func TestV9Case34ParentDirectoryBecomesSymlinkRefused(t *testing.T) {
	sh := requireSandboxExecHost(t)
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	outside := filepath.Join(parent, "outside")
	if err := os.MkdirAll(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	outsideParentSub := filepath.Join(outside, "parent", "sub")
	if err := os.MkdirAll(outsideParentSub, 0700); err != nil {
		t.Fatal(err)
	}

	parentDir := filepath.Join(workspace, "parent")
	writeDir := filepath.Join(parentDir, "sub")
	// parentDir is a symlink escaping the workspace; writeDir's declared
	// string is still lexically "workspace/parent/sub".
	if err := os.Symlink(filepath.Join(outside, "parent"), parentDir); err != nil {
		t.Fatal(err)
	}

	cmd := sandboxExecCmd(t, workspace, true, []string{writeDir}, nil, sh, "-c", "echo pwned > "+filepath.Join(writeDir, "escaped.txt"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a write-dir with a symlinked parent component to be refused, got success: %s", out)
	}
	if _, statErr := os.Stat(filepath.Join(outsideParentSub, "escaped.txt")); !os.IsNotExist(statErr) {
		t.Fatal("escape target was written despite a symlinked parent component")
	}
}

// TestV9Case35WorkspaceReachedViaSymlinkRefused is report case 35: the
// --workspace argument itself is a symlink to the real workspace directory.
// The prior implementation passed the raw workspace string straight into
// landlock.RWDirs/RODirs with no symlink check at all; resolveRealDir now
// opens it with O_NOFOLLOW and refuses a symlinked workspace argument
// outright.
func TestV9Case35WorkspaceReachedViaSymlinkRefused(t *testing.T) {
	sh := requireSandboxExecHost(t)
	parent := t.TempDir()
	realWorkspace := filepath.Join(parent, "real-workspace")
	if err := os.MkdirAll(realWorkspace, 0700); err != nil {
		t.Fatal(err)
	}
	wsLink := filepath.Join(parent, "workspace-link")
	if err := os.Symlink(realWorkspace, wsLink); err != nil {
		t.Fatal(err)
	}

	cmd := sandboxExecCmd(t, wsLink, true, nil, nil, sh, "-c", "true")
	cmd.Dir = realWorkspace
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a symlinked --workspace argument to be refused, got success: %s", out)
	}
}

// TestV9Case36PathExchangedAfterEarlierValidationRefused is report case 36:
// an earlier __sandbox_exec invocation legitimately resolves and uses a
// declared write-dir while it is a real directory (mirroring an earlier
// "this path is fine" observation an operator or caller might have made);
// the SAME declared path is then exchanged for a symlink escaping the
// workspace before the next invocation. There is no cached "already
// validated" state that carries over -- every invocation independently
// re-resolves from scratch -- so the later exec must still be refused.
func TestV9Case36PathExchangedAfterEarlierValidationRefused(t *testing.T) {
	sh := requireSandboxExecHost(t)
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	outside := filepath.Join(parent, "outside")
	for _, d := range []string{workspace, outside} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}
	writeDir := filepath.Join(workspace, "carveout")
	if err := os.MkdirAll(writeDir, 0700); err != nil {
		t.Fatal(err)
	}

	baseline := sandboxExecCmd(t, workspace, true, []string{writeDir}, nil, sh, "-c", "echo ok > "+filepath.Join(writeDir, "first.txt"))
	if out, err := baseline.CombinedOutput(); err != nil {
		t.Fatalf("expected the baseline legitimate write to succeed before the exchange, got: %v output=%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(writeDir, "first.txt")); err != nil {
		t.Fatalf("baseline write did not land: %v", err)
	}

	if err := os.RemoveAll(writeDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, writeDir); err != nil {
		t.Fatal(err)
	}

	attack := sandboxExecCmd(t, workspace, true, []string{writeDir}, nil, sh, "-c", "echo pwned > "+filepath.Join(writeDir, "second.txt"))
	out, err := attack.CombinedOutput()
	if err == nil {
		t.Fatalf("expected the exchanged path to be refused after the earlier validation, got success: %s", out)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "second.txt")); !os.IsNotExist(statErr) {
		t.Fatal("escape target was written despite the post-validation path exchange")
	}
}

// TestV9Case37WriteFileTargetReplacedByDirectoryOrSymlinkRefused is report
// case 37: a declared write-file must be a pre-existing regular file. A
// directory or a symlink (to a file outside the workspace) at that path
// must both be refused.
func TestV9Case37WriteFileTargetReplacedByDirectoryOrSymlinkRefused(t *testing.T) {
	sh := requireSandboxExecHost(t)
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	outside := filepath.Join(parent, "outside")
	for _, d := range []string{workspace, outside} {
		if err := os.MkdirAll(d, 0700); err != nil {
			t.Fatal(err)
		}
	}

	asDir := filepath.Join(workspace, "notafile")
	if err := os.MkdirAll(asDir, 0700); err != nil {
		t.Fatal(err)
	}
	dirCmd := sandboxExecCmd(t, workspace, true, nil, []string{asDir}, sh, "-c", "true")
	if out, err := dirCmd.CombinedOutput(); err == nil {
		t.Fatalf("expected write-file declared against a directory to be refused, got success: %s", out)
	}

	outsideFile := filepath.Join(outside, "target.txt")
	if err := os.WriteFile(outsideFile, []byte("real"), 0600); err != nil {
		t.Fatal(err)
	}
	asSymlink := filepath.Join(workspace, "linkfile")
	if err := os.Symlink(outsideFile, asSymlink); err != nil {
		t.Fatal(err)
	}
	symlinkCmd := sandboxExecCmd(t, workspace, true, nil, []string{asSymlink}, sh, "-c", "echo pwned > "+asSymlink)
	out, err := symlinkCmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected a symlinked write-file to be refused, got success: %s", out)
	}
	data, readErr := os.ReadFile(outsideFile)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != "real" {
		t.Fatalf("escape target was modified despite a symlinked write-file: %q", data)
	}
}

// TestV9Case6SameUIDMutationOfSealedToolCopyDetectedOrIneffective is report
// case 6 (P1-4). A published private copy is a plain chmod(0500) regular
// file, not a kernel-sealed object (memfd_create + F_ADD_SEALS cannot be
// combined with a real, multi-process pathname -- linkat(2) publishing a
// memfd's anonymous inode into a real directory fails with EXDEV on this
// host, verified empirically, not assumed), so a same-UID process CAN
// chmod it back open and overwrite it in place, or unlink and recreate the
// directory entry. What this proves instead, matching the report's
// documented fallback, is that SealedCopy.Verify -- which every call site
// now invokes immediately before launch -- catches both shapes of tamper
// and must never report a tampered copy as clean.
func TestV9Case6SameUIDMutationOfSealedToolCopyDetectedOrIneffective(t *testing.T) {
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatalf("load trusted-tool registry: %v", err)
	}
	handle, err := registry.ResolveHandle("bash", "bash", toolregistry.KindTrustedController)
	if err != nil {
		t.Skipf("conditional: bash is not an enrolled trusted controller tool on this host (%v) -- case needs it sealed", err)
	}
	defer handle.Close()

	sealed, err := handle.SealedExecutablePath()
	if err != nil {
		t.Fatalf("seal bash: %v", err)
	}
	defer sealed.Close()

	if verr := sealed.Verify(); verr != nil {
		t.Fatalf("expected a freshly published, untampered copy to verify clean, got: %v", verr)
	}

	// Attempt 1: same-UID in-place mutation -- chmod the copy back open
	// and overwrite its content without touching the directory entry.
	// dev/inode stay identical; only the bytes reachable through the
	// retained descriptor change.
	if err := os.Chmod(sealed.Path, 0600); err != nil {
		t.Fatalf("chmod sealed copy open: %v", err)
	}
	if err := os.WriteFile(sealed.Path, []byte("tampered-in-place"), 0600); err != nil {
		t.Fatalf("overwrite sealed copy in place: %v", err)
	}
	if verr := sealed.Verify(); verr == nil {
		t.Fatal("expected Verify to detect an in-place content mutation of the published copy, but it reported clean")
	}

	// Attempt 2: replace the directory entry itself (unlink + recreate at
	// the same published path) with different content -- dev/inode now
	// differ from what was published. The containing directory is
	// chmod(0500) too, so the same-UID attacker chmods it open first
	// (exactly the "chmod the directory" step the report describes) before
	// unlinking.
	if err := os.Chmod(filepath.Dir(sealed.Path), 0700); err != nil {
		t.Fatalf("chmod sealed copy directory open: %v", err)
	}
	if err := os.Remove(sealed.Path); err != nil {
		t.Fatalf("remove sealed copy path: %v", err)
	}
	if err := os.WriteFile(sealed.Path, []byte("attacker-controlled"), 0500); err != nil {
		t.Fatalf("recreate path with attacker content: %v", err)
	}
	if verr := sealed.Verify(); verr == nil {
		t.Fatal("expected Verify to detect a directory-entry swap at the published path, but it reported clean")
	}
}
