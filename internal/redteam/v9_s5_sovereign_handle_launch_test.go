//go:build redteam

// v9_s5_sovereign_handle_launch_test.go is Sol redteam v9's rc3 Session 5
// corpus (agents/governator-sol-upgrade9-rc3-plan.md Session 5,
// agents/governator-sol-upgrade9.md P0-6): "cases 4 and 5" (replace Git
// between verification and merge invocation; replace Bash between
// verification and internal shell invocation -- must still execute the
// verified object or fail closed).
//
// P0-6 was that internal/gitplumb.runCmd verified git through the
// trusted-tool registry (gitplumb.TrustedGitPath) but then executed it by
// its enrolled PATHNAME (exec.CommandContext(ctx, gitPath, ...)), leaving a
// same-uid TOCTOU window between verification and every plumbing command a
// sovereign merge/quarantine sequence runs; internal/runtime and
// internal/runner's shell() helpers had the identical shape for bash
// (toolregistry.ResolveTrusted("bash", ...) followed by
// exec.CommandContext(ctx, bashIdentity.CanonicalPath, ...)). The fix holds
// one verified, open toolregistry.Handle per gitplumb.Session (reused for
// every plumbing command the session runs, never re-resolved from a bare
// path) and launches bash in shell() through Handle.CommandWith's fd-argv
// mechanism (the same primitive enforce.Plan.Wrap uses for unshare/self-exec,
// Sol9 P0-1/P0-2) instead of a pathname exec.CommandContext.
package redteam

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/gitplumb"
	"github.com/cousingary/governator/internal/toolregistry"
)

// resolveRealTool finds name's real on-disk binary the same way
// enrollRealControllerTools does (a fixed /usr/bin path, falling back to
// PATH lookup, canonicalized through any symlink).
func resolveRealTool(t *testing.T, name, fixedPath string) string {
	t.Helper()
	path := fixedPath
	if _, err := os.Stat(path); err != nil {
		looked, lookErr := exec.LookPath(name)
		if lookErr != nil {
			t.Fatalf("resolve real %s: %v", name, lookErr)
		}
		path = looked
	}
	if canonical, err := filepath.EvalSymlinks(path); err == nil {
		path = canonical
	}
	return path
}

// writeExecutable writes script to path with executable permissions.
func writeExecutable(t *testing.T, path, script string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
}

// swapInPlace replaces target's pathname with hostile's content while
// leaving any already-open descriptor to the pre-swap inode untouched:
// hostile is written to a sibling path first, then renamed onto target --
// rename() detaches target's name from its current inode and attaches it to
// hostile's, rather than truncating/overwriting the inode a held fd points
// at (the same technique v9_s1_wrapper_composition_test.go's Case 2 uses
// against unshare).
func swapInPlace(t *testing.T, target, script string) {
	t.Helper()
	sibling := target + ".hostile-swap"
	writeExecutable(t, sibling, script)
	if err := os.Rename(sibling, target); err != nil {
		t.Fatal(err)
	}
}

// TestV9Case4EnrolledGitSwapAfterSessionOpenCannotChangeExecutedBytes is Sol
// v9 report case 4 (P0-6's Git half): gitplumb.NewSession resolves and opens
// the trusted-tool registry's verified git object exactly once, holding it
// for the Session's entire lifetime; every plumbing command that Session
// runs (hash-object, read-tree, update-index, write-tree, diff, commit-tree,
// update-ref, rev-parse) must execute through that one held descriptor, not
// by re-resolving/reopening git's enrolled pathname per command. This
// enrolls a disposable "git" wrapper that marks every invocation it actually
// serves and shells out to the REAL git binary (so the plumbing operations
// below still do real, verifiable git work), opens a Session against it, and
// only THEN swaps the enrolled pathname to a hostile stand-in that would
// fail loudly and leave its own distinct mark if it ever ran. Every
// operation the session performs afterward must still succeed via the
// pre-swap wrapper, and the marker file must never show the hostile mark.
func TestV9Case4EnrolledGitSwapAfterSessionOpenCannotChangeExecutedBytes(t *testing.T) {
	requireLinuxSealedExecution(t, "/proc/self/fd held-git execution")
	realGit := resolveRealTool(t, "git", "/usr/bin/git")

	regDir := t.TempDir()
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(regDir, "tools.yaml"))

	wrapperDir := t.TempDir()
	wrapperPath := filepath.Join(wrapperDir, "git")
	marker := filepath.Join(t.TempDir(), "marker.log")
	honest := "#!/bin/sh\necho honest >> '" + marker + "'\nexec '" + realGit + "' \"$@\"\n"
	writeExecutable(t, wrapperPath, honest)
	if _, err := toolregistry.Enroll("git", wrapperPath); err != nil {
		t.Fatal(err)
	}

	// A real repo, seeded with the actual system git -- independent of the
	// enrolled wrapper above, exactly like gitplumb_test.go's own newRepo
	// helper and this package's fixtureRepo.
	root := fixtureRepo(t)

	ctx := context.Background()
	sess, err := gitplumb.NewSession(ctx, root)
	if err != nil {
		t.Fatalf("open session against the honest wrapper: %v", err)
	}
	defer sess.Close()

	// Same-uid replacement of the enrolled git binary AFTER the session
	// already holds an open, verified descriptor to the honest wrapper.
	hostile := "#!/bin/sh\necho hostile >> '" + marker + "'\nexit 1\n"
	swapInPlace(t, wrapperPath, hostile)

	baseline, err := sess.RevParseTree(ctx, "HEAD")
	if err != nil {
		t.Fatalf("post-swap rev-parse through held handle: %v", err)
	}
	if err := sess.ReadTreeIntoIndex(ctx, baseline); err != nil {
		t.Fatalf("post-swap read-tree through held handle: %v", err)
	}
	newFile := filepath.Join(root, "post-swap.txt")
	if err := os.WriteFile(newFile, []byte("added after swap\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := sess.UpdateIndexAddFile(ctx, newFile, "post-swap.txt"); err != nil {
		t.Fatalf("post-swap update-index through held handle: %v", err)
	}
	tree, err := sess.WriteTree(ctx)
	if err != nil {
		t.Fatalf("post-swap write-tree through held handle: %v", err)
	}
	diff, err := sess.DiffTreePaths(ctx, baseline, tree)
	if err != nil {
		t.Fatalf("post-swap diff through held handle: %v", err)
	}
	if len(diff) != 1 || diff[0] != "post-swap.txt" {
		t.Fatalf("expected exactly post-swap.txt in the diff, got %v", diff)
	}
	commit, err := sess.CommitTree(ctx, tree, "", "post-swap commit\n")
	if err != nil {
		t.Fatalf("post-swap commit-tree through held handle: %v", err)
	}
	if err := sess.UpdateRefCAS(ctx, root, "refs/heads/gov-post-swap", commit, strings.Repeat("0", 40)); err != nil {
		t.Fatalf("post-swap update-ref through held handle: %v", err)
	}

	logBytes, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker log: %v", err)
	}
	lines := strings.Fields(string(logBytes))
	if len(lines) == 0 {
		t.Fatal("expected the honest wrapper to have run at least once")
	}
	for _, line := range lines {
		if line != "honest" {
			t.Fatalf("hostile git ran after the same-uid swap: marker log = %q", string(logBytes))
		}
	}
}

// TestV9Case5EnrolledBashSwapAfterHandleOpenCannotChangeExecutedBytes is Sol
// v9 report case 5 (P0-6's Bash half): internal/runtime and internal/runner's
// shell() helpers now launch bash through toolregistry.Handle.CommandWith's
// fd-argv mechanism instead of a pathname exec.CommandContext against
// bashIdentity.CanonicalPath. This proves that exact primitive -- resolve,
// open, hold, THEN swap the enrolled pathname, THEN launch through the held
// handle -- executes only the pre-swap object, mirroring
// v9_s1_wrapper_composition_test.go's TestV9Case2 (which proves the
// identical shape for unshare).
func TestV9Case5EnrolledBashSwapAfterHandleOpenCannotChangeExecutedBytes(t *testing.T) {
	requireLinuxSealedExecution(t, "/proc/self/fd held-bash execution")
	regDir := t.TempDir()
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(regDir, "tools.yaml"))

	wrapperDir := t.TempDir()
	wrapperPath := filepath.Join(wrapperDir, "bash")
	honest := "#!/bin/sh\nprintf honest-bash\nexit 0\n"
	writeExecutable(t, wrapperPath, honest)
	if _, err := toolregistry.Enroll("bash", wrapperPath); err != nil {
		t.Fatal(err)
	}

	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	bashHandle, err := registry.ResolveHandle("bash", "bash", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatalf("resolve trusted bash handle against the honest wrapper: %v", err)
	}
	defer bashHandle.Close()

	// Same-uid replacement of the enrolled bash binary AFTER the handle is
	// already open, exactly the window P0-6 requires be closed.
	hostile := "#!/bin/sh\nprintf hostile-bash\nexit 1\n"
	swapInPlace(t, wrapperPath, hostile)

	ctx := context.Background()
	cmd, err := bashHandle.Command(ctx)
	if err != nil {
		t.Fatalf("launch through held bash handle: %v", err)
	}
	out, runErr := cmd.Output()
	if runErr != nil {
		t.Fatalf("verified bash object did not run (the swapped replacement may have executed instead): %v", runErr)
	}
	if got := strings.TrimSpace(string(out)); got != "honest-bash" {
		t.Fatalf("swap changed the executed bytes: got %q", got)
	}
}
