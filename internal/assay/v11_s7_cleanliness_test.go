//go:build redteam

// v11_s7_cleanliness_test.go implements Sol11 rc5 Session 7's P1-2
// mandatory red-team corpus (agents/governator-sol-upgrade11.md "P1-2:
// Failure to prove Assayer cleanliness is treated as clean",
// agents/governator-sol-upgrade11-rc5-plan.md Session 7, manifest cases
// 186-188 / report corpus 37-39). Corpus 40 ("unknown cleanliness disables
// replay" and blocks approval) is TestV11Case44 in
// internal/runtime/v11_s7_cleanliness_approval_test.go -- that assertion
// needs the full runOnce merge/approval pipeline, which does not belong to
// this package (this package's TestMain forces enforce.ForceUnsupported;
// see assay_test.go's doc comment).
//
// The pre-P1-2 defect: snapshotDirty returned a plain bool, and every
// failure path -- git unresolvable, command construction failed, `git
// status` itself failed or timed out -- fell through to `return false, ""`,
// i.e. reported "not dirty." That conflated "verified clean" with "could
// not tell" into the same false value: an indeterminate Assayer checkout
// was represented in evidence and replay identity exactly as if it had been
// checked and found clean. The fix makes snapshotDirty return a tri-state
// Cleanliness (clean/dirty/unknown); each case below drives one of the
// three failure paths directly and asserts CleanlinessUnknown, not the old
// silent CleanlinessClean.
package assay

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/toolregistry"
)

// TestV11Case41GitStatusProbeFailsInvalidatesReplay is corpus 37: `git
// status --porcelain` itself fails against a `.git` entry that exists but
// is not a real, resolvable git repository (a gitdir-pointer file naming a
// nonexistent target) -- as opposed to no `.git` entry at all, which is
// unambiguously clean (a pinned, non-git fixture has no notion of
// "uncommitted changes"). This must report CleanlinessUnknown, not the
// pre-fix silent "not dirty".
func TestV11Case41GitStatusProbeFailsInvalidatesReplay(t *testing.T) {
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatalf("load trusted-tool registry: %v", err)
	}
	if _, herr := registry.ResolveHandle("git", "git", toolregistry.KindTrustedController); herr != nil {
		t.Skipf("git not enrolled/trusted on this host: %v", herr)
	}

	repo := t.TempDir()
	// A `.git` entry exists (so the "no .git at all -> unambiguously clean"
	// short-circuit does not apply), but it is a broken gitdir-pointer file,
	// not a real repository -- `git status --porcelain -C repo` must fail.
	if err := os.WriteFile(filepath.Join(repo, ".git"), []byte("gitdir: /nonexistent/gitdir/for/case41\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	state, reason := snapshotDirty(registry, repo)
	if state != CleanlinessUnknown {
		t.Fatalf("expected CleanlinessUnknown when the git status probe fails against a broken .git entry, got %q (reason=%q)", state, reason)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason describing the probe failure")
	}
}

// TestV11Case42GitBinaryUnavailableInvalidatesReplay is corpus 38: git is
// simply not enrolled in the trusted-tool registry at all (ResolveHandle
// fails before any subprocess is even attempted). Must report
// CleanlinessUnknown, not the pre-fix silent "not dirty".
func TestV11Case42GitBinaryUnavailableInvalidatesReplay(t *testing.T) {
	repo := t.TempDir()
	if err := os.Mkdir(filepath.Join(repo, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}

	// Zero-value Registry: no tool has ever been enrolled, so
	// ResolveHandle("git", ...) fails with "no entry in the trusted-tool
	// registry" before any subprocess is attempted -- exactly "git binary
	// unavailable".
	emptyRegistry := &toolregistry.Registry{}

	state, reason := snapshotDirty(emptyRegistry, repo)
	if state != CleanlinessUnknown {
		t.Fatalf("expected CleanlinessUnknown when git is not enrolled in the trusted-tool registry, got %q (reason=%q)", state, reason)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason describing why git could not be resolved")
	}
}

// TestV11Case43GitStatusTimesOutInvalidatesReplay is corpus 39: the `git
// status --porcelain` probe exceeds its own deadline. environmentProbeTimeout
// is a package var specifically so this case can shrink it to something the
// process launch itself cannot possibly complete within, deterministically
// forcing the timeout path without an actual multi-second sleep. Uses a
// REAL, freshly `git init`'d repository (not a broken one, unlike case 41)
// so the only failure vector exercised is the deadline itself.
func TestV11Case43GitStatusTimesOutInvalidatesReplay(t *testing.T) {
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatalf("load trusted-tool registry: %v", err)
	}
	if _, herr := registry.ResolveHandle("git", "git", toolregistry.KindTrustedController); herr != nil {
		t.Skipf("git not enrolled/trusted on this host: %v", herr)
	}
	if _, lerr := exec.LookPath("git"); lerr != nil {
		t.Skip("git not on PATH to initialize the fixture repo")
	}

	repo := t.TempDir()
	initCmd := exec.Command("git", "init", repo)
	if out, ierr := initCmd.CombinedOutput(); ierr != nil {
		t.Fatalf("git init fixture repo: %v: %s", ierr, out)
	}

	original := environmentProbeTimeout
	environmentProbeTimeout = time.Nanosecond
	t.Cleanup(func() { environmentProbeTimeout = original })

	state, reason := snapshotDirty(registry, repo)
	if state != CleanlinessUnknown {
		t.Fatalf("expected CleanlinessUnknown when the git status probe exceeds its deadline, got %q (reason=%q)", state, reason)
	}
	if reason == "" {
		t.Fatal("expected a non-empty reason describing the timeout")
	}
}
