//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestV16Case394ReleaseTagUnreachableFromMainFailsTopology is v16-release
// report case 394 (R1): the entire rc7/rc8 program lived on an unmerged side
// branch while main was 45+ commits stale. A release tag main cannot reach is
// the sharpest failure mode -- .github/workflows/ci.yml triggers on
// push: [main] and would test a stale tree, and `go install ...@latest`
// resolves the highest non-prerelease tag reachable from the default branch.
// scripts/check_branch_topology.py is the durable half of R1's fix: every v*
// semver release tag must be reachable from the release branch (main) before a
// release ships. This proves it actually rejects an unreachable tag and a
// missing release branch, rather than only that the real repo happens to be
// clean today.
func TestV16Case394ReleaseTagUnreachableFromMainFailsTopology(t *testing.T) {
	repoRoot := repoRootForBundleTests(t)
	checker := filepath.Join(repoRoot, "scripts", "check_branch_topology.py")

	runCheck := func(t *testing.T, repo string, branch string) (string, error) {
		t.Helper()
		args := []string{checker, "--repo", repo}
		if branch != "" {
			args = append(args, "--release-branch", branch)
		}
		out, err := exec.Command("python3", args...).CombinedOutput()
		return string(out), err
	}

	// buildTopologyFixture creates an isolated git repo whose default branch
	// is `main`. If unreachableTag is non-empty, a side branch is created off
	// main's initial commit, advanced one commit, and that tag is placed on
	// the side-branch tip -- unreachable from main. mainTag (if non-empty) is
	// placed on main itself. The fixture is left with `main` checked out.
	buildTopologyFixture := func(t *testing.T, mainTag, unreachableTag string) string {
		t.Helper()
		fixture := t.TempDir()
		runGit := func(args ...string) {
			t.Helper()
			cmd := exec.Command("git", args...)
			cmd.Dir = fixture
			cmd.Env = append(os.Environ(),
				"GIT_AUTHOR_NAME=redteam", "GIT_AUTHOR_EMAIL=redteam@example.com",
				"GIT_COMMITTER_NAME=redteam", "GIT_COMMITTER_EMAIL=redteam@example.com")
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("git %v: %v\n%s", args, err, out)
			}
		}
		mustWrite := func(rel, content string) {
			t.Helper()
			p := filepath.Join(fixture, rel)
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		runGit("init", "-q")
		// Force the default branch to `main` regardless of the local git
		// init.defaultBranch setting -- the checker keys off refs/heads/main.
		runGit("symbolic-ref", "HEAD", "refs/heads/main")
		runGit("config", "user.email", "redteam@example.com")
		runGit("config", "user.name", "redteam")
		mustWrite("README.md", "fixture\n")
		runGit("add", "-A")
		runGit("commit", "-q", "-m", "initial release")
		if mainTag != "" {
			runGit("tag", mainTag)
		}
		if unreachableTag != "" {
			runGit("checkout", "-q", "-b", "side")
			mustWrite("side.txt", "work not on main\n")
			runGit("add", "-A")
			runGit("commit", "-q", "-m", "side work")
			runGit("tag", unreachableTag)
			runGit("checkout", "-q", "main")
		}
		return fixture
	}

	t.Run("the real repo's release tags are all reachable from main", func(t *testing.T) {
		// The live R1 demonstration: before v16-release S2 fast-forwards
		// main, this subtest FAILS (rc8 is unreachable) -- which is the
		// finding itself. After S2 moves main to the release tip, every
		// release tag is reachable and this passes for every later session
		// and every CI run, because adding non-tagged dev commits to a side
		// branch can never make an existing release tag unreachable.
		out, err := runCheck(t, repoRoot, "")
		if err != nil {
			t.Fatalf("expected every release tag reachable from main on the real repo, got:\n%s", out)
		}
	})

	t.Run("a release tag unreachable from main is rejected and named", func(t *testing.T) {
		fixture := buildTopologyFixture(t, "v1.0.0", "v1.1.0")
		out, err := runCheck(t, fixture, "")
		if err == nil {
			t.Fatalf("expected check_branch_topology.py to reject an unreachable release tag, but it passed:\n%s", out)
		}
		if !strings.Contains(out, "RELEASE_TAG_UNREACHABLE_FROM_RELEASE_BRANCH") {
			t.Fatalf("expected the named error RELEASE_TAG_UNREACHABLE_FROM_RELEASE_BRANCH, got:\n%s", out)
		}
		if !strings.Contains(out, "v1.1.0") {
			t.Fatalf("expected the failure to name the unreachable tag v1.1.0, got:\n%s", out)
		}
		// The reachable tag must NOT be reported as the offender.
		if strings.Contains(out, "v1.0.0") {
			t.Fatalf("expected v1.0.0 (reachable) to be left alone, but it appears in the failure:\n%s", out)
		}
	})

	t.Run("a fixture whose tags are all on main passes", func(t *testing.T) {
		fixture := buildTopologyFixture(t, "v1.0.0", "")
		if out, err := runCheck(t, fixture, ""); err != nil {
			t.Fatalf("expected the checker to accept a fixture whose tags are all on main, got:\n%s", out)
		}
	})

	t.Run("a repo with no release branch fails with a named error", func(t *testing.T) {
		// Default branch renamed away from `main` entirely: there is no
		// branch for tags to be reachable from, which is itself a blocker.
		fixture := buildTopologyFixture(t, "v1.0.0", "")
		if out, err := exec.Command("git", "-C", fixture, "branch", "-m", "main", "develop").CombinedOutput(); err != nil {
			t.Fatalf("git branch -m: %v\n%s", err, out)
		}
		out, err := runCheck(t, fixture, "")
		if err == nil {
			t.Fatalf("expected the checker to reject a repo with no main branch, but it passed:\n%s", out)
		}
		if !strings.Contains(out, "RELEASE_BRANCH_MISSING") {
			t.Fatalf("expected the named error RELEASE_BRANCH_MISSING, got:\n%s", out)
		}
	})
}
