//go:build redteam

// v6_s5_git_isolation_test.go is the Sol redteam v6 Permanent Regression
// Corpus, cases 14-18, owned by Session 5 (Phase 5: complete Git isolation
// -- the approved-merge path's neutralizer must strip every inherited
// repository-redirection GIT_* variable, and quarantine preservation must
// go through the same controlled plumbing, never repository hooks/filters).
// See agents/governator-sol-upgrade6-plan.md Session 5 and
// agents/governator-sol-upgrade6.md P0-7/P0-8. internal/gitplumb/gitplumb.go's
// neutralEnv only drops GIT_CONFIG_GLOBAL/GIT_CONFIG_SYSTEM/
// GIT_CONFIG_NOSYSTEM/GIT_INDEX_FILE/GIT_TERMINAL_PROMPT -- GIT_OBJECT_DIRECTORY,
// GIT_ALTERNATE_OBJECT_DIRECTORIES, GIT_DIR, and GIT_WORK_TREE all pass
// through untouched. internal/runtime/runtime.go's quarantine path (the
// `git commit --allow-empty` inside runOnce's violations branch) runs a
// plain `shell(ctx, work, ...)` in the ordinary repository context, sharing
// the common hooks dir a linked worktree inherits -- unlike the approved
// path, which already goes through gitplumb's isolated plumbing. These tests
// are active in S5; they run the real Governator runtime end to end and assert
// the black-box security outcome.
package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestV6Case14GitObjectDirectoryRedirectionDoesNotEscapeRepository is
// corpus case 14 (report P0-7): GIT_OBJECT_DIRECTORY in the ambient
// environment surrounding a governed run redirects newly written objects
// into an external directory instead of the repository's own
// .git/objects. After the run, the approved commit must still be present
// in the repository's own object database (git cat-file -e HEAD must
// succeed against root, independent of the poisoned env var, which this
// test explicitly unsets before checking -- mirroring the report's own
// methodology of removing the variables before verifying).
func TestV6Case14GitObjectDirectoryRedirectionDoesNotEscapeRepository(t *testing.T) {

	root := fixtureRepo(t)
	useDegradedContainmentScopeForTest(t)
	external := t.TempDir()
	t.Setenv("GIT_OBJECT_DIRECTORY", external)

	c := baseContract(root)
	c.Success.Validators = []string{"test -f output/result.txt"}
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)

	// Mirror the report's own verification order: remove the hostile
	// variable, THEN check the repository's own object database.
	os.Unsetenv("GIT_OBJECT_DIRECTORY")

	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED even with a hostile GIT_OBJECT_DIRECTORY in the ambient environment, got status=%s message=%s", rec.Status, rec.Message)
	}
	paths := committedPaths(t, root)
	if !contains(paths, "output/result.txt") {
		t.Fatalf("approved output is not present in the repository's own committed tree (objects redirected externally?): %v", paths)
	}
	if err := exec.Command("git", "-C", root, "cat-file", "-e", "HEAD").Run(); err != nil {
		t.Fatalf("HEAD commit is not present in the repository's own object database after removing the hostile GIT_OBJECT_DIRECTORY: %v", err)
	}
}

// TestV6Case15GitAlternateObjectDirectoriesRedirectionDoesNotEscapeRepository
// is corpus case 15 (report P0-7): the report's exact combination --
// GIT_OBJECT_DIRECTORY points at an external directory (new objects are
// written there) while GIT_ALTERNATE_OBJECT_DIRECTORIES points back at the
// repository's real .git/objects (so reads of pre-existing objects, like
// the parent commit's tree, keep working) -- letting the whole merge
// silently succeed while the newly approved objects live outside the
// repository. Same assertion shape as case 14.
func TestV6Case15GitAlternateObjectDirectoriesRedirectionDoesNotEscapeRepository(t *testing.T) {

	root := fixtureRepo(t)
	useDegradedContainmentScopeForTest(t)
	external := t.TempDir()
	realObjects := filepath.Join(root, ".git", "objects")
	t.Setenv("GIT_OBJECT_DIRECTORY", external)
	t.Setenv("GIT_ALTERNATE_OBJECT_DIRECTORIES", realObjects)

	c := baseContract(root)
	c.Success.Validators = []string{"test -f output/result.txt"}
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)

	os.Unsetenv("GIT_OBJECT_DIRECTORY")
	os.Unsetenv("GIT_ALTERNATE_OBJECT_DIRECTORIES")

	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED even with hostile GIT_OBJECT_DIRECTORY/GIT_ALTERNATE_OBJECT_DIRECTORIES in the ambient environment, got status=%s message=%s", rec.Status, rec.Message)
	}
	paths := committedPaths(t, root)
	if !contains(paths, "output/result.txt") {
		t.Fatalf("approved output is not present in the repository's own committed tree (objects redirected externally via the alternates trick?): %v", paths)
	}
	if err := exec.Command("git", "-C", root, "cat-file", "-e", "HEAD").Run(); err != nil {
		t.Fatalf("HEAD commit is not present in the repository's own object database after removing the hostile GIT_* env: %v", err)
	}
}

// TestV6Case16GitDirWorkTreeInjectionDoesNotRedirectApprovedCommit is
// corpus case 16 (report P0-7): GIT_DIR and GIT_WORK_TREE in the ambient
// environment redirect Git's entire notion of "which repository/worktree
// am I operating on." An approved run's commit must land in the real
// target repository (root), never wherever the injected GIT_DIR/
// GIT_WORK_TREE point.
func TestV6Case16GitDirWorkTreeInjectionDoesNotRedirectApprovedCommit(t *testing.T) {

	root := fixtureRepo(t)
	useDegradedContainmentScopeForTest(t)
	decoy := t.TempDir()
	if err := exec.Command("git", "-C", decoy, "init", "-b", "main").Run(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_DIR", filepath.Join(decoy, ".git"))
	t.Setenv("GIT_WORK_TREE", decoy)

	c := baseContract(root)
	c.Success.Validators = []string{"test -f output/result.txt"}
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)

	os.Unsetenv("GIT_DIR")
	os.Unsetenv("GIT_WORK_TREE")

	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED even with hostile GIT_DIR/GIT_WORK_TREE in the ambient environment, got status=%s message=%s", rec.Status, rec.Message)
	}
	paths := committedPaths(t, root)
	if !contains(paths, "output/result.txt") {
		t.Fatalf("approved output is not present in the REAL target repository's committed tree -- GIT_DIR/GIT_WORK_TREE injection may have redirected the commit elsewhere: %v", paths)
	}
	if err := exec.Command("git", "-C", decoy, "rev-parse", "--verify", "HEAD").Run(); err == nil {
		decoyLog, _ := exec.Command("git", "-C", decoy, "log", "--oneline").CombinedOutput()
		t.Fatalf("the decoy repository pointed to by the injected GIT_DIR/GIT_WORK_TREE received commits instead of the real target repository: %s", decoyLog)
	}
}

// TestV6Case17QuarantinePreCommitHookNeverFires is corpus case 17 (report
// P0-8): unlike TestAttack1HostilePreCommitHookNeverStagesForbiddenFile/
// TestAttack2HostileGlobalHooksPathNeverStagesForbiddenFile (hooks_test.go),
// which cover the ORDINARY APPROVED merge path (already routed through
// gitplumb's isolated plumbing with an empty hooks dir), this attack
// targets the QUARANTINE path specifically: runOnce's violations branch
// still runs a plain `git add -A` / `git commit --allow-empty` via
// runtime.go's shell() helper in the ordinary repository context, which
// shares the common hooks directory a linked worktree inherits. A hostile
// pre-commit hook must never fire during quarantine preservation.
func TestV6Case17QuarantinePreCommitHookNeverFires(t *testing.T) {

	root := fixtureRepo(t)
	useDegradedContainmentScopeForTest(t)
	hookMarker := filepath.Join(root, "quarantine-hook-ran.txt")
	hook := filepath.Join(root, ".git", "hooks", "pre-commit")
	hookScript := "#!/bin/sh\nprintf 'injected\\n' > " + hookMarker + "\n"
	if err := os.WriteFile(hook, []byte(hookScript), 0755); err != nil {
		t.Fatal(err)
	}

	c := baseContract(root)
	// A write outside Allowed.Write ("output/**") forces a violation, and
	// therefore quarantine, deterministically -- independent of the hook.
	bin := fakeBackend(t, standardBackendBody(`
printf 'out-of-scope\n' > unauthorized.txt
`))
	rec := runGoverned(t, t.TempDir(), bin, c)

	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected QUARANTINED (backend wrote outside its allowed scope), got status=%s message=%s", rec.Status, rec.Message)
	}
	if _, err := os.Stat(hookMarker); !os.IsNotExist(err) {
		t.Fatal("hostile pre-commit hook fired during quarantine preservation -- quarantining an agent must not execute repository-controlled code")
	}
}

// TestV6Case18QuarantineCleanFilterNeverRuns is corpus case 18 (report
// P0-8): the same quarantine-path gap as case 17, for a configured
// filter.<name>.clean instead of a hook -- mirrors
// TestAttack4CleanFilterNeverAltersCommittedContent (hooks_test.go), which
// covers the ordinary approved path, applied to the quarantine path
// specifically.
func TestV6Case18QuarantineCleanFilterNeverRuns(t *testing.T) {

	root := fixtureRepo(t)
	useDegradedContainmentScopeForTest(t)
	if err := os.WriteFile(filepath.Join(root, ".gitattributes"), []byte("output/result.txt filter=redact\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".gitattributes")
	git(t, root, "commit", "-m", "add attributes")

	filterMarker := filepath.Join(t.TempDir(), "filter-ran.txt")
	filterScript := filepath.Join(t.TempDir(), "redact-filter.sh")
	filterBody := "#!/bin/sh\nprintf ran > " + filterMarker + "\nsed 's/ok/PWNED/'\n"
	if err := os.WriteFile(filterScript, []byte(filterBody), 0755); err != nil {
		t.Fatal(err)
	}
	git(t, root, "config", "filter.redact.clean", filterScript)
	git(t, root, "config", "filter.redact.smudge", "cat")

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(`
printf 'out-of-scope\n' > unauthorized.txt
`))
	rec := runGoverned(t, t.TempDir(), bin, c)

	if rec.Status != "QUARANTINED" {
		t.Fatalf("expected QUARANTINED (backend wrote outside its allowed scope), got status=%s message=%s", rec.Status, rec.Message)
	}
	if _, err := os.Stat(filterMarker); !os.IsNotExist(err) {
		t.Fatal("configured clean filter executed during quarantine preservation -- quarantine commits must go through the same controlled, filter-free plumbing as approved trees")
	}
}
