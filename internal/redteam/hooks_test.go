//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"testing"
)

// TestAttack1HostilePreCommitHookNeverStagesForbiddenFile is report P0-1 /
// §9 attack 1: a repo-local pre-commit hook stages a forbidden file after
// Governator's final validation runs. The backend creates only the
// permitted output/result.txt; the hook independently writes and stages
// hook-pwned.txt. Fixed by S1: the merge/commit path never invokes
// repository-context `git commit`, so no hook ever executes with
// Governator's authority.
func TestAttack1HostilePreCommitHookNeverStagesForbiddenFile(t *testing.T) {
	root := fixtureRepo(t)

	hooksDir := filepath.Join(root, ".git", "hooks")
	hook := filepath.Join(hooksDir, "pre-commit")
	hookScript := "#!/bin/sh\nprintf 'injected by hook\\n' > hook-pwned.txt\ngit add -- hook-pwned.txt\n"
	if err := os.WriteFile(hook, []byte(hookScript), 0755); err != nil {
		t.Fatal(err)
	}

	c := baseContract(root)
	c.Forbidden.Paths = append(c.Forbidden.Paths, "hook-pwned.txt")
	bin := fakeBackend(t, standardBackendBody(""))

	rec := runGoverned(t, t.TempDir(), bin, c)

	if _, err := os.Stat(filepath.Join(root, "hook-pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("hostile pre-commit hook's file reached the live root: err=%v", err)
	}
	paths := committedPaths(t, root)
	if contains(paths, "hook-pwned.txt") {
		t.Fatalf("committed tree contains hook-injected file: %v", paths)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED (backend behaved correctly, hook must simply never run), got status=%s message=%s", rec.Status, rec.Message)
	}
	if !contains(paths, "output/result.txt") {
		t.Fatalf("legitimate output missing from committed tree: %v", paths)
	}
}

// TestAttack2HostileGlobalHooksPathNeverStagesForbiddenFile is report P0-1 /
// §9 attack 2: same injection, but sourced from a global core.hooksPath
// rather than a repo-local hook — simulating an operator machine whose
// ambient git config points at a hostile hooks directory. Governator's own
// git invocations must neutralize GIT_CONFIG_GLOBAL/core.hooksPath
// regardless of what the ambient environment says.
func TestAttack2HostileGlobalHooksPathNeverStagesForbiddenFile(t *testing.T) {
	root := fixtureRepo(t)

	hostileHooksDir := t.TempDir()
	hook := filepath.Join(hostileHooksDir, "pre-commit")
	hookScript := "#!/bin/sh\nprintf 'injected by hook\\n' > hook-pwned.txt\ngit add -- hook-pwned.txt\n"
	if err := os.WriteFile(hook, []byte(hookScript), 0755); err != nil {
		t.Fatal(err)
	}
	globalConfig := filepath.Join(t.TempDir(), "gitconfig")
	if err := os.WriteFile(globalConfig, []byte("[core]\n\thooksPath = "+hostileHooksDir+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GIT_CONFIG_GLOBAL", globalConfig)

	c := baseContract(root)
	c.Forbidden.Paths = append(c.Forbidden.Paths, "hook-pwned.txt")
	bin := fakeBackend(t, standardBackendBody(""))

	rec := runGoverned(t, t.TempDir(), bin, c)

	if _, err := os.Stat(filepath.Join(root, "hook-pwned.txt")); !os.IsNotExist(err) {
		t.Fatalf("hostile global-hooksPath hook's file reached the live root: err=%v", err)
	}
	paths := committedPaths(t, root)
	if contains(paths, "hook-pwned.txt") {
		t.Fatalf("committed tree contains hook-injected file: %v", paths)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED, got status=%s message=%s", rec.Status, rec.Message)
	}
}

// TestAttack4CleanFilterNeverAltersCommittedContent is report P0-1 (clean
// filters listed among hook-equivalent mutation sources) / §9 attack 4: a
// committed .gitattributes + local `filter.<name>.clean` config transforms
// file content during `git add`/`git commit`. Governator must hash the
// approved bytes directly (`git hash-object --no-filters --literally`)
// rather than letting `git add` run the filter.
func TestAttack4CleanFilterNeverAltersCommittedContent(t *testing.T) {
	root := fixtureRepo(t)

	if err := os.WriteFile(filepath.Join(root, ".gitattributes"), []byte("output/result.txt filter=redact\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".gitattributes")
	git(t, root, "commit", "-m", "add attributes")
	git(t, root, "config", "filter.redact.clean", "sed s/ok/PWNED/")
	git(t, root, "config", "filter.redact.smudge", "cat")

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	rec := runGoverned(t, t.TempDir(), bin, c)

	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED, got status=%s message=%s", rec.Status, rec.Message)
	}
	got := gitOutput(t, root, "show", "HEAD:output/result.txt")
	if got != "ok\n" {
		t.Fatalf("clean filter altered committed content: got %q, want %q", got, "ok\n")
	}
}
