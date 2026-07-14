package gitplumb

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func git(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", args...)
	cmd.Dir = dir
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v: %s", args, err, out)
	}
	return string(out)
}

func newRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	git(t, root, "init", "-b", "main")
	git(t, root, "config", "user.email", "test@example.invalid")
	git(t, root, "config", "user.name", "gitplumb test")
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("seed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".")
	git(t, root, "commit", "-m", "seed")
	return root
}

func headTree(t *testing.T, root string) string {
	t.Helper()
	return strings.TrimSpace(git(t, root, "rev-parse", "HEAD^{tree}"))
}

func TestHashObjectFileIgnoresCleanFilter(t *testing.T) {
	ctx := context.Background()
	root := newRepo(t)
	if err := os.WriteFile(filepath.Join(root, ".gitattributes"), []byte("secret.txt filter=redact\n"), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", ".gitattributes")
	git(t, root, "commit", "-m", "attrs")
	git(t, root, "config", "filter.redact.clean", "sed s/ok/PWNED/")
	git(t, root, "config", "filter.redact.smudge", "cat")

	path := filepath.Join(root, "secret.txt")
	if err := os.WriteFile(path, []byte("ok\n"), 0644); err != nil {
		t.Fatal(err)
	}

	sess, err := NewSession(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	hash, err := sess.HashObjectFile(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	content := git(t, root, "cat-file", "-p", hash)
	if content != "ok\n" {
		t.Fatalf("clean filter applied despite --no-filters --literally: got %q", content)
	}
}

func TestReadTreeUpdateIndexWriteTreeRoundTrip(t *testing.T) {
	ctx := context.Background()
	root := newRepo(t)
	baseline := headTree(t, root)

	newFile := filepath.Join(root, "new.txt")
	if err := os.WriteFile(newFile, []byte("new content\n"), 0644); err != nil {
		t.Fatal(err)
	}

	sess, err := NewSession(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.ReadTreeIntoIndex(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	if err := sess.UpdateIndexAddFile(ctx, newFile, "new.txt"); err != nil {
		t.Fatal(err)
	}
	tree, err := sess.WriteTree(ctx)
	if err != nil {
		t.Fatal(err)
	}

	paths, err := sess.LsTreePaths(ctx, tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(paths) != 2 || !contains(paths, "seed.txt") || !contains(paths, "new.txt") {
		t.Fatalf("unexpected tree contents: %v", paths)
	}

	diff, err := sess.DiffTreePaths(ctx, baseline, tree)
	if err != nil {
		t.Fatal(err)
	}
	if len(diff) != 1 || diff[0] != "new.txt" {
		t.Fatalf("expected diff to contain exactly new.txt, got %v", diff)
	}

	if err := sess.UpdateIndexRemove(ctx, "new.txt"); err != nil {
		t.Fatal(err)
	}
	backToBaseline, err := sess.WriteTree(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if backToBaseline != baseline {
		t.Fatalf("expected write-tree after removal to match baseline: got %s want %s", backToBaseline, baseline)
	}
}

func TestUpdateIndexAddFileTreatsPathspecMagicFilenameLiterally(t *testing.T) {
	ctx := context.Background()
	root := newRepo(t)
	baseline := headTree(t, root)

	hostile := filepath.Join(root, "hostile-on-disk.txt")
	if err := os.WriteFile(hostile, []byte("payload\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".governator"), 0755); err != nil {
		t.Fatal(err)
	}
	internalFile := filepath.Join(root, ".governator", "hidden.txt")
	if err := os.WriteFile(internalFile, []byte("hidden\n"), 0644); err != nil {
		t.Fatal(err)
	}

	sess, err := NewSession(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	if err := sess.ReadTreeIntoIndex(ctx, baseline); err != nil {
		t.Fatal(err)
	}
	// Add ONLY the literal pathspec-magic-looking filename — never
	// ".governator/hidden.txt". If magic were honored, a real `git add
	// -- ':(glob)**'` would match the whole tree; a literal cacheinfo add
	// must match only the exact byte string given.
	if err := sess.UpdateIndexAddFile(ctx, hostile, ":(glob)**"); err != nil {
		t.Fatal(err)
	}
	tree, err := sess.WriteTree(ctx)
	if err != nil {
		t.Fatal(err)
	}

	paths, err := sess.LsTreePaths(ctx, tree)
	if err != nil {
		t.Fatal(err)
	}
	if contains(paths, ".governator/hidden.txt") {
		t.Fatalf("literal cacheinfo add pulled in an unrelated path via pathspec magic: %v", paths)
	}
	if !contains(paths, ":(glob)**") {
		t.Fatalf("expected the literal filename in the tree, got %v", paths)
	}
}

func TestCommitTreeAndUpdateRefCAS(t *testing.T) {
	ctx := context.Background()
	root := newRepo(t)
	oldHead := strings.TrimSpace(git(t, root, "rev-parse", "HEAD"))
	baseline := headTree(t, root)

	sess, err := NewSession(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	commit, err := sess.CommitTree(ctx, baseline, oldHead, "gitplumb test commit\n")
	if err != nil {
		t.Fatal(err)
	}

	// A stale CAS must fail without moving anything.
	if err := sess.UpdateRefCAS(ctx, root, "refs/heads/main", commit, "0000000000000000000000000000000000000000"); err == nil {
		t.Fatal("expected a stale compare-and-swap old value to be rejected")
	}
	if got := strings.TrimSpace(git(t, root, "rev-parse", "HEAD")); got != oldHead {
		t.Fatalf("a failed CAS must not move HEAD: got %s want %s", got, oldHead)
	}

	if err := sess.UpdateRefCAS(ctx, root, "refs/heads/main", commit, oldHead); err != nil {
		t.Fatal(err)
	}
	if got := strings.TrimSpace(git(t, root, "rev-parse", "HEAD")); got != commit {
		t.Fatalf("expected HEAD to advance to the new commit: got %s want %s", got, commit)
	}

	verifyTree, err := sess.RevParseTree(ctx, commit)
	if err != nil {
		t.Fatal(err)
	}
	if verifyTree != baseline {
		t.Fatalf("commit^{tree} mismatch: got %s want %s", verifyTree, baseline)
	}
}

func TestStatusPorcelainV2HandlesHostileFilename(t *testing.T) {
	ctx := context.Background()
	root := newRepo(t)
	hostile := "weird\nname:(top)"
	if err := os.WriteFile(filepath.Join(root, hostile), []byte("x\n"), 0644); err != nil {
		t.Fatal(err)
	}

	entries, err := StatusPorcelainV2(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Kind == '?' && e.Path == hostile {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an untracked entry for the hostile filename, got %+v", entries)
	}
}

func TestStatusPorcelainV2HandlesRename(t *testing.T) {
	ctx := context.Background()
	root := newRepo(t)
	// Big enough content that git's rename detection actually fires.
	content := strings.Repeat("line of content for rename detection\n", 50)
	if err := os.WriteFile(filepath.Join(root, "big.txt"), []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	git(t, root, "add", "big.txt")
	git(t, root, "commit", "-m", "add big.txt")
	git(t, root, "mv", "big.txt", "renamed.txt")
	git(t, root, "add", "-A")

	entries, err := StatusPorcelainV2(ctx, root)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range entries {
		if e.Kind == '2' && e.Path == "renamed.txt" && e.OrigPath == "big.txt" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected a renamed entry big.txt -> renamed.txt, got %+v", entries)
	}
}

func contains(paths []string, target string) bool {
	for _, p := range paths {
		if p == target {
			return true
		}
	}
	return false
}
