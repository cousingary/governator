//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAttack3PathspecMagicFilenameNeverStagesInternalPath is report P0-2 /
// §9 attack 3: a file literally named `:(glob)**` is a legitimate,
// contract-permitted change (Allowed.Write: ["**"]), but git interprets
// pathspec magic even after `--`, so passing it to `git add --` matches the
// entire tree. Governator's own final-barrier verification separately
// (correctly, by design) never counts .governator/** as part of the
// approved change set, since that's Governator's own bookkeeping directory
// -- so a backend-planted .governator/hidden.txt is invisible to every
// content-based check. The only thing standing between that file and the
// live root's committed history is whether git's own path handling treats
// `:(glob)**` as a literal filename or as magic. Fixed by S1: every
// machine-generated pathspec goes through --literal-pathspecs /
// :(literal), and .governator/** is asserted absent from the final tree
// regardless of what the contract allows.
func TestAttack3PathspecMagicFilenameNeverStagesInternalPath(t *testing.T) {
	root := fixtureRepo(t)

	c := baseContract(root)
	c.Allowed.Write = []string{"**"}
	c.Preflight.IntendedWrites = []string{"**"}
	c.Preflight.ApproveHighRisk = true
	c.Budget.MaxNewFiles = 5
	c.Budget.MaxFilesChanged = 5
	bin := fakeBackend(t, standardBackendBody(`
mkdir -p .governator
printf 'hidden\n' > .governator/hidden.txt
printf 'injected\n' > ':(glob)**'
`))

	rec := runGoverned(t, t.TempDir(), bin, c)

	if _, err := os.Stat(filepath.Join(root, ".governator", "hidden.txt")); !os.IsNotExist(err) {
		t.Fatalf(".governator/hidden.txt leaked into the live root: err=%v", err)
	}
	paths := committedPaths(t, root)
	if hasPrefixAny(paths, ".governator") {
		t.Fatalf("committed tree contains a .governator/** path: %v", paths)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED (only output/result.txt and the literal pathspec-named file are legitimate changes), got status=%s message=%s", rec.Status, rec.Message)
	}
	if !contains(paths, "output/result.txt") {
		t.Fatalf("legitimate output missing from committed tree: %v", paths)
	}
}

// TestAttack19NewlinePathspecFilenameHandledLiterally is report P1-9/P0-2 /
// §9 attack 19: a filename combining an embedded newline with leading
// pathspec-magic syntax. Human-readable `git status --porcelain` parsing
// (line-split, no NUL delimiting) cannot represent this filename correctly
// -- a naive per-line parser either mis-splits it into two bogus records or
// bails out with an "unparseable" error. Fixed by S1:
// `git status --porcelain=v2 -z`, parsed byte-wise on NUL with no
// shell-style unquoting, plus literal-pathspec handling so the leading
// `:(...)` text is never interpreted as magic.
func TestAttack19NewlinePathspecFilenameHandledLiterally(t *testing.T) {
	root := fixtureRepo(t)

	// The hostile filename embeds a literal newline and has no "/", so a
	// single-star pattern ("*" -> regex "[^/]*", which allows any byte
	// including "\n") matches it without needing "**" ("**" -> ".*", and
	// Go's regexp "." never matches "\n" without an (?s) flag -- a
	// separate, Go-side glob() limitation unrelated to the git-side
	// attack this test targets; logged as its own finding rather than
	// folded into this test's assertions). A literal (non-glob) pattern
	// can't be used instead: contracts.Validate rejects control
	// characters in any declared allowed.write/intended_writes pattern.
	const hostileName = ":(top)weird\nname.txt"
	c := baseContract(root)
	c.Allowed.Write = []string{"output/**", "*"}
	c.Preflight.IntendedWrites = []string{"output/**", "*"}
	c.Preflight.ApproveHighRisk = true
	c.Budget.MaxNewFiles = 5
	c.Budget.MaxFilesChanged = 5
	bin := fakeBackend(t, standardBackendBody(`
mkdir -p .governator
printf 'hidden\n' > .governator/hidden.txt
printf 'evil\n' > "`+hostileName+`"
`))

	rec := runGoverned(t, t.TempDir(), bin, c)

	if strings.Contains(rec.Message, "unparseable") {
		t.Fatalf("hostile filename broke status parsing: status=%s message=%s", rec.Status, rec.Message)
	}
	if _, err := os.Stat(filepath.Join(root, ".governator", "hidden.txt")); !os.IsNotExist(err) {
		t.Fatalf(".governator/hidden.txt leaked into the live root: err=%v", err)
	}
	paths := committedPaths(t, root)
	if hasPrefixAny(paths, ".governator") {
		t.Fatalf("committed tree contains a .governator/** path: %v", paths)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED, got status=%s message=%s", rec.Status, rec.Message)
	}
}
