package policy

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestScratchOnlyDelete(t *testing.T) {
	if !scratchRootRE.MatchString("/tmp/claude-1000/-mnt-e-downloads/6c9b49e0/scratchpad/out/") {
		t.Fatal("real scratchpad layout must match")
	}
	if scratchRootRE.MatchString("/tmp/claude-1000/-mnt-e-downloads/6c9b49e0/") {
		t.Fatal("the session dir above the scratchpad must not match")
	}
	if !scratchRootRE.MatchString("/private/tmp/claude-501/-Users-x/6c9b49e0/scratchpad/") {
		t.Fatal("macOS resolved scratchpad must match")
	}

	base := t.TempDir()
	sp := filepath.Join(base, "scratchpad")
	outside := filepath.Join(base, "outside")
	for _, d := range []string{filepath.Join(sp, "out"), outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(outside, filepath.Join(sp, "link")); err != nil {
		t.Fatal(err)
	}
	// The root pattern sees resolved paths; macOS temp dirs sit behind the
	// /var -> /private/var symlink, while commands keep the unresolved path.
	realSP, err := filepath.EvalSymlinks(sp)
	if err != nil {
		t.Fatal(err)
	}
	saved := scratchRootRE
	scratchRootRE = regexp.MustCompile("^" + regexp.QuoteMeta(realSP) + "(?:/|$)")
	defer func() { scratchRootRE = saved }()

	cases := []struct {
		cmd  string
		want bool
	}{
		{"rm -rf " + sp + "/out", true},
		{"rm -rf " + sp, true},
		{"rm -rf " + sp + "/out/*", true},
		{"rm -rf " + sp + "/gone/never/existed", true},
		{"rm -rf -- " + sp + "/out 2>/dev/null", true},
		{"find " + sp + " -name '*.png' -delete", false}, // quotes: unprovable
		{"find " + sp + " -name x.png -delete", true},
		{"rm -rf " + outside, false},
		{"rm -rf " + sp + "/out " + outside, false},
		{"rm -rf " + sp + "/out && rm -rf " + outside, false},
		{"rm -rf " + sp + "/link", false},
		{"rm -rf " + sp + "/link/", false},
		{"rm -rf " + sp + "/link/*", false},
		{"rm -rf " + sp + "/../outside", false},
		{"rm -rf " + sp + "/*/x", false},
		{"rm -rf $SP/out", false},
		{"find -L " + sp + " -delete", false},
		{"find " + sp + " -exec rm {} +", false},
		{"shred -u " + sp + "/out/f", false},
		{"rm -rf " + sp + "/out; git push --force origin x", false},
	}
	for _, c := range cases {
		if got := ScratchOnlyDelete(c.cmd, base); got != c.want {
			t.Errorf("ScratchOnlyDelete(%q) = %v, want %v", c.cmd, got, c.want)
		}
	}
	// Relative targets resolve against the session cwd.
	if !ScratchOnlyDelete("rm -rf out", sp) || ScratchOnlyDelete("rm -rf out", base) {
		t.Error("relative target must resolve against cwd")
	}
}
