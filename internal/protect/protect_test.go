package protect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestApplyAndStatus(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "critical.txt")
	if err := os.WriteFile(file, []byte("safe"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(root+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", manifest)

	result, err := Apply(true, nil)
	if err != nil {
		t.Fatal(err)
	}
	if result.Files != 1 || result.Roots != 1 {
		t.Fatalf("unexpected result: %+v", result)
	}
	info, _ := os.Stat(file)
	if info.Mode().Perm()&0200 != 0 {
		t.Fatal("file remained writable")
	}
	// Regression: the parent directory must also be locked. On POSIX, write
	// permission on the parent directory alone is sufficient to delete or
	// replace a 0444 file, so a file-only lock was bypassable until this fix
	// propagated dir chmod errors instead of swallowing them.
	dirInfo, _ := os.Stat(root)
	if dirInfo.Mode().Perm()&0200 != 0 {
		t.Fatalf("parent dir remained writable: %v", dirInfo.Mode().Perm())
	}
	entries, err := Status()
	if err != nil || len(entries) != 1 || entries[0].State != "LOCKED" {
		t.Fatalf("status: %+v %v", entries, err)
	}

	if _, err := Apply(false, []string{root}); err != nil {
		t.Fatal(err)
	}
	info, _ = os.Stat(file)
	if info.Mode().Perm()&0200 == 0 {
		t.Fatal("file remained locked")
	}
}

// Regression: a filter pointing at a subdirectory used to select the ENTIRE
// containing root and chmod every file under it, so `release /root/sub` also
// released /root/sibling. pathInScope now scopes each chmod to the filter
// path (plus ancestor dirs, which must follow the target so a partial lock is
// effective), leaving siblings exactly where they were.
func TestApplyFilterScopesToSubdirectory(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target", "deep")
	sibling := filepath.Join(root, "sibling")
	for _, dir := range []string{target, sibling} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			t.Fatal(err)
		}
	}
	targetFile := filepath.Join(target, "a.txt")
	siblingFile := filepath.Join(sibling, "b.txt")
	for _, f := range []string{targetFile, siblingFile} {
		if err := os.WriteFile(f, []byte("x"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(root+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", manifest)
	// The test locks directories the temp-dir cleaner cannot then remove;
	// release everything before cleanup so the assertions own the only
	// failure mode.
	t.Cleanup(func() { _, _ = Apply(false, nil) })

	// Lock everything first.
	if _, err := Apply(true, nil); err != nil {
		t.Fatal(err)
	}

	// Release ONLY the target subtree; the sibling must stay locked.
	if res, err := Apply(false, []string{target}); err != nil {
		t.Fatal(err)
	} else if res.Files != 1 {
		t.Fatalf("expected exactly one file released (the target), got %d", res.Files)
	}
	ti, _ := os.Stat(targetFile)
	if ti.Mode().Perm()&0200 == 0 {
		t.Fatal("target file was not released by the filtered Apply")
	}
	si, _ := os.Stat(siblingFile)
	if si.Mode().Perm()&0200 != 0 {
		t.Fatal("sibling file was released by a filter that did not name it (scope leak)")
	}

	// Re-lock, then prove the inverse: a filtered LOCK on the sibling does
	// not touch the target subtree (which is currently writable) either.
	if _, err := Apply(true, []string{sibling}); err != nil {
		t.Fatal(err)
	}
	ti2, _ := os.Stat(targetFile)
	if ti2.Mode().Perm()&0200 == 0 {
		t.Fatal("filtered lock on sibling leaked onto the target subtree")
	}
	si2, _ := os.Stat(siblingFile)
	if si2.Mode().Perm()&0200 != 0 {
		t.Fatal("filtered lock did not actually lock the sibling")
	}
}
