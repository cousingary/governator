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
