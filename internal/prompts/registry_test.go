package prompts

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLatestAndMutationChecksum(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "claude-code", "surgeon")
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "v001.md"), []byte("minimal change"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "v002.md"), []byte("bounded change"), 0644); err != nil {
		t.Fatal(err)
	}
	first, err := Latest(root, "claude-code", "surgeon")
	if err != nil {
		t.Fatal(err)
	}
	if first.ID != "v002" {
		t.Fatalf("latest=%s", first.ID)
	}
	if err := os.WriteFile(first.Path, []byte("bounded change mutated"), 0644); err != nil {
		t.Fatal(err)
	}
	mutated, err := Latest(root, "claude-code", "surgeon")
	if err != nil {
		t.Fatal(err)
	}
	if mutated.Checksum == first.Checksum {
		t.Fatal("prompt mutation did not change checksum")
	}
}
