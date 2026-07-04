package snapshots

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRoundTripDryRunAndHardlinkDedup(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	file := filepath.Join(root, "note.txt")
	if err := os.WriteFile(file, []byte("one"), 0644); err != nil {
		t.Fatal(err)
	}
	fixed := time.Now().Add(-time.Hour)
	if err := os.Chtimes(file, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_SNAPSHOT_DIR", store)
	t.Setenv("GOV_SNAPSHOT_ROOTS", root)

	first, err := Create("first")
	if err != nil {
		t.Fatal(err)
	}
	second, err := Create("second")
	if err != nil {
		t.Fatal(err)
	}
	a, _ := os.Stat(filepath.Join(store, first.ID, "r0", "note.txt"))
	b, _ := os.Stat(filepath.Join(store, second.ID, "r0", "note.txt"))
	if !os.SameFile(a, b) {
		t.Fatal("unchanged snapshot files do not share an inode")
	}

	if err := os.WriteFile(file, []byte("two"), 0644); err != nil {
		t.Fatal(err)
	}
	future := fixed.Add(2 * time.Hour)
	if err := os.Chtimes(file, future, future); err != nil {
		t.Fatal(err)
	}
	changes, err := Diff(first.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(changes) != 1 || changes[0].Kind != "M" {
		t.Fatalf("changes=%+v", changes)
	}

	count, err := Restore(first.ID, true)
	if err != nil || count != 1 {
		t.Fatalf("dry-run=%d err=%v", count, err)
	}
	data, _ := os.ReadFile(file)
	if string(data) != "two" {
		t.Fatal("dry-run mutated live file")
	}

	count, err = Restore(first.ID, false)
	if err != nil || count != 1 {
		t.Fatalf("restore=%d err=%v", count, err)
	}
	data, _ = os.ReadFile(file)
	if string(data) != "one" {
		t.Fatalf("restore content=%q", data)
	}
	list, err := List()
	if err != nil || len(list) < 3 {
		t.Fatalf("list=%d err=%v", len(list), err)
	}
}
