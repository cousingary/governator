package snapshots

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
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

// Regression: same() compared whole-second mtimes, so two writes to the same
// file inside one second that kept the same size were reported unchanged —
// Diff missed the edit and snapshotRoot hardlinked stale content forward.
func TestSameDetectsSubSecondMtimeChange(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	a := filepath.Join(dir1, "f.txt")
	b := filepath.Join(dir2, "f.txt")
	if err := os.WriteFile(a, []byte("same-size"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("same-size"), 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(a, now, now); err != nil {
		t.Fatal(err)
	}
	// Same second, deliberately different sub-second nanosecond offset.
	if err := os.Chtimes(b, now.Add(500*time.Millisecond), now.Add(500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if same(a, b) {
		t.Fatalf("same() missed a sub-second mtime change (both in second %d)", now.Unix())
	}
}

// Regression: find() pushed exact and prefix matches into one slice, so once a
// longer ID sharing the exact ID as prefix existed (the -1 collision suffix),
// the exact ID became "ambiguous" and could never be addressed.
func TestFindExactIDWinsOverPrefixCollision(t *testing.T) {
	root := t.TempDir()
	t.Setenv("GOV_SNAPSHOT_DIR", t.TempDir())
	t.Setenv("GOV_SNAPSHOT_ROOTS", root)
	if err := os.WriteFile(filepath.Join(root, "seed.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	first, err := Create("")
	if err != nil {
		t.Fatal(err)
	}
	// Force the collision suffix path: a second Create in the same second
	// produces "<first.ID>-1", making first.ID a prefix of the second.
	second, err := Create("")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(second.ID, first.ID) {
		t.Skipf("no prefix collision to exercise (ids %q, %q); time rolled a second", first.ID, second.ID)
	}
	got, _, err := find(first.ID)
	if err != nil {
		t.Fatalf("exact id %q should resolve, got err=%v", first.ID, err)
	}
	if got.ID != first.ID {
		t.Fatalf("find returned wrong snapshot: got=%q want=%q", got.ID, first.ID)
	}
}

func TestPruneKeepsNewestAndMatchesLegacySemantics(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_SNAPSHOT_DIR", store)
	t.Setenv("GOV_SNAPSHOT_ROOTS", root)

	// IDs are second-granularity timestamps; use labels to keep them unique
	// without sleeping. Labeled snapshots must NOT be exempt (legacy parity).
	var ids []string
	for _, label := range []string{"a", "b", "c", "d", "e"} {
		manifest, err := Create(label)
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, manifest.ID)
	}

	if _, err := Prune(0); err == nil {
		t.Fatal("Prune(0) must be rejected")
	}

	removed, err := Prune(2)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 3 {
		t.Fatalf("expected 3 removed, got %d: %v", len(removed), removed)
	}
	list, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 {
		t.Fatalf("expected 2 surviving snapshots, got %d", len(list))
	}
	// List is newest-first; the two newest by ID must be the survivors, and
	// their content must still be readable (hardlink safety after removal).
	sorted := append([]string(nil), ids...)
	sort.Sort(sort.Reverse(sort.StringSlice(sorted)))
	for i, want := range sorted[:2] {
		if list[i].ID != want {
			t.Fatalf("survivor %d = %s, want %s", i, list[i].ID, want)
		}
		data, err := os.ReadFile(filepath.Join(store, want, "r0", "note.txt"))
		if err != nil || string(data) != "x" {
			t.Fatalf("survivor %s content unreadable after prune: %v", want, err)
		}
	}

	// Prune with keep >= count is a no-op.
	removed, err = Prune(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 0 {
		t.Fatalf("expected no-op, removed %v", removed)
	}
}
