package snapshots

import (
	"errors"
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

	result, err := Restore(first.ID, RestoreOverlay, true, false)
	if err != nil || result.Restored != 1 {
		t.Fatalf("dry-run=%+v err=%v", result, err)
	}
	data, _ := os.ReadFile(file)
	if string(data) != "two" {
		t.Fatal("dry-run mutated live file")
	}

	result, err = Restore(first.ID, RestoreOverlay, false, false)
	if err != nil || result.Restored != 1 {
		t.Fatalf("restore=%+v err=%v", result, err)
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

// Regression (Sol audit finding #19): same() previously trusted size +
// nanosecond mtime as proof of identical content. A file's content can change
// while both size and mtime are deliberately preserved, which let
// snapshotRoot hardlink stale content from a prior snapshot into a new one.
// same() must now compare real file bytes, not timestamps.
func TestSameDetectsContentChangeDespiteMatchingSizeAndMtime(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	a := filepath.Join(dir1, "f.txt")
	b := filepath.Join(dir2, "f.txt")
	if err := os.WriteFile(a, []byte("aaaaaaaaa"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("bbbbbbbbb"), 0644); err != nil {
		t.Fatal(err)
	}
	fixed := time.Now()
	for _, p := range []string{a, b} {
		if err := os.Chtimes(p, fixed, fixed); err != nil {
			t.Fatal(err)
		}
	}
	if same(a, b) {
		t.Fatal("same() reported identical for files with matching size+mtime but different content")
	}
}

// Companion: byte-identical content must read as "same" even when mtimes
// differ down to sub-second precision — the old proxy-via-mtime heuristic
// this session replaces would have flagged this as a change; a real
// content-addressed comparison correctly does not.
func TestSameTreatsIdenticalContentAsSameRegardlessOfMtime(t *testing.T) {
	dir1 := t.TempDir()
	dir2 := t.TempDir()
	a := filepath.Join(dir1, "f.txt")
	b := filepath.Join(dir2, "f.txt")
	content := []byte("identical-bytes")
	if err := os.WriteFile(a, content, 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, content, 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if err := os.Chtimes(a, now, now); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(b, now.Add(500*time.Millisecond), now.Add(500*time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if !same(a, b) {
		t.Fatal("same() should treat byte-identical files as same regardless of mtime jitter")
	}
}

// Regression (Sol audit finding #19, the literal reproduction): a file whose
// content changes while size and mtime are preserved must not be
// hardlink-deduped to stale content in the new snapshot.
func TestSnapshotDoesNotHardlinkStaleContentWhenSizeAndMtimeMatch(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	file := filepath.Join(root, "note.txt")
	if err := os.WriteFile(file, []byte("original!"), 0644); err != nil {
		t.Fatal(err)
	}
	fixed := time.Now().Add(-time.Hour)
	if err := os.Chtimes(file, fixed, fixed); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_SNAPSHOT_DIR", store)
	t.Setenv("GOV_SNAPSHOT_ROOTS", root)

	if _, err := Create("first"); err != nil {
		t.Fatal(err)
	}

	// Same size (9 bytes) and same mtime as before — only the bytes differ.
	if err := os.WriteFile(file, []byte("mutated!!"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(file, fixed, fixed); err != nil {
		t.Fatal(err)
	}

	second, err := Create("second")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(store, second.ID, "r0", "note.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "mutated!!" {
		t.Fatalf("second snapshot captured stale content: got %q", data)
	}
	root0 := second.Roots[0]
	if root0.Linked != 0 || root0.Copied != 1 {
		t.Fatalf("expected a real copy (not a hardlink) since content changed despite matching size/mtime: linked=%d copied=%d", root0.Linked, root0.Copied)
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

// Regression (Sol audit finding #18): the original Restore only ever
// overlaid — it never removed a file added to the live root after the
// snapshot was taken, despite the command name and recovery purpose implying
// a full restoration. RestoreOverlay must keep behaving exactly like that
// (no over-blocking of the pre-existing default); RestoreExact must actually
// remove the addition.
func TestRestoreExactRemovesAdditionsAndOverlayDoesNot(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	t.Setenv("GOV_SNAPSHOT_DIR", store)
	t.Setenv("GOV_SNAPSHOT_ROOTS", root)
	t.Setenv("GOV_PROTECTED_MANIFEST", filepath.Join(t.TempDir(), "empty-protected-paths.txt"))
	if err := os.WriteFile(filepath.Join(root, "kept.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	first, err := Create("first")
	if err != nil {
		t.Fatal(err)
	}
	added := filepath.Join(root, "added-after-snapshot.txt")
	if err := os.WriteFile(added, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	overlay, err := Restore(first.ID, RestoreOverlay, false, false)
	if err != nil {
		t.Fatalf("overlay restore: %v", err)
	}
	if len(overlay.Deleted) != 0 {
		t.Fatalf("overlay restore must never delete: %v", overlay.Deleted)
	}
	if _, err := os.Stat(added); err != nil {
		t.Fatal("overlay restore removed a post-snapshot addition")
	}

	exact, err := Restore(first.ID, RestoreExact, false, true)
	if err != nil {
		t.Fatalf("exact restore: %v", err)
	}
	if len(exact.Deleted) != 1 || exact.Deleted[0] != added {
		t.Fatalf("exact restore deletion set = %v, want [%s]", exact.Deleted, added)
	}
	if _, err := os.Stat(added); !os.IsNotExist(err) {
		t.Fatalf("exact restore should have removed %s, stat err=%v", added, err)
	}
	if _, err := os.Stat(filepath.Join(root, "kept.txt")); err != nil {
		t.Fatal("exact restore removed a file that was already in the snapshot")
	}
}

// Regression (Sol audit finding #18): exact restore must apply protected-path
// rules before deleting anything, even when confirmed.
func TestRestoreExactPreservesProtectedPaths(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	t.Setenv("GOV_SNAPSHOT_DIR", store)
	t.Setenv("GOV_SNAPSHOT_ROOTS", root)
	if err := os.WriteFile(filepath.Join(root, "kept.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	first, err := Create("first")
	if err != nil {
		t.Fatal(err)
	}
	protectedFile := filepath.Join(root, "secrets.env")
	if err := os.WriteFile(protectedFile, []byte("SECRET=1"), 0644); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "protected-paths.txt")
	if err := os.WriteFile(manifest, []byte(protectedFile+"\n"), 0644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_MANIFEST", manifest)

	result, err := Restore(first.ID, RestoreExact, false, true)
	if err != nil {
		t.Fatalf("exact restore: %v", err)
	}
	if len(result.Deleted) != 0 {
		t.Fatalf("protected path should not appear in Deleted: %v", result.Deleted)
	}
	if len(result.Preserved) != 1 || result.Preserved[0] != protectedFile {
		t.Fatalf("Preserved = %v, want [%s]", result.Preserved, protectedFile)
	}
	if _, err := os.Stat(protectedFile); err != nil {
		t.Fatal("exact restore deleted a protected post-snapshot addition")
	}
}

// Regression (Sol audit finding #18): exact restore must not delete anything
// without confirmation — it must return the plan and a distinguished error
// instead, and must not even take the pre-restore snapshot in that case.
func TestRestoreExactRequiresConfirmation(t *testing.T) {
	root := t.TempDir()
	store := t.TempDir()
	t.Setenv("GOV_SNAPSHOT_DIR", store)
	t.Setenv("GOV_SNAPSHOT_ROOTS", root)
	t.Setenv("GOV_PROTECTED_MANIFEST", filepath.Join(t.TempDir(), "empty-protected-paths.txt"))
	if err := os.WriteFile(filepath.Join(root, "kept.txt"), []byte("x"), 0644); err != nil {
		t.Fatal(err)
	}
	first, err := Create("first")
	if err != nil {
		t.Fatal(err)
	}
	added := filepath.Join(root, "added-after-snapshot.txt")
	if err := os.WriteFile(added, []byte("new"), 0644); err != nil {
		t.Fatal(err)
	}

	before, err := List()
	if err != nil {
		t.Fatal(err)
	}

	result, err := Restore(first.ID, RestoreExact, false, false)
	if !errors.Is(err, ErrExactRestoreConfirmationRequired) {
		t.Fatalf("expected ErrExactRestoreConfirmationRequired, got %v", err)
	}
	if len(result.Deleted) != 1 || result.Deleted[0] != added {
		t.Fatalf("plan Deleted = %v, want [%s]", result.Deleted, added)
	}
	if _, err := os.Stat(added); err != nil {
		t.Fatal("unconfirmed exact restore deleted a file")
	}
	after, err := List()
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("unconfirmed exact restore should not take a pre-restore snapshot: before=%d after=%d", len(before), len(after))
	}

	// Dry-run never requires confirmation and never deletes, regardless.
	dry, err := Restore(first.ID, RestoreExact, true, false)
	if err != nil {
		t.Fatalf("dry-run exact restore: %v", err)
	}
	if len(dry.Deleted) != 1 || dry.Deleted[0] != added {
		t.Fatalf("dry-run plan Deleted = %v, want [%s]", dry.Deleted, added)
	}
	if _, err := os.Stat(added); err != nil {
		t.Fatal("dry-run exact restore deleted a file")
	}
}
