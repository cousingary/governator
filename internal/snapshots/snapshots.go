package snapshots

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/protectedpaths"
)

// ErrExactRestoreConfirmationRequired is returned by Restore when mode is
// RestoreExact, the plan would delete at least one post-snapshot addition,
// and the caller passed confirmed=false. The caller (gov snap restore) must
// present the returned RestoreResult's Deleted/Preserved sets to the operator
// and re-invoke with confirmed=true (interactive --yes) or an operator-set
// unattended policy (doctrine.exact_restore_unattended: allow) before
// anything is removed. Nothing is deleted, and no pre-restore snapshot is
// taken, when this error is returned.
var ErrExactRestoreConfirmationRequired = errors.New("exact restore requires confirmation: pass --yes or set doctrine.exact_restore_unattended: allow")

var excluded = map[string]bool{
	".git": true, "node_modules": true, "__pycache__": true, ".next": true,
	"dist": true, "build": true, ".venv": true, "venv": true, ".cache": true,
	".mypy_cache": true, ".pytest_cache": true, ".harness_snapshots": true,
}

type Root struct {
	ID      string `json:"id"`
	Path    string `json:"path"`
	Files   int    `json:"files"`
	Linked  int    `json:"linked"`
	Copied  int    `json:"copied"`
	Skipped int    `json:"skipped"`
}

type Manifest struct {
	ID      string `json:"id"`
	Created string `json:"created"`
	Label   string `json:"label"`
	Roots   []Root `json:"roots"`
}

type Change struct {
	Kind string
	Path string
}

func StoreDir() string { return config.Current().SnapshotDir }

func rootsFile() string {
	if file := config.Env("GOV_SNAPSHOT_ROOTS_FILE"); file != "" {
		return filepath.Clean(file)
	}
	return filepath.Join(config.HomeDir(), ".governed-harness", "recall_roots.txt")
}

func Roots() ([]string, error) {
	configured := config.Current().SnapshotRoots
	if configured != nil {
		return append([]string(nil), configured...), nil
	}
	data, err := os.ReadFile(rootsFile())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var roots []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "~/") {
			line = filepath.Join(config.HomeDir(), line[2:])
		}
		if _, err := os.Stat(line); err == nil {
			roots = append(roots, filepath.Clean(line))
		}
	}
	return roots, nil
}

func List() ([]Manifest, error) {
	entries, err := os.ReadDir(StoreDir())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Manifest
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		data, err := os.ReadFile(filepath.Join(StoreDir(), entry.Name(), "manifest.json"))
		if err != nil {
			continue
		}
		var manifest Manifest
		if json.Unmarshal(data, &manifest) == nil {
			out = append(out, manifest)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID > out[j].ID })
	return out, nil
}

// contentHash returns the SHA-256 digest of a file's actual bytes.
func contentHash(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// same reports whether two files have identical content. Sol audit finding
// #19: size + mtime is not proof of identity — a file's bytes can change
// while both are deliberately preserved, which previously let snapshotRoot
// hardlink stale content from a prior snapshot into a new one, and let Diff
// miss a real edit. Size is checked first purely as a cheap short-circuit
// (differing sizes can never be identical content); anything past that must
// match by actual content hash. mtime is deliberately not consulted at all
// anymore: it was never proof of anything and a byte-identical file is the
// same file regardless of when it was last touched.
func same(a, b string) bool {
	left, err := os.Stat(a)
	if err != nil {
		return false
	}
	right, err := os.Stat(b)
	if err != nil {
		return false
	}
	if left.Size() != right.Size() {
		return false
	}
	hashA, err := contentHash(a)
	if err != nil {
		return false
	}
	hashB, err := contentHash(b)
	if err != nil {
		return false
	}
	return hashA == hashB
}

func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	info, err := in.Stat()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0755); err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, info.Mode().Perm())
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		return copyErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chtimes(dst, info.ModTime(), info.ModTime())
}

func snapshotRoot(root, dest, previous string) (Root, error) {
	stat := Root{Path: root}
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			stat.Skipped++
			return nil
		}
		if entry.IsDir() && path != root && excluded[entry.Name()] {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			stat.Skipped++
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		target := filepath.Join(dest, rel)
		if previous != "" {
			old := filepath.Join(previous, rel)
			if same(path, old) {
				if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
					return err
				}
				if err := os.Link(old, target); err == nil {
					stat.Linked++
					stat.Files++
					return nil
				}
			}
		}
		if err := copyFile(path, target); err != nil {
			stat.Skipped++
			return nil
		}
		stat.Copied++
		stat.Files++
		return nil
	})
	return stat, err
}

func Create(label string) (Manifest, error) {
	roots, err := Roots()
	if err != nil {
		return Manifest{}, err
	}
	if len(roots) == 0 {
		return Manifest{}, errors.New("no snapshot roots configured")
	}
	if err := os.MkdirAll(StoreDir(), 0700); err != nil {
		return Manifest{}, err
	}
	previous := map[string]string{}
	manifests, _ := List()
	if len(manifests) > 0 {
		for _, root := range manifests[0].Roots {
			previous[root.Path] = filepath.Join(StoreDir(), manifests[0].ID, root.ID)
		}
	}
	base := time.Now().UTC().Format("20060102-150405")
	if label != "" {
		safe := strings.Map(func(r rune) rune {
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_' {
				return r
			}
			return '-'
		}, label)
		base += "_" + safe
	}
	id := base
	for n := 1; ; n++ {
		_, err := os.Stat(filepath.Join(StoreDir(), id))
		if os.IsNotExist(err) {
			break
		}
		id = fmt.Sprintf("%s-%d", base, n)
	}
	dir := filepath.Join(StoreDir(), id)
	if err := os.Mkdir(dir, 0700); err != nil {
		return Manifest{}, err
	}
	manifest := Manifest{ID: id, Created: time.Now().UTC().Format(time.RFC3339Nano), Label: label}
	for i, root := range roots {
		item, err := snapshotRoot(root, filepath.Join(dir, fmt.Sprintf("r%d", i)), previous[root])
		if err != nil {
			return Manifest{}, err
		}
		item.ID = fmt.Sprintf("r%d", i)
		manifest.Roots = append(manifest.Roots, item)
	}
	data, _ := json.MarshalIndent(manifest, "", "  ")
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), data, 0600); err != nil {
		return Manifest{}, err
	}
	return manifest, nil
}

// Prune removes all but the keep newest snapshots and returns the IDs it
// removed, matching the legacy harness_recall.py semantics: newest-first by
// ID, labeled snapshots not exempt. Hardlink dedup makes removal of older
// snapshots safe — each snapshot holds its own directory entries, so newer
// snapshots keep their content regardless of which older links disappear.
func Prune(keep int) ([]string, error) {
	if keep < 1 {
		return nil, errors.New("prune: --keep must be at least 1")
	}
	manifests, err := List()
	if err != nil {
		return nil, err
	}
	if len(manifests) <= keep {
		return nil, nil
	}
	var removed []string
	for _, manifest := range manifests[keep:] {
		if err := os.RemoveAll(filepath.Join(StoreDir(), manifest.ID)); err != nil {
			return removed, err
		}
		removed = append(removed, manifest.ID)
	}
	return removed, nil
}

func find(id string) (Manifest, string, error) {
	list, err := List()
	if err != nil {
		return Manifest{}, "", err
	}
	// An exact ID match is unambiguous even when a longer ID shares it as a
	// prefix (e.g. "20260101-120000" vs "20260101-120000-1"): short-circuit so
	// the exact match wins instead of reporting ambiguity.
	var prefixMatches []Manifest
	for _, manifest := range list {
		if manifest.ID == id {
			return manifest, filepath.Join(StoreDir(), manifest.ID), nil
		}
		if strings.HasPrefix(manifest.ID, id) {
			prefixMatches = append(prefixMatches, manifest)
		}
	}
	if len(prefixMatches) == 0 {
		return Manifest{}, "", fmt.Errorf("snapshot %q not found", id)
	}
	if len(prefixMatches) > 1 {
		return Manifest{}, "", fmt.Errorf("snapshot prefix %q is ambiguous", id)
	}
	return prefixMatches[0], filepath.Join(StoreDir(), prefixMatches[0].ID), nil
}

// postSnapshotAdditions returns the live files under root.Path that are not
// present in the snapshot at dir/root.ID — i.e. files added after the
// snapshot was taken. Shared by Diff (reported as Kind "A") and Restore's
// RestoreExact mode (the deletion candidate set).
func postSnapshotAdditions(dir string, root Root) ([]string, error) {
	snapRoot := filepath.Join(dir, root.ID)
	inSnapshot := map[string]bool{}
	if err := filepath.WalkDir(snapRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(snapRoot, path)
		inSnapshot[rel] = true
		return nil
	}); err != nil {
		return nil, err
	}
	var additions []string
	err := filepath.WalkDir(root.Path, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return nil
		}
		if entry.IsDir() && path != root.Path && excluded[entry.Name()] {
			return filepath.SkipDir
		}
		if entry.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root.Path, path)
		if !inSnapshot[rel] {
			additions = append(additions, path)
		}
		return nil
	})
	return additions, err
}

func Diff(id string) ([]Change, error) {
	manifest, dir, err := find(id)
	if err != nil {
		return nil, err
	}
	var changes []Change
	for _, root := range manifest.Roots {
		snapRoot := filepath.Join(dir, root.ID)
		_ = filepath.WalkDir(snapRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(snapRoot, path)
			live := filepath.Join(root.Path, rel)
			if _, err := os.Stat(live); os.IsNotExist(err) {
				changes = append(changes, Change{Kind: "D", Path: live})
			} else if !same(live, path) {
				changes = append(changes, Change{Kind: "M", Path: live})
			}
			return nil
		})
		additions, err := postSnapshotAdditions(dir, root)
		if err != nil {
			return nil, err
		}
		for _, path := range additions {
			changes = append(changes, Change{Kind: "A", Path: path})
		}
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind == changes[j].Kind {
			return changes[i].Path < changes[j].Path
		}
		return changes[i].Kind < changes[j].Kind
	})
	return changes, nil
}

// RestoreMode selects how Restore reconciles the live root against a
// snapshot (Sol audit finding #18: the pre-Sol3 behavior only ever overlaid,
// silently keeping any file added after the snapshot, despite the command
// name and recovery purpose implying a full restoration).
type RestoreMode int

const (
	// RestoreOverlay copies snapshot files back over the live root but never
	// removes a file that was added to the live root after the snapshot was
	// taken. This is the long-standing default behavior, unchanged.
	RestoreOverlay RestoreMode = iota
	// RestoreExact additionally removes post-snapshot additions so the live
	// root matches the snapshot exactly, except for paths matching the
	// protected-path manifest, which are never deleted. Deletion only
	// happens when confirmed is true (see Restore).
	RestoreExact
)

// RestoreResult reports what a Restore call did (or, for RestoreExact
// without confirmation, what it would do).
type RestoreResult struct {
	Restored  int      // files copied back from the snapshot
	Deleted   []string // post-snapshot additions removed (RestoreExact only); on dry-run or an unconfirmed plan, this is the set that WOULD be removed
	Preserved []string // post-snapshot additions that matched a protected-path pattern and were kept despite RestoreExact
}

func matchesProtected(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if protectedpaths.Match(path, pattern) {
			return true
		}
	}
	return false
}

// Restore reconciles the live root(s) against snapshot id. mode selects
// overlay (copy back only, additions untouched — the original behavior) or
// exact (also deletes post-snapshot additions). For RestoreExact, deletion
// only happens once: a pre-restore snapshot has been taken (so exact restore
// is itself always recoverable), the deletion set has been computed with
// protected paths excluded, and confirmed is true — otherwise Restore returns
// the plan (Deleted/Preserved populated, nothing touched) alongside
// ErrExactRestoreConfirmationRequired so the caller can present it to the
// operator before retrying with confirmation.
func Restore(id string, mode RestoreMode, dryRun bool, confirmed bool) (RestoreResult, error) {
	manifest, dir, err := find(id)
	if err != nil {
		return RestoreResult{}, err
	}

	var deletions []string
	var preserved []string
	if mode == RestoreExact {
		patterns, err := protectedpaths.Patterns()
		if err != nil {
			return RestoreResult{}, fmt.Errorf("exact restore: reading protected-path manifest: %w", err)
		}
		for _, root := range manifest.Roots {
			additions, err := postSnapshotAdditions(dir, root)
			if err != nil {
				return RestoreResult{}, err
			}
			for _, path := range additions {
				if matchesProtected(path, patterns) {
					preserved = append(preserved, path)
					continue
				}
				deletions = append(deletions, path)
			}
		}
		sort.Strings(deletions)
		sort.Strings(preserved)
		if len(deletions) > 0 && !dryRun && !confirmed {
			return RestoreResult{Deleted: deletions, Preserved: preserved}, ErrExactRestoreConfirmationRequired
		}
	}

	if !dryRun {
		if _, err := Create("pre-restore"); err != nil {
			return RestoreResult{}, fmt.Errorf("pre-restore snapshot: %w", err)
		}
	}
	count := 0
	for _, root := range manifest.Roots {
		snapRoot := filepath.Join(dir, root.ID)
		err := filepath.WalkDir(snapRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(snapRoot, path)
			target := filepath.Join(root.Path, rel)
			count++
			if dryRun {
				return nil
			}
			if info, err := os.Stat(target); err == nil && info.Mode().Perm()&0200 == 0 {
				_ = os.Chmod(target, 0644)
			}
			return copyFile(path, target)
		})
		if err != nil {
			return RestoreResult{Restored: count, Deleted: deletions, Preserved: preserved}, err
		}
	}

	result := RestoreResult{Restored: count, Preserved: preserved}
	if mode == RestoreExact {
		if dryRun {
			result.Deleted = deletions
			return result, nil
		}
		for _, path := range deletions {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				result.Deleted = deletions
				return result, fmt.Errorf("exact restore: removing %s: %w", path, err)
			}
		}
		result.Deleted = deletions
	}
	return result, nil
}
