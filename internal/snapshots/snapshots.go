package snapshots

import (
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
)

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

func same(a, b string) bool {
	left, err := os.Stat(a)
	if err != nil {
		return false
	}
	right, err := os.Stat(b)
	if err != nil {
		return false
	}
	return left.Size() == right.Size() && left.ModTime().Unix() == right.ModTime().Unix()
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

func find(id string) (Manifest, string, error) {
	list, err := List()
	if err != nil {
		return Manifest{}, "", err
	}
	var matches []Manifest
	for _, manifest := range list {
		if manifest.ID == id || strings.HasPrefix(manifest.ID, id) {
			matches = append(matches, manifest)
		}
	}
	if len(matches) == 0 {
		return Manifest{}, "", fmt.Errorf("snapshot %q not found", id)
	}
	if len(matches) > 1 {
		return Manifest{}, "", fmt.Errorf("snapshot prefix %q is ambiguous", id)
	}
	return matches[0], filepath.Join(StoreDir(), matches[0].ID), nil
}

func Diff(id string) ([]Change, error) {
	manifest, dir, err := find(id)
	if err != nil {
		return nil, err
	}
	var changes []Change
	for _, root := range manifest.Roots {
		snapRoot := filepath.Join(dir, root.ID)
		inSnapshot := map[string]bool{}
		_ = filepath.WalkDir(snapRoot, func(path string, entry fs.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel(snapRoot, path)
			inSnapshot[rel] = true
			live := filepath.Join(root.Path, rel)
			if _, err := os.Stat(live); os.IsNotExist(err) {
				changes = append(changes, Change{Kind: "D", Path: live})
			} else if !same(live, path) {
				changes = append(changes, Change{Kind: "M", Path: live})
			}
			return nil
		})
		_ = filepath.WalkDir(root.Path, func(path string, entry fs.DirEntry, walkErr error) error {
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
				changes = append(changes, Change{Kind: "A", Path: path})
			}
			return nil
		})
	}
	sort.Slice(changes, func(i, j int) bool {
		if changes[i].Kind == changes[j].Kind {
			return changes[i].Path < changes[j].Path
		}
		return changes[i].Kind < changes[j].Kind
	})
	return changes, nil
}

func Restore(id string, dryRun bool) (int, error) {
	manifest, dir, err := find(id)
	if err != nil {
		return 0, err
	}
	if !dryRun {
		if _, err := Create("pre-restore"); err != nil {
			return 0, fmt.Errorf("pre-restore snapshot: %w", err)
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
			return count, err
		}
	}
	return count, nil
}
