package protect

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/cousingary/governator/internal/protectedpaths"
)

type Entry struct {
	Pattern string
	Path    string
	Files   int
	Locked  int
	State   string
}

type Result struct {
	Roots int
	Files int
}

func filesUnder(root string) ([]string, error) {
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return []string{root}, nil
	}
	var files []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.Type().IsRegular() {
			files = append(files, path)
		}
		return nil
	})
	return files, err
}

func readonly(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().Perm()&0200 == 0
}

func Status() ([]Entry, error) {
	patterns, err := protectedpaths.Patterns()
	if err != nil {
		return nil, err
	}
	var entries []Entry
	for _, pattern := range patterns {
		roots := protectedpaths.Resolve(pattern)
		if len(roots) == 0 {
			entries = append(entries, Entry{Pattern: pattern, Path: pattern, State: "missing"})
			continue
		}
		for _, root := range roots {
			files, err := filesUnder(root)
			if err != nil {
				return nil, err
			}
			locked := 0
			for _, file := range files {
				if readonly(file) {
					locked++
				}
			}
			state := "unlocked"
			if len(files) == 0 {
				state = "empty"
			} else if locked == len(files) {
				state = "LOCKED"
			} else if locked > 0 {
				state = fmt.Sprintf("partial %d/%d", locked, len(files))
			}
			entries = append(entries, Entry{Pattern: pattern, Path: root, Files: len(files), Locked: locked, State: state})
		}
	}
	return entries, nil
}

func selected(root string, filters []string) bool {
	if len(filters) == 0 {
		return true
	}
	absolute, _ := filepath.Abs(root)
	for _, filter := range filters {
		wanted, _ := filepath.Abs(protectedpaths.Expand(strings.TrimRight(filter, "/")))
		if absolute == wanted || strings.HasPrefix(absolute, wanted+string(filepath.Separator)) || strings.HasPrefix(wanted, absolute+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// Apply mirrors the legacy lock/unlock semantics and verifies every chmod.
func Apply(lock bool, filters []string) (Result, error) {
	patterns, err := protectedpaths.Patterns()
	if err != nil {
		return Result{}, err
	}
	result := Result{}
	for _, pattern := range patterns {
		for _, root := range protectedpaths.Resolve(pattern) {
			if !selected(root, filters) {
				continue
			}
			files, err := filesUnder(root)
			if err != nil {
				return result, err
			}
			mode := os.FileMode(0644)
			if lock {
				mode = 0444
			}
			for _, file := range files {
				if err := os.Chmod(file, mode); err != nil {
					return result, fmt.Errorf("chmod %s: %w", file, err)
				}
				if readonly(file) != lock {
					return result, fmt.Errorf("lock verification failed for %s", file)
				}
				result.Files++
			}
			if info, err := os.Stat(root); err == nil && info.IsDir() {
				dirMode := os.FileMode(0755)
				if lock {
					dirMode = 0555
				}
				_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
					if walkErr == nil && d.IsDir() {
						_ = os.Chmod(path, dirMode)
					}
					return nil
				})
			}
			result.Roots++
		}
	}
	return result, nil
}
