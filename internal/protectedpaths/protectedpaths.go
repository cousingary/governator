package protectedpaths

import (
	"os"
	"path/filepath"
	"strings"
)

// Manifest returns the single protected-path manifest shared by every plane.
func Manifest() string {
	if p := strings.TrimSpace(os.Getenv("GOV_PROTECTED_PATHS")); p != "" {
		return filepath.Clean(p)
	}
	if state := strings.TrimSpace(os.Getenv("CLAUDE_HARNESS_STATE")); state != "" {
		return filepath.Join(state, "protected_paths.txt")
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".governed-harness", "state", "protected_paths.txt")
}

func Expand(path string) string {
	if path == "~" {
		home, _ := os.UserHomeDir()
		return home
	}
	if strings.HasPrefix(path, "~/") {
		home, _ := os.UserHomeDir()
		return filepath.Join(home, path[2:])
	}
	return os.ExpandEnv(path)
}

func Patterns() ([]string, error) {
	data, err := os.ReadFile(Manifest())
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func Match(path, pattern string) bool {
	absolute, err := filepath.Abs(Expand(path))
	if err != nil {
		return false
	}
	pat, err := filepath.Abs(Expand(strings.TrimRight(pattern, "/")))
	if err != nil {
		return false
	}
	if absolute == pat || strings.HasPrefix(absolute, pat+string(filepath.Separator)) {
		return true
	}
	ok, _ := filepath.Match(pat, absolute)
	return ok
}

// Resolve expands a file, directory, or glob manifest entry to existing roots.
func Resolve(pattern string) []string {
	expanded := Expand(strings.TrimRight(pattern, "/"))
	if strings.ContainsAny(expanded, "*?[") {
		matches, _ := filepath.Glob(expanded)
		return matches
	}
	if _, err := os.Stat(expanded); err == nil {
		return []string{expanded}
	}
	return nil
}
