package protectedpaths

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/cousingary/governator/internal/config"
)

// Manifest returns the protected-path manifest selected by configuration.
func Manifest() string { return config.Current().ProtectedManifest }

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

// Patterns reads the manifest path chosen by the live configuration. It
// exists for standalone administrative callers (gov protect, gov doctor)
// where re-reading config.yaml on every call is intentional. Execution-
// critical callers (a run's protected-path fingerprint, the transcript
// audit's secret-pattern check) must call PatternsFor with a manifest path
// captured once in the run's RunEnvironment instead — see Sol Finding 2 /
// governator-sol3-repair-plan.md Session 3.
func Patterns() ([]string, error) {
	return PatternsFor(Manifest())
}

// PatternsFor reads and parses the protected-path manifest at the given
// path, without consulting the live configuration for which path to use.
func PatternsFor(manifestPath string) ([]string, error) {
	data, err := os.ReadFile(manifestPath)
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
