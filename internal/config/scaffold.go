package config

import (
	"fmt"
	"os"
	"path/filepath"
)

type WriteResult struct {
	Path    string
	Skipped bool
}

func Scaffold(cwd string) ([]WriteResult, error) {
	root, err := filepath.Abs(cwd)
	if err != nil {
		return nil, fmt.Errorf("resolve current directory: %w", err)
	}
	base := filepath.Join(HomeDir(), ".governator")
	files := []struct {
		path string
		body string
	}{
		{Path(), configTemplate},
		{filepath.Join(base, "jobs", "example.yaml"), fmt.Sprintf(exampleContract, root)},
		{filepath.Join(base, "protected-paths.txt"), ""},
	}
	results := make([]WriteResult, 0, len(files))
	for _, file := range files {
		skipped, err := writeExclusive(file.path, []byte(file.body))
		if err != nil {
			return results, err
		}
		results = append(results, WriteResult{Path: file.path, Skipped: skipped})
	}
	return results, nil
}

func writeExclusive(path string, data []byte) (bool, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return false, fmt.Errorf("create %s: %w", filepath.Dir(path), err)
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
	if os.IsExist(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("create %s: %w", path, err)
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return false, fmt.Errorf("write %s: %w", path, err)
	}
	if err := file.Close(); err != nil {
		return false, fmt.Errorf("close %s: %w", path, err)
	}
	return false, nil
}

const configTemplate = `# Governator configuration. Environment variables override these values.
protected_manifest: ~/.governator/protected-paths.txt
snapshot_dir: ~/.governator/snapshots
snapshot_roots: []
ledger_dir: ~/.governator
backends:
  claude-code:
    bin: claude
  codex:
    bin: codex
  glm:
    bin: glm
  opencode:
    bin: opencode
  pi:
    bin: pi
rtk:
  mode: auto # auto, off, or required
  bin: rtk
graph:
  mode: auto # auto, off, or required
  provider: codegraph
  bin: codegraph
minimalism:
  mode: full # off, lite, full, or ultra
spend:
  daily_cap_usd: 0 # 0 = unlimited
  halt_file: ~/.governator/HALT
doctrine:
  require_cleanup: false # true = gov validate fails a surgeon/batch_worker/repair
                          # contract with no cleanup block and no lint/format
                          # validator instead of just warning
defaults:
  agent: claude-code
  max_minutes: 30
`

const exampleContract = `task: Verify this repository without modifying it.
job_id: example-verification
job_type: verification
agent: claude-code
mode: verifier
workspace:
  root: %q
  worktree: auto
allowed:
  read: ["**"]
  write: []
  execute: ["go test ./..."]
forbidden:
  paths: [".git/**"]
  commands: ["rm -rf", "git push"]
  behaviors: ["write_files", "scope_expansion"]
budget:
  max_minutes: 30
  max_commands: 20
  max_files_changed: 1
  max_lines_changed: 1
  max_new_files: 0
  max_deleted: 0
preflight:
  intended_writes: []
success:
  required_files: []
  validators: ["go test ./..."]
# cleanup:
#   required: false # true blocks the merge on a failing cleanup validator,
#                    # like success.validators; false (default) just records it
#   validators:
#     - test -z "$(gofmt -l .)"                                            # go: no unformatted files
#     - test -z "$(git status --porcelain -- . ':(exclude).governator')"   # no stray/temp files left behind
#     - '! grep -rn "TODO_DEBUG\|console\.log(\"DEBUG" .'                  # no leftover debug prints
output:
  style: terse
  max_final_words: 80
on_violation: quarantine
`
