package agents

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cousingary/governator/internal/config"
)

// OpenCode has no read-only CLI flag. For read-only contracts this adapter
// installs a worktree-scoped permission projection for the duration of the
// process. Runtime fingerprints remain authoritative.
type OpenCode struct{}

func (OpenCode) Name() string { return "opencode" }

func (OpenCode) Capabilities() Capability {
	return Capability{
		NativeApprovalPolicy: true,
		TranscriptFormat:     TranscriptOpenCode,
	}
}

func (OpenCode) project(spec BackendSpec) ([]string, error) {
	if spec.Workdir == "" {
		return nil, fmt.Errorf("opencode: spec.Workdir is required")
	}
	return []string{"run", "--pure", "--format", "json", "--dir", spec.Workdir}, nil
}

func openCodeReadOnlyConfig() []byte {
	config := map[string]any{"permission": map[string]any{
		"edit": "deny",
		"bash": map[string]string{
			"*": "deny", "git status*": "allow", "git diff*": "allow",
			"git log*": "allow", "git show*": "allow", "git grep*": "allow",
			"rg *": "allow", "grep *": "allow", "find *": "allow",
			"ls*": "allow", "cat *": "allow", "head *": "allow",
			"tail *": "allow", "pwd": "allow",
		},
	}}
	data, _ := json.MarshalIndent(config, "", "  ")
	return append(data, '\n')
}

func withScopedConfig(workdir string, enabled bool) (func(), error) {
	if !enabled {
		return func() {}, nil
	}
	path := filepath.Join(workdir, "opencode.json")
	previous, readErr := os.ReadFile(path)
	var previousMode os.FileMode
	if readErr == nil {
		info, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		previousMode = info.Mode().Perm()
	} else if !os.IsNotExist(readErr) {
		return nil, readErr
	}
	if err := os.WriteFile(path, openCodeReadOnlyConfig(), 0600); err != nil {
		return nil, err
	}
	return func() {
		if readErr == nil {
			_ = os.WriteFile(path, previous, previousMode)
		} else {
			_ = os.Remove(path)
		}
	}, nil
}

func (OpenCode) Run(parent context.Context, req Request) (Result, error) {
	bin := config.BackendBin("opencode")
	flags, err := OpenCode{}.project(req.Spec)
	if err != nil {
		return Result{}, err
	}
	restore, err := withScopedConfig(req.Workdir, req.Spec.Sandbox == SandboxReadOnly)
	if err != nil {
		return Result{}, err
	}
	defer restore()
	return runCLI(parent, runCLIRequest{
		bin: bin, workdir: req.Workdir, transcript: req.Transcript,
		timeout: req.Timeout, prompt: req.Prompt, extraFlags: flags,
	})
}
