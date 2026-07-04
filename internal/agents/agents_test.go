package agents

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/contracts"
)

// TestSpecFromContract asserts the abstract spec is derived once from the mode
// lock + forbidden list, and that read-only modes tighten the sandbox while
// write-capable modes keep workspace-write + on-request approval.
func TestSpecFromContract(t *testing.T) {
	workdir := "/tmp/work"
	tests := []struct {
		mode          contracts.Mode
		forbidNetwork bool
		wantSandbox   SandboxMode
		wantApproval  ApprovalPolicy
	}{
		{contracts.ModeSurgeon, false, SandboxWorkspaceWrite, ApprovalOnRequest},
		{contracts.ModeBatchWorker, false, SandboxWorkspaceWrite, ApprovalOnRequest},
		{contracts.ModeRepair, false, SandboxWorkspaceWrite, ApprovalOnRequest},
		{contracts.ModeScout, false, SandboxReadOnly, ApprovalNever},
		{contracts.ModeVerifier, false, SandboxReadOnly, ApprovalNever},
		{contracts.ModeArchitect, false, SandboxReadOnly, ApprovalNever},
		{contracts.ModeSurgeon, true, SandboxWorkspaceWrite, ApprovalOnRequest},
	}
	for _, tc := range tests {
		c := contracts.Contract{Mode: tc.mode}
		if tc.forbidNetwork {
			c.Forbidden.Behaviors = []string{"network"}
		}
		spec := SpecFromContract(c, workdir)
		if spec.Sandbox != tc.wantSandbox {
			t.Errorf("%s: sandbox=%s want %s", tc.mode, spec.Sandbox, tc.wantSandbox)
		}
		if spec.Approval != tc.wantApproval {
			t.Errorf("%s: approval=%s want %s", tc.mode, spec.Approval, tc.wantApproval)
		}
		if spec.Workdir != workdir {
			t.Errorf("%s: workdir=%s want %s", tc.mode, spec.Workdir, workdir)
		}
		if tc.forbidNetwork && spec.Network {
			t.Errorf("%s: forbidden network but spec.Network=true", tc.mode)
		}
	}
}

// TestNewRegistersAllBackends verifies all three adapters resolve from the
// contract's agent name (Phase 5: "Add Codex + GLM adapters").
func TestNewRegistersAllBackends(t *testing.T) {
	for _, name := range []string{"claude", "claude-code", "codex", "glm"} {
		a, err := New(name)
		if err != nil {
			t.Fatalf("New(%q): %v", name, err)
		}
		if a.Name() == "" {
			t.Fatalf("%q: empty adapter name", name)
		}
	}
	if _, err := New("unknown"); err == nil {
		t.Fatal("unknown agent should error")
	}
}

// TestClaudeProjectsSpec asserts the abstract spec translates into Claude's
// native flags, and read-only modes tighten permission-mode to plan.
func TestClaudeProjectsSpec(t *testing.T) {
	write := BackendSpec{Approval: ApprovalOnRequest, Sandbox: SandboxWorkspaceWrite, Workdir: "/w"}
	flags := Claude{}.project(write)
	if !contains(flags, "--permission-mode") || !contains(flags, "acceptEdits") {
		t.Fatalf("write spec should map to acceptEdits: %v", flags)
	}
	if !contains(flags, "--add-dir") || !contains(flags, "/w") {
		t.Fatalf("workdir must be added: %v", flags)
	}
	read := BackendSpec{Approval: ApprovalNever, Sandbox: SandboxReadOnly, Workdir: "/w"}
	flags = Claude{}.project(read)
	if !contains(flags, "plan") {
		t.Fatalf("read-only spec should map to plan: %v", flags)
	}
}

// TestCodexProjectsSpec asserts the abstract spec projects into codex's native
// approval_policy + sandbox_mode flags (plan §7.3).
func TestCodexProjectsSpec(t *testing.T) {
	spec := BackendSpec{Approval: ApprovalOnRequest, Sandbox: SandboxWorkspaceWrite, Workdir: "/w"}
	flags, err := Codex{}.project(spec)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(flags, " ")
	for _, want := range []string{"exec", "--json", "--ask-for-approval", "on-request", "--sandbox", "workspace-write", "-C", "/w"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("codex flags missing %q: %v", want, flags)
		}
	}
	read := BackendSpec{Approval: ApprovalNever, Sandbox: SandboxReadOnly, Workdir: "/w"}
	flags, err = Codex{}.project(read)
	if err != nil {
		t.Fatal(err)
	}
	joined = strings.Join(flags, " ")
	if !strings.Contains(joined, "read-only") || !strings.Contains(joined, "never") {
		t.Fatalf("read-only codex spec mis-projected: %v", flags)
	}
	bogus := BackendSpec{Sandbox: "bogus", Workdir: "/w"}
	codex := Codex{}
	if _, err := codex.project(bogus); err == nil {
		t.Fatal("invalid sandbox should error")
	}
}

// TestGLMProjectsSpec asserts the generic adapter projects the spec into its
// native flag surface.
func TestGLMProjectsSpec(t *testing.T) {
	spec := BackendSpec{Sandbox: SandboxWorkspaceWrite, Workdir: "/w"}
	flags, err := GLM{}.project(spec)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(flags, " ")
	for _, want := range []string{"stream-json", "acceptEdits", "--add-dir", "/w"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("glm flags missing %q: %v", want, flags)
		}
	}
	bogusGLM := BackendSpec{Sandbox: "bogus", Workdir: "/w"}
	glm := GLM{}
	if _, err := glm.project(bogusGLM); err == nil {
		t.Fatal("invalid sandbox should error")
	}
}

// TestAdaptersRunFakeBackend drives every adapter end-to-end against a fake
// backend binary, asserting the projected flags AND the prompt actually reach
// the backend argv and the transcript is captured. This is the adapter
// equivalent of the runtime cage-leak test: it proves the spec → flags →
// subprocess path is wired for each backend (a per-adapter wiring slip —
// e.g. forgetting to forward req.Prompt — fails here, not in production).
func TestAdaptersRunFakeBackend(t *testing.T) {
	tests := []struct {
		name      string
		envVar    string
		agent     Agent
		wantFlags []string
	}{
		{"claude", "GOV_CLAUDE_BIN", Claude{}, []string{"acceptEdits", "--add-dir"}},
		{"codex", "GOV_CODEX_BIN", Codex{}, []string{"workspace-write", "on-request"}},
		{"glm", "GOV_GLM_BIN", GLM{}, []string{"acceptEdits", "--add-dir"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fakeBin := filepath.Join(t.TempDir(), "fake-"+tc.name)
			// Echo args to stdout, not a side file: runCLI wires cmd.Stdout to
			// the transcript file, so this is the only way the flags land where
			// the assertions below look for them. LAST_ARG isolates the final
			// positional so the prompt-position assertion is exact.
			script := `#!/bin/sh
printf '%s\n' "$@"
for a in "$@"; do last="$a"; done
printf 'LAST_ARG=%s\n' "$last"
printf '{"type":"result","total_cost_usd":0.1}\n'
`
			if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
				t.Fatal(err)
			}
			t.Setenv(tc.envVar, fakeBin)
			transcript := filepath.Join(t.TempDir(), "out.jsonl")
			// cmd.Dir must exist: with SysProcAttr{Setpgid:true} set, a missing
			// Dir makes the child's chdir failure surface as a misleading
			// "fork/exec <bin>: no such file or directory" instead of naming chdir.
			workdir := t.TempDir()
			spec := BackendSpec{Approval: ApprovalOnRequest, Sandbox: SandboxWorkspaceWrite, Workdir: workdir}
			res, err := tc.agent.Run(context.Background(), Request{
				Prompt: "do the thing", Workdir: workdir, Transcript: transcript,
				Timeout: 5 * time.Second, Spec: spec,
			})
			if err != nil {
				t.Fatal(err)
			}
			if res.ExitCode != 0 {
				t.Fatalf("exit=%d", res.ExitCode)
			}
			data, err := os.ReadFile(transcript)
			if err != nil {
				t.Fatal(err)
			}
			body := string(data)
			// The prompt must reach the backend as the final positional arg.
			if !strings.Contains(body, "LAST_ARG=do the thing") {
				t.Fatalf("prompt not passed as final positional: %s", body)
			}
			for _, want := range tc.wantFlags {
				if !strings.Contains(body, want) {
					t.Fatalf("spec not projected to native flags (missing %q): %s", want, body)
				}
			}
		})
	}
}

// TestRunCLIRejectsEmptyPrompt pins the guard: an adapter that fails to forward
// req.Prompt must error immediately instead of launching a backend that blocks
// on stdin until the budget timeout burns.
func TestRunCLIRejectsEmptyPrompt(t *testing.T) {
	_, err := runCLI(context.Background(), runCLIRequest{
		bin: "/bin/true", workdir: t.TempDir(),
		transcript: filepath.Join(t.TempDir(), "t.jsonl"), timeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "empty prompt") {
		t.Fatalf("want empty-prompt error, got %v", err)
	}
}

func contains(slice []string, want string) bool {
	for _, s := range slice {
		if s == want {
			return true
		}
	}
	return false
}
