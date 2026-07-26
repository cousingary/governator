package runtime

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/prompts"
	"github.com/cousingary/governator/internal/toolregistry"
)

// TestV13Case38LegacyStringValidatorCannotApproveInProduction is Sol #39 /
// manifest 283. The legacy command still runs for migration/advisory use, but
// its ambient executable and script bytes cannot authorize a production merge.
func TestV13Case38LegacyStringValidatorCannotApproveInProduction(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	c := contract(root)
	c.Success.ValidatorSpecs = nil

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status == "APPROVED" {
		t.Fatalf("legacy validator reached APPROVED: %s", rec.Message)
	}
	for _, want := range []string{
		"LEGACY_VALIDATOR_NON_APPROVING",
		"success.validators[0]",
		"command: \"test -f output/result.txt\"",
		"tools: [<every executable>]",
		"files: [<every semantic script>]",
	} {
		if !strings.Contains(rec.Message, want) {
			t.Fatalf("migration diagnostic missing %q: %q", want, rec.Message)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); err == nil {
		t.Fatal("legacy validator merged output into the live root")
	}
}

// TestV13Case39AmbientPythonChangeUnderLegacyValidatorIsNonApproving is Sol
// #40 / manifest 284. It proves a legacy validator can inherit a changed ambient
// PATH during advisory migration, while the same run remains non-approving.
func TestV13Case39AmbientPythonChangeUnderLegacyValidatorIsNonApproving(t *testing.T) {
	root, bin := fixture(t)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	ambientDir := t.TempDir()
	ambientPython := filepath.Join(ambientDir, "python3")
	if err := os.WriteFile(ambientPython, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FAKE_AMBIENT_PYTHON", ambientPython)
	t.Setenv("PATH", ambientDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	frozen := controllerenv.Freeze()
	path, ok := frozen.Lookup("PATH")
	if !ok || !strings.HasPrefix(path, ambientDir+string(os.PathListSeparator)) {
		t.Fatalf("controller did not capture the changed ambient PATH: %q", path)
	}

	c := contract(root)
	// command -v makes this legacy command depend on the mutable ambient
	// python path without declaring a structured tool binding.
	c.Success.Validators = []string{"test \"$(command -v python3)\" = \"$FAKE_AMBIENT_PYTHON\""}
	c.Success.ValidatorSpecs = nil
	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status == "APPROVED" || !strings.Contains(rec.Message, "LEGACY_VALIDATOR_NON_APPROVING") {
		t.Fatalf("ambient legacy validator was not blocked: status=%s message=%q", rec.Status, rec.Message)
	}
}

// TestV13Case40ValidatorScriptChangeInvalidatesIdentity is Sol #41 / manifest
// 285. The structured declaration binds validate.py's bytes into the validator
// toolset hash and therefore the transaction identity.
func TestV13Case40ValidatorScriptChangeInvalidatesIdentity(t *testing.T) {
	root, _ := fixture(t)
	python, err := exec.LookPath("python3")
	if err != nil {
		t.Skip("python3 is required for the structured-validator fixture")
	}
	if _, err := toolregistry.Enroll("python3", python); err != nil {
		t.Fatal(err)
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "validate.py")
	if err := os.WriteFile(path, []byte("print('first')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	c := contract(root)
	c.Success.Validators = []string{"python3 validate.py"}
	c.Success.ValidatorSpecs = []contracts.ValidatorSpec{{Command: "python3 validate.py", Tools: []string{"python3"}, Files: []string{"validate.py"}}}
	first, err := resolveValidatorToolset(c, root, registry)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("print('second')\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	second, err := resolveValidatorToolset(c, root, registry)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("validator script byte change did not alter the frozen validator toolset hash")
	}
	agent, err := agents.New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	firstIdentity := computeExecutionIdentity(config.Config{}, c, agent, agents.PathResolution{}, agents.BackendIdentity{}, nil, nil, "env", "head", "contract", prompts.Version{}, "", PolicyBundle{}, containment.ContainmentEnvironment{}, "prompt", "consumed", "graph", "snapshot", "controller", first)
	secondIdentity := computeExecutionIdentity(config.Config{}, c, agent, agents.PathResolution{}, agents.BackendIdentity{}, nil, nil, "env", "head", "contract", prompts.Version{}, "", PolicyBundle{}, containment.ContainmentEnvironment{}, "prompt", "consumed", "graph", "snapshot", "controller", second)
	if firstIdentity.Hash() == secondIdentity.Hash() {
		t.Fatal("validator script byte change did not invalidate execution identity")
	}
}
