//go:build redteam

package redteam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/assay"
	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/enforce"
	stageexec "github.com/cousingary/governator/internal/stage"
)

func TestV8Case3ValidatorNetworkDenyDoesNotInheritBackendAllow(t *testing.T) {
	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	root := fixtureRepo(t)
	c := baseContract(root)
	c.Forbidden.Behaviors = nil
	c.Success.Validators = []string{
		"test -f output/result.txt",
		"curl -s -m 3 -X POST --data validator-inherited-backend-network " + srv.URL + " >/dev/null 2>&1 || true",
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if atomic.LoadInt32(&received) > 0 && rec.Status == "APPROVED" {
		t.Fatalf("validator inherited backend network allowance (%d request(s))", atomic.LoadInt32(&received))
	}
}

func TestV8Case4SuccessValidatorCannotRewriteBackendOutput(t *testing.T) {
	root := fixtureRepo(t)
	c := baseContract(root)
	c.Success.Validators = []string{
		"test -f output/result.txt",
		"printf validator-overwrite > output/result.txt",
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	got, _ := os.ReadFile(filepath.Join(root, "output", "result.txt"))
	if rec.Status == "APPROVED" && strings.TrimSpace(string(got)) == "validator-overwrite" {
		t.Fatal("success validator rewrote backend output and run still approved")
	}
}

func TestV8Case5CleanupValidatorCannotWriteOutsideDeclaredRoots(t *testing.T) {
	root := fixtureRepo(t)
	hostEscape := filepath.Join(t.TempDir(), "outside-governator-v8-case5.txt")
	c := baseContract(root)
	c.Cleanup = &contracts.Cleanup{
		Required:   false,
		Validators: []string{"printf escaped > " + hostEscape + " 2>/dev/null || true"},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command:    "printf escaped > " + hostEscape + " 2>/dev/null || true",
			Tools:      []string{"bash"},
			WriteRoots: []string{"output"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if _, err := os.Stat(hostEscape); err == nil && rec.Status == "APPROVED" {
		t.Fatalf("cleanup validator wrote outside declared roots (%s)", hostEscape)
	}
}

func TestV8Case6AssayerFailsClosedWithoutExternalSandbox(t *testing.T) {
	enrollRealPython3(t)
	enforce.ForceUnsupported = true
	defer func() { enforce.ForceUnsupported = false }()

	dir := t.TempDir()
	artifactPath, sha := assayerTestArtifact(t, dir, `{"ok":true}`)
	cfg := assay.Config{Repo: dir, Timeout: time.Second}
	v := assay.Evaluate(context.Background(), cfg, assayerTestRequest("v8-case6", sha), artifactPath)
	if !v.HadError || !strings.Contains(v.Reason, "construct authority plan") {
		t.Fatalf("verdict = %+v, want fail-closed sandbox error", v)
	}
}

func TestV8Case7GraphProviderFailsClosedWithoutExternalSandbox(t *testing.T) {
	enforce.ForceUnsupported = true
	defer func() { enforce.ForceUnsupported = false }()

	root := fixtureRepo(t)
	bin := buildFakeCodegraphBinary(t, "", "", "")
	status := contextgraph.Status{Mode: "auto", Provider: "codegraph", Bin: bin, Path: bin, Enabled: true}
	_, err := contextgraph.Inspect(context.Background(), status, root)
	if err == nil || !strings.Contains(err.Error(), "construct authority plan") {
		t.Fatalf("error = %v, want fail-closed sandbox refusal", err)
	}
}

func TestV8Case8AuthorityRejectsContradictorySuppliedPlan(t *testing.T) {
	executable, err := stageexec.HashExecutable("/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	env := controllerenv.Base()
	_, err = stageexec.NewExecutor().Run(context.Background(), stageexec.StageSpec{
		RunID:            "v8-phase2",
		StageID:          "authority-contradiction",
		Executable:       executable,
		Environment:      stageexec.FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
		OutputCapture:    stageexec.CaptureNone,
		DescendantPolicy: stageexec.DescendantPolicy{RequireStrong: true},
		Authority:        stageexec.StageAuthority{ReadRoots: []string{"."}, Network: stageexec.NetworkPolicyDenied, Credentials: stageexec.CredentialPolicyNone, RequireStrongScope: true},
		EnforcementPlan:  enforce.Plan{Active: true, ReadOnly: true, AllowNetwork: true},
	})
	if err == nil || !strings.Contains(err.Error(), "authority denies network but plan allows it") {
		t.Fatalf("error = %v, want authority/plan contradiction", err)
	}
}
