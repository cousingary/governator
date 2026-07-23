package runtime

import (
	"bytes"
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/controllerenv"
	"github.com/cousingary/governator/internal/enforce"
	stageexec "github.com/cousingary/governator/internal/stage"
	"github.com/cousingary/governator/internal/toolregistry"
)

// TestV11Case33EnforcedStageExecutableLaunchesThroughDescriptorNeverPathname
// is Sol11 rc5 Session 4 corpus case 29 (agents/governator-sol-upgrade11.md
// P0-5, agents/governator-sol-upgrade11-rc5-plan.md Session 4): "replace a
// validator tool after final Verify". stageexec.StageSpec.ExecutableHandle
// is exactly the shape internal/runtime's own shellStage uses for every
// command-string/structured validator (ExecutableHandle: bashHandle) --
// "stage executables routed through enforcement wrappers", the report's
// affected object alongside systemd-run/unshare.
//
// Before this fix, stageexec.Executor.Run's default factory (invoked
// whenever spec.CommandFactory is nil and spec.ExecutableHandle is set, and
// the compiled enforce.Plan is Active) sealed a fresh private copy of the
// handle's held bytes to a real pathname, re-verified that copy, then
// handed the pathname to enforce.Plan.Wrap, which embedded it as a literal
// argv string the kernel re-resolves at exec -- a same-uid tamper of the
// sealed copy between its own Verify() and the kernel's open-for-exec could
// still swap what runs. The fix (toolregistry.FDAllocator +
// enforce.Plan.WrapWith + containment.Scope.CommandWith) launches through
// the handle's own held, already-verified descriptor via /proc/self/fd/<n>
// instead, so no pathname is ever reopened after resolution.
//
// This test resolves a toolregistry.Handle itself (mirroring
// registry.ResolveHandle inside shellStage), THEN replaces the file at that
// handle's own enrolled path -- the same same-uid tamper
// containment.TestScopeCommandLaunchesThroughSealedCopyNeverPathname
// exercises for the containment primitive -- and only THEN drives the
// already-resolved handle through stageexec.NewExecutor().Run under a real,
// internally-compiled active enforce.Plan (this host must actually support
// Landlock+unshare; enforce.SelfExeOverride points the re-exec chain at a
// freshly built real gov binary, since a bare `go test` binary has no
// __sandbox_exec handler of its own). The executed output must be the
// ORIGINAL verified bytes, never the replacement.
func TestV11Case33EnforcedStageExecutableLaunchesThroughDescriptorNeverPathname(t *testing.T) {
	if !enforce.Supported() {
		t.Skip("conditional: this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}

	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	// stageexec.Executor.Run resolves its own ContainmentEnvironment when
	// none is already attached to ctx (it isn't here) -- unshare/
	// systemd-run must be enrolled in this same isolated registry for that
	// resolution to find a real descendant-owning primitive, best-effort
	// exactly like containment's own testContainmentEnvironment helper.
	for _, name := range []string{"unshare", "systemd-run"} {
		if path, lerr := exec.LookPath(name); lerr == nil {
			if _, eerr := toolregistry.Enroll(name, path); eerr != nil {
				t.Fatalf("enroll %s: %v", name, eerr)
			}
		}
	}

	// A real compiled ELF binary, not a "#!/bin/sh" script -- a script's
	// own read-closure is just the script file itself (its interpreter must
	// be separately declared through ReadRoots, which this fixture does
	// not do), so it would fail closed under real Landlock confinement for
	// reasons unrelated to the property this test checks. Two distinct Go
	// sources compiled to the SAME enrolled path across two builds mirrors
	// TestV9Case23DeclaredToolSwappedAfterIdentityCalcFailsClosed's own
	// enrolledGo/swappedGo fixture pattern.
	dir := t.TempDir()
	pinned := filepath.Join(dir, "validator-tool")
	buildToolBinary(t, dir, "original", pinned)
	if _, err := toolregistry.Enroll("validator-tool", pinned); err != nil {
		t.Fatal(err)
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	handle, err := registry.ResolveHandle("validator-tool", "validator-tool", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	defer handle.Close()

	// Same-uid tamper: replace the file at the enrolled path AFTER the
	// handle already holds it open -- via rename, so a NEW inode lands at
	// pinned (mirroring containment's own sibling test).
	replacementPath := pinned + ".replacement"
	buildToolBinary(t, dir, "replacement", replacementPath)
	if err := os.Rename(replacementPath, pinned); err != nil {
		t.Fatal(err)
	}

	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	workdir := t.TempDir()
	env := controllerenv.Base()
	var stdout bytes.Buffer
	res, err := stageexec.NewExecutor().Run(context.Background(), stageexec.StageSpec{
		RunID: "v11-case33", StageID: "validator-tool-swap",
		Executable:       stageexec.ExecutableIdentity{CanonicalPath: handle.Identity.CanonicalPath, SHA256: handle.Identity.SHA256},
		WorkingDirectory: workdir,
		Environment:      stageexec.FrozenEnvironment{Values: env, Hash: controllerenv.Hash(env)},
		OutputCapture:    stageexec.CaptureRequiredComplete,
		OutputLimit:      1 << 20,
		DescendantPolicy: stageexec.DescendantPolicy{RequireStrong: true},
		Authority: stageexec.StageAuthority{
			ReadRoots:          []string{workdir},
			Network:            stageexec.NetworkPolicyDenied,
			Credentials:        stageexec.CredentialPolicyNone,
			RequireStrongScope: true,
		},
		ExecutableHandle: handle,
		Stdout:           &stdout,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if res.ExitStatus != 0 {
		t.Fatalf("stage exited %d, want 0 (output=%q)", res.ExitStatus, stdout.String())
	}
	if stdout.String() != "original" {
		t.Fatalf("stage executable output %q, want %q -- the same-uid replacement of the enrolled path must have no effect on what actually executes", stdout.String(), "original")
	}
}

// buildToolBinary compiles a tiny Go program that prints label to stdout
// (no trailing newline) and writes it to out, mirroring
// internal/redteam's own buildPathPrinterBinary/TestV9Case23 fixture
// pattern of compiling small distinct Go binaries for swap tests instead of
// shell scripts (a script's interpreter dependency is not something a bare
// swap fixture declares to Landlock).
func buildToolBinary(t *testing.T, dir, label, out string) {
	t.Helper()
	srcDir, err := os.MkdirTemp(dir, "src-*")
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(srcDir, "main.go")
	source := "package main\n\nimport \"fmt\"\n\nfunc main() {\n\tfmt.Print(\"" + label + "\")\n}\n"
	if err := os.WriteFile(src, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, src)
	cmd.Dir = srcDir
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build %s tool binary: %v: %s", label, err, combined)
	}
}
