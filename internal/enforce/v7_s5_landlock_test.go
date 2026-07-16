package enforce

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestS5ExactRuntimeClosureHasNoBroadRoots(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	roots, err := exactReadClosure(shell, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(roots) < 2 {
		t.Fatalf("dynamic runtime closure unexpectedly small: %v", roots)
	}
	for _, root := range roots {
		if forbiddenBroadReadRoots[root] {
			t.Fatalf("broad root leaked into closure: %q", root)
		}
		info, err := os.Stat(root)
		if err != nil {
			t.Fatalf("closure path %q: %v", root, err)
		}
		if info.IsDir() {
			t.Fatalf("implicit closure entry is a directory: %q", root)
		}
	}
}

func TestS5BroadDeclaredRootsRejected(t *testing.T) {
	for root := range forbiddenBroadReadRoots {
		if _, err := exactReadClosure("", []string{root}); err == nil {
			t.Errorf("broad root %q was accepted", root)
		}
	}
}

func TestS5StageExecutableAddsELFClosureAndWrapEvidence(t *testing.T) {
	shell, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("sh unavailable")
	}
	declared := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(declared, []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := (Plan{Active: true, Workspace: t.TempDir(), AllowNetwork: true, selfExe: "/trusted/gov"}).WithExecutableAndReadRoots(shell, declared)
	if err != nil {
		t.Fatal(err)
	}
	if len(p.ReadRoots) < 3 {
		t.Fatalf("missing executable/runtime/declared closure: %v", p.ReadRoots)
	}
	_, args := p.Wrap(shell, nil)
	joined := strings.Join(args, "\n")
	for _, root := range p.ReadRoots {
		if !strings.Contains(joined, "--read-root\n"+root) {
			t.Fatalf("wrap omitted read root %q: %v", root, args)
		}
	}
}

func TestS5KernelPolicyAllowsRuntimeAndDeniesUndeclaredReads(t *testing.T) {
	if os.Getenv("GOV_S5_LANDLOCK_HELPER") == "1" {
		workspace := os.Getenv("GOV_S5_WORKSPACE")
		secret := os.Getenv("GOV_S5_SECRET")
		shell, err := exec.LookPath("sh")
		if err != nil {
			os.Exit(90)
		}
		if err := applyLandlockRuleset(workspace, false, shell, nil); err != nil {
			os.Exit(91)
		}
		if _, err := os.ReadFile(filepath.Join(workspace, "allowed")); err != nil {
			os.Exit(92)
		}
		if _, err := os.ReadFile(secret); err == nil {
			os.Exit(93)
		}
		if _, err := os.ReadFile("/proc/self/environ"); err == nil {
			os.Exit(94)
		}
		if err := exec.Command(shell, "-c", "read x < allowed; [ \"$x\" = ok ]; printf ok >/dev/null").Run(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(95)
		}
		os.Exit(0)
	}
	if !landlockUsable() {
		t.Skip("host Landlock ABI cannot enforce V3 policy")
	}
	parent := t.TempDir()
	workspace := filepath.Join(parent, "workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "allowed"), []byte("ok"), 0600); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(parent, "secret")
	if err := os.WriteFile(secret, []byte("deny"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestS5KernelPolicyAllowsRuntimeAndDeniesUndeclaredReads$")
	cmd.Dir = workspace
	cmd.Env = append(os.Environ(), "GOV_S5_LANDLOCK_HELPER=1", "GOV_S5_WORKSPACE="+workspace, "GOV_S5_SECRET="+secret)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Landlock helper failed: %v output=%s", err, out)
	}
}
