//go:build sol14repro

// This build-tagged fixture exercises Sol14 P0-4 with a second same-UID
// process. It remains outside the ordinary release tier because it directly
// coordinates a hostile mutator process, but after S7 it proves the complete
// closure verifier detects that process's dependency swap.
//
// Run explicitly:
//
//	go test -tags sol14repro -count=1 -run 'TestSol14P04' ./internal/redteam/fixtures/
//
// It lives in a _test.go file so that it is exempt — by the ratchets' own
// pre-existing rule, not by a new allowlist entry — from the raw-exec ratchet
// (internal/govlint) and the no-launch-outside-StageExecutor invariant
// (internal/stage). Neither invariant is weakened to carry this fixture.

package fixtures

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/config"
)

// depEnvVar carries the frozen-closure dependency path to the re-executed
// child. Its presence is what turns the helper test into the mutator.
const depEnvVar = "SOL14_P04_DEP"

// TestSol14P04HelperMutateDependency is the second same-UID process. It is a
// helper, not an assertion: it chmods a 0400 file beneath a 0500 frozen
// closure directory, replaces its bytes, waits, then restores both the
// original bytes and the original mode.
func TestSol14P04HelperMutateDependency(t *testing.T) {
	dep := os.Getenv(depEnvVar)
	if dep == "" {
		t.Skip("helper process only; driven by TestSol14P04NodeClosureSameUIDMutation")
	}

	original, err := os.ReadFile(dep)
	if err != nil {
		t.Fatalf("read dependency: %v", err)
	}
	info, err := os.Stat(dep)
	if err != nil {
		t.Fatalf("stat dependency: %v", err)
	}
	if err := os.Chmod(dep, 0600); err != nil {
		t.Fatalf("chmod 0400 dependency to writable: %v", err)
	}
	if err := os.WriteFile(dep, []byte("module.exports = 'hostile';\n"), 0600); err != nil {
		t.Fatalf("replace dependency bytes: %v", err)
	}
	os.Stdout.WriteString("SOL14-MUTATED\n")

	if _, err := bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
		t.Fatalf("await restore signal: %v", err)
	}

	if err := os.WriteFile(dep, original, 0600); err != nil {
		t.Fatalf("restore dependency bytes: %v", err)
	}
	if err := os.Chmod(dep, info.Mode().Perm()); err != nil {
		t.Fatalf("restore dependency mode: %v", err)
	}
	os.Stdout.WriteString("SOL14-RESTORED\n")
}

// TestSol14P04NodeClosureSameUIDMutation freezes a real Node dependency
// closure through the production path, then proves that a second same-UID
// process cannot swap a dependency's bytes without VerifyUnchanged detecting
// it. Restoring the bytes afterwards is intentionally observable as a clean
// final tree; local Node execution is separately non-approving because a
// transient same-UID swap cannot be proven away by an after-the-fact hash.
func TestSol14P04NodeClosureSameUIDMutation(t *testing.T) {
	if os.Getenv(depEnvVar) != "" {
		t.Skip("child mutator process")
	}

	source := t.TempDir()
	entry := filepath.Join(source, "cli.js")
	if err := os.WriteFile(entry, []byte("#!/usr/bin/env node\nrequire('dep')\n"), 0755); err != nil {
		t.Fatalf("write entry script: %v", err)
	}
	if err := os.WriteFile(filepath.Join(source, "package.json"), []byte(`{"name":"fixture"}`), 0644); err != nil {
		t.Fatalf("write package.json: %v", err)
	}
	depSource := filepath.Join(source, "node_modules", "dep", "index.js")
	if err := os.MkdirAll(filepath.Dir(depSource), 0755); err != nil {
		t.Fatalf("create node_modules: %v", err)
	}
	if err := os.WriteFile(depSource, []byte("module.exports = 'original';\n"), 0644); err != nil {
		t.Fatalf("write dependency: %v", err)
	}

	agent, err := agents.New("claude-code")
	if err != nil {
		t.Fatalf("resolve agent: %v", err)
	}
	cfg := config.Config{Backends: map[string]config.Backend{
		"claude-code": {Bin: entry},
	}}
	handle, err := agents.ResolveHandle(context.Background(), cfg, agent)
	if err != nil {
		t.Fatalf("resolve handle: %v", err)
	}
	defer handle.Close()

	if !handle.DependencyClosureProven || handle.DependencyClosureHash == "" {
		t.Fatalf("Node closure was not frozen and hashed; fixture preconditions do not hold")
	}

	rootField := reflect.ValueOf(handle).Elem().FieldByName("closureRoot")
	if !rootField.IsValid() || rootField.Kind() != reflect.String {
		t.Fatalf("could not locate frozen closure root on handle")
	}
	root := rootField.String()
	dep := filepath.Join(root, "node_modules", "dep", "index.js")

	rootInfo, err := os.Stat(root)
	if err != nil {
		t.Fatalf("stat closure root: %v", err)
	}
	depInfo, err := os.Stat(dep)
	if err != nil {
		t.Fatalf("stat frozen dependency: %v", err)
	}
	if rootInfo.Mode().Perm() != 0500 || depInfo.Mode().Perm() != 0400 {
		t.Fatalf("unexpected frozen modes: root=%#o dep=%#o (expected 0500/0400)",
			rootInfo.Mode().Perm(), depInfo.Mode().Perm())
	}

	cmd := exec.Command(os.Args[0], "-test.run", "^TestSol14P04HelperMutateDependency$", "-test.count=1")
	cmd.Env = append(os.Environ(), depEnvVar+"="+dep)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("child stdout pipe: %v", err)
	}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("child stdin pipe: %v", err)
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start same-UID mutator: %v", err)
	}

	scanner := bufio.NewScanner(stdout)
	awaitMarker := func(marker string) {
		t.Helper()
		for scanner.Scan() {
			if scanner.Text() == marker {
				return
			}
		}
		t.Fatalf("same-UID mutator never reported %s: %v", marker, scanner.Err())
	}

	awaitMarker("SOL14-MUTATED")

	hostile, err := os.ReadFile(dep)
	if err != nil {
		t.Fatalf("read mutated dependency: %v", err)
	}
	if string(hostile) != "module.exports = 'hostile';\n" {
		t.Fatalf("dependency was not actually mutated; got %q", string(hostile))
	}

	wantHash := handle.DependencyClosureHash
	if err := handle.VerifyUnchanged(); err == nil {
		t.Fatal("VerifyUnchanged did not detect the frozen dependency mutation")
	}
	if handle.DependencyClosureHash != wantHash {
		t.Fatalf("recorded closure identity changed during mutation")
	}

	if _, err := stdin.Write([]byte("restore\n")); err != nil {
		t.Fatalf("signal restore: %v", err)
	}
	awaitMarker("SOL14-RESTORED")
	if err := cmd.Wait(); err != nil {
		t.Fatalf("same-UID mutator exited nonzero: %v", err)
	}

	restored, err := os.ReadFile(dep)
	if err != nil {
		t.Fatalf("read restored dependency: %v", err)
	}
	if string(restored) != "module.exports = 'original';\n" {
		t.Fatalf("dependency bytes were not restored; got %q", string(restored))
	}
	if err := handle.VerifyUnchanged(); err != nil {
		t.Fatalf("VerifyUnchanged failed after restoration: %v", err)
	}
	if handle.DependencyClosureHash != wantHash {
		t.Fatalf("recorded closure hash changed after restoration")
	}

	proof, err := json.Marshal(map[string]any{
		"dependency_mutated_by_second_same_uid_process": true,
		"whole_closure_verification_detected_mutation":  true,
		"closure_identity_remained_bound_to_original":   true,
		"original_bytes_and_modes_restored":             true,
	})
	if err != nil {
		t.Fatalf("encode proof: %v", err)
	}
	t.Logf("SOL14-P04-PROOF %s", proof)
}
