//go:build redteam

package agents

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/config"
)

func s14NodeHandle(t *testing.T, dependency string, nativeAddon bool) *BackendExecutionHandle {
	t.Helper()
	root := t.TempDir()
	entry := filepath.Join(root, "cli.js")
	if err := os.WriteFile(entry, []byte("#!/usr/bin/env node\nrequire('dep')\n"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "package.json"), []byte(`{"name":"s14-node"}`), 0644); err != nil {
		t.Fatal(err)
	}
	dep := filepath.Join(root, "node_modules", "dep", "index.js")
	if err := os.MkdirAll(filepath.Dir(dep), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dep, []byte(dependency), 0644); err != nil {
		t.Fatal(err)
	}
	if nativeAddon {
		if err := os.WriteFile(filepath.Join(filepath.Dir(dep), "addon.node"), []byte("native-original"), 0644); err != nil {
			t.Fatal(err)
		}
	}
	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	h, err := ResolveHandle(context.Background(), config.Config{Backends: map[string]config.Backend{
		"claude-code": {Bin: entry},
	}}, agent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = h.Close() })
	return h
}

func s14MutateFrozen(t *testing.T, h *BackendExecutionHandle, relative, replacement string) func() {
	t.Helper()
	path := filepath.Join(h.closureRoot, filepath.FromSlash(relative))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(replacement), 0600); err != nil {
		t.Fatal(err)
	}
	return func() {
		if err := os.WriteFile(path, original, 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0400); err != nil {
			t.Fatal(err)
		}
	}
}

func TestV14Case331MutatedFrozenDependencyAfterFinalVerificationIsDetected(t *testing.T) {
	h := s14NodeHandle(t, "module.exports = 'original';\n", false)
	if err := h.VerifyUnchanged(); err != nil {
		t.Fatalf("initial verification: %v", err)
	}
	restore := s14MutateFrozen(t, h, "node_modules/dep/index.js", "module.exports = 'hostile';\n")
	defer restore()
	if err := h.VerifyUnchanged(); err == nil {
		t.Fatal("whole-closure verification accepted a dependency changed after final entry verification")
	}
}

func TestV14Case332DependencyRestoredBeforeBackendCompletionIsStillDetected(t *testing.T) {
	h := s14NodeHandle(t, "module.exports = 'original';\n", false)
	restore := s14MutateFrozen(t, h, "node_modules/dep/index.js", "module.exports = 'hostile';\n")
	if err := h.VerifyUnchanged(); err == nil {
		t.Fatal("mutation was not detected while hostile dependency bytes were present")
	}
	restore()
	// A restored local tree cannot prove that hostile bytes did not execute;
	// approval is consequently rejected by the runtime policy (case 335).
	if err := h.VerifyUnchanged(); err != nil {
		t.Fatalf("restored tree should retain its original identity: %v", err)
	}
}

func TestV14Case333NativeAddonTransientSwapIsDetected(t *testing.T) {
	h := s14NodeHandle(t, "module.exports = require('./addon.node');\n", true)
	restore := s14MutateFrozen(t, h, "node_modules/dep/addon.node", "native-hostile")
	defer restore()
	if err := h.VerifyUnchanged(); err == nil {
		t.Fatal("closure verifier accepted a native-addon dependency swap")
	}
}

func TestV14Case334EntryUnchangedWhileDependencyChangesIsDetected(t *testing.T) {
	h := s14NodeHandle(t, "module.exports = 'original';\n", false)
	entry, err := os.ReadFile(h.launchPath)
	if err != nil {
		t.Fatal(err)
	}
	restore := s14MutateFrozen(t, h, "node_modules/dep/index.js", "module.exports = 'hostile';\n")
	defer restore()
	if got, err := os.ReadFile(h.launchPath); err != nil || string(got) != string(entry) {
		t.Fatalf("entry changed unexpectedly: %q (%v)", got, err)
	}
	if err := h.VerifyUnchanged(); err == nil {
		t.Fatal("entry-only verification would miss this; whole closure must reject it")
	}
}
