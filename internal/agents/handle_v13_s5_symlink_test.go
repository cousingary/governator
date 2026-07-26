package agents

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/config"
)

// freezeUnprovenNodeLink resolves a Node backend whose dependency tree contains
// linkRel -> linkTarget. A safe closure must reject every external, broken, or
// cyclic target rather than preserve a link into live storage.
func freezeUnprovenNodeLink(t *testing.T, linkRel, linkTarget string) *BackendExecutionHandle {
	t.Helper()
	dir := t.TempDir()
	entry := nodeFixtureBackend(t, dir, map[string]string{
		"node_modules/internal/index.js": "module.exports = 'sealed';\n",
	})
	linkPath := filepath.Join(dir, "node_modules", linkRel)
	if err := os.MkdirAll(filepath.Dir(linkPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(linkTarget, linkPath); err != nil {
		t.Fatal(err)
	}
	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	h, err := ResolveHandle(context.Background(), config.Config{Backends: map[string]config.Backend{
		"claude-code": {Bin: entry},
	}}, agent)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })
	if h.DependencyClosureProven || h.DependencyClosureHash != "" || h.closureRoot != "" {
		t.Fatalf("unsafe link produced a closure-proven handle: proven=%t hash=%q root=%q", h.DependencyClosureProven, h.DependencyClosureHash, h.closureRoot)
	}
	return h
}

func externalNodeTarget(t *testing.T, name string) string {
	t.Helper()
	target := filepath.Join(t.TempDir(), name)
	if err := os.MkdirAll(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(target, "index.js"), []byte("module.exports = 'safe';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return target
}

// TestV13Case28AbsoluteSymlinkEscapingClosureIsRejected is Sol #23 / manifest 273.
func TestV13Case28AbsoluteSymlinkEscapingClosureIsRejected(t *testing.T) {
	freezeUnprovenNodeLink(t, "dep", externalNodeTarget(t, "live-dep"))
}

// TestV13Case29RelativeSymlinkEscapingClosureIsRejected is Sol #24 / manifest 274.
func TestV13Case29RelativeSymlinkEscapingClosureIsRejected(t *testing.T) {
	// Build the relative escape under a parent whose sibling is the live tree.
	base := t.TempDir()
	project := filepath.Join(base, "project")
	live := filepath.Join(base, "live")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(live, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(live, "index.js"), []byte("module.exports='safe'"), 0o644); err != nil {
		t.Fatal(err)
	}
	entry := nodeFixtureBackend(t, project, map[string]string{})
	if err := os.MkdirAll(filepath.Join(project, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", "..", "live"), filepath.Join(project, "node_modules", "dep")); err != nil {
		t.Fatal(err)
	}
	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	h, err := ResolveHandle(context.Background(), config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: entry}}}, agent)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.DependencyClosureProven || h.DependencyClosureHash != "" || h.closureRoot != "" {
		t.Fatalf("relative escape was accepted: %+v", h.PathResolution)
	}
}

// TestV13Case30PnpmStoreSymlinkIsFrozenOrRejected is Sol #25 / manifest 275.
func TestV13Case30PnpmStoreSymlinkIsFrozenOrRejected(t *testing.T) {
	freezeUnprovenNodeLink(t, ".pnpm/dep@1/node_modules/dep", externalNodeTarget(t, "pnpm-store"))
}

// TestV13Case31NpmLinkDependencyIsFrozenOrRejected is Sol #26 / manifest 276.
func TestV13Case31NpmLinkDependencyIsFrozenOrRejected(t *testing.T) {
	freezeUnprovenNodeLink(t, "linked-workspace-package", externalNodeTarget(t, "npm-link"))
}

// TestV13Case32SymlinkCycleIsRejected is Sol #27 / manifest 277.
func TestV13Case32SymlinkCycleIsRejected(t *testing.T) {
	dir := t.TempDir()
	entry := nodeFixtureBackend(t, dir, map[string]string{"node_modules/.keep": ""})
	if err := os.Symlink("b", filepath.Join(dir, "node_modules", "a")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a", filepath.Join(dir, "node_modules", "b")); err != nil {
		t.Fatal(err)
	}
	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	h, err := ResolveHandle(context.Background(), config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: entry}}}, agent)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	if h.DependencyClosureProven {
		t.Fatal("symlink cycle was closure-proven")
	}
}

// TestV13Case33BrokenSymlinkIsRejected is Sol #28 / manifest 278.
func TestV13Case33BrokenSymlinkIsRejected(t *testing.T) {
	freezeUnprovenNodeLink(t, "dep", "missing-target")
}

// TestV13Case34ExternalTargetChangedAfterIdentityCalculationIsDetected is Sol #29 / manifest 279.
func TestV13Case34ExternalTargetChangedAfterIdentityCalculationIsDetected(t *testing.T) {
	live := externalNodeTarget(t, "mutable-live-dep")
	h := freezeUnprovenNodeLink(t, "dep", live)
	if err := os.WriteFile(filepath.Join(live, "index.js"), []byte("module.exports = 'hostile-after-freeze';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if h.DependencyClosureProven || h.DependencyClosureHash != "" {
		t.Fatal("external target mutation remained eligible for a frozen identity")
	}
}

// TestV13Case35ExternalTargetRestoredAfterExecutionIsDetected is Sol #30 / manifest 280.
func TestV13Case35ExternalTargetRestoredAfterExecutionIsDetected(t *testing.T) {
	live := externalNodeTarget(t, "restored-live-dep")
	h := freezeUnprovenNodeLink(t, "dep", live)
	path := filepath.Join(live, "index.js")
	if err := os.WriteFile(path, []byte("module.exports = 'hostile';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("module.exports = 'safe';\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if h.DependencyClosureProven || h.DependencyClosureHash != "" {
		t.Fatal("restored external target remained eligible for a frozen identity")
	}
}

// TestV13Case36NativeAddonReachedThroughExternalSymlinkIsRejected is Sol #31 / manifest 281.
func TestV13Case36NativeAddonReachedThroughExternalSymlinkIsRejected(t *testing.T) {
	addon := filepath.Join(t.TempDir(), "native.node")
	if err := os.WriteFile(addon, []byte{0x7f, 'E', 'L', 'F'}, 0o644); err != nil {
		t.Fatal(err)
	}
	freezeUnprovenNodeLink(t, "dep/build/Release/native.node", addon)
}
