package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/enforce"
)

func writeHandleFixture(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0755); err != nil {
		t.Fatal(err)
	}
}

// TestResolveHandleHashesFromTheOpenDescriptor proves ResolveHandle's
// SHA256/CanonicalPath describe the same content the open descriptor backs,
// matching what a fresh independent read of the file would produce (there's
// only one file here; the point is the handle's fields are internally
// consistent, not that they differ from a naive read).
func TestResolveHandleHashesFromTheOpenDescriptor(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	writeHandleFixture(t, binPath, "echo hi\n")
	t.Setenv("GOV_CLAUDE_BIN", binPath)

	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: binPath}}}
	h, err := ResolveHandle(context.Background(), cfg, agent)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	defer h.Close()

	data, err := os.ReadFile(binPath)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	want := hex.EncodeToString(sum[:])
	if h.SHA256 != want {
		t.Fatalf("SHA256 = %q, want %q", h.SHA256, want)
	}
	if h.CanonicalPath != binPath {
		t.Fatalf("CanonicalPath = %q, want %q", h.CanonicalPath, binPath)
	}
	if h.file == nil {
		t.Fatal("expected an open file descriptor on the handle")
	}
}

// TestResolveHandleFailsClosedWhenUnresolvable mirrors
// TestSol3ResolvePathFailsClosedWhenUnresolvable for the new constructor: a
// bare name findable nowhere on PATH must be a hard error.
func TestResolveHandleFailsClosedWhenUnresolvable(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	agent, err := New("pi")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveHandle(context.Background(), config.Config{}, agent); err == nil {
		t.Fatal("expected ResolveHandle to fail closed for an unresolvable bare name, got nil error")
	}
}

// TestBackendExecutionHandleLaunchRejectsFileSwap is the unit-level proof
// behind report attack 6 (P0-6): once ResolveHandle has opened and hashed
// the executable, replacing the file at that same path (an in-place
// truncate+overwrite, exactly what attack 6's fixture and os.WriteFile both
// do) must cause LaunchCommand to refuse the launch entirely -- never
// silently run either the old or the new content. A script backend's
// shebang line makes the kernel re-open the path itself to find the
// interpreter, which defeats the held-fd protection alone; VerifyUnchanged's
// unconditional re-hash is what actually catches this case.
func TestBackendExecutionHandleLaunchRejectsFileSwap(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	writeHandleFixture(t, binPath, "printf original\n")

	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: binPath}}}
	h, err := ResolveHandle(context.Background(), cfg, agent)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	defer h.Close()

	// Swap the file at the same path for a hostile script, exactly as
	// attack 6's fixture does "in the instant between resolution and
	// launch."
	writeHandleFixture(t, binPath, "printf swapped\n")

	if _, err := LaunchCommand(context.Background(), h, binPath, nil); err == nil {
		t.Fatal("expected LaunchCommand to reject the launch after a post-resolution file swap, got nil error")
	}
}

// TestBackendExecutionHandleFDLaunchRunsVerifiedContent proves the positive
// case for the same mechanism: an UNTOUCHED resolved executable launches
// successfully via the fd-based path (Linux) and actually runs the
// originally-hashed content -- the fix must not over-block a legitimate,
// unmodified launch.
func TestBackendExecutionHandleFDLaunchRunsVerifiedContent(t *testing.T) {
	if goruntime.GOOS != "linux" {
		t.Skip("fd-based exec relies on /proc/self/fd, Linux-only")
	}
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	writeHandleFixture(t, binPath, "printf original\n")

	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: binPath}}}
	h, err := ResolveHandle(context.Background(), cfg, agent)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	defer h.Close()

	cmd, err := LaunchCommand(context.Background(), h, binPath, nil)
	if err != nil {
		t.Fatalf("LaunchCommand: %v", err)
	}
	if cmd.Path != "/proc/self/fd/3" {
		t.Fatalf("cmd.Path = %q, want the fd-based pseudo-path", cmd.Path)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(string(out)); got != "original" {
		t.Fatalf("output = %q, want original", got)
	}
}

// TestLaunchCommandNoHandleUsesPlainPath proves LaunchCommand's no-handle
// case (Request.ResolvedBin unset -- gov doctor probes, tests) is unchanged:
// a plain path launch, no fd trickery, no VerifyUnchanged.
func TestLaunchCommandNoHandleUsesPlainPath(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	writeHandleFixture(t, binPath, "printf ok\n")

	cmd, err := LaunchCommand(context.Background(), nil, binPath, nil)
	if err != nil {
		t.Fatalf("LaunchCommand: %v", err)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.TrimSpace(string(out)) != "ok" {
		t.Fatalf("output = %q, want ok", out)
	}
}

// TestVerifyUnchangedDetectsSwap proves the wrapper-launch fallback (used
// when a containment.Scope must exec via systemd-run/unshare, whose
// immediate child is the wrapper rather than the governed backend, so
// fd-passing can't reach the real target): re-stat+re-hash immediately
// before Start must reject a file swapped after ResolveHandle ran.
func TestVerifyUnchangedDetectsSwap(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	writeHandleFixture(t, binPath, "printf original\n")

	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: binPath}}}
	h, err := ResolveHandle(context.Background(), cfg, agent)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if err := h.VerifyUnchanged(); err != nil {
		t.Fatalf("VerifyUnchanged on an untouched file: %v", err)
	}

	writeHandleFixture(t, binPath, "printf swapped\n")
	if err := h.VerifyUnchanged(); err == nil {
		t.Fatal("expected VerifyUnchanged to reject a swapped file, got nil error")
	}
}

// TestLaunchStagedWrapperPathRejectsSwap proves the scope-wrapped launch path
// still fails closed on a post-resolution swap. Pre-P0-4, this was
// LaunchCommand's own scopeCmd-present branch; P0-4 (Sol12) moved the
// scope-bearing governed launch out of LaunchCommand entirely into
// LaunchStaged's CommandFactory (composeBackendLaunch), which calls
// handle.VerifyUnchanged() before composing anything (handle.go's factory,
// immediately before the `if p.Active` branch). This proves that guard is
// still reached and still fails closed through the actual current
// wrapper-launch path -- stage.Executor.Run's factory invocation -- rather
// than through the removed parameter that used to carry it. A factory error
// means nothing was launched (stage.go's own comment: "Nothing was
// launched... so there is nothing this scope could have failed to
// extinguish"), so LaunchStaged must return the VerifyUnchanged error with no
// process ever started.
func TestLaunchStagedWrapperPathRejectsSwap(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	writeHandleFixture(t, binPath, "printf original\n")

	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: binPath}}}
	h, err := ResolveHandle(context.Background(), cfg, agent)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	defer h.Close()

	writeHandleFixture(t, binPath, "printf swapped\n")

	scope, err := containment.NewScope("v12-s3-wrapper-swap-test", false, containment.ContainmentEnvironment{})
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	exitCode, descendantsGone, err := LaunchStaged(context.Background(), h, binPath, nil, binDir, io.Discard, scope, enforce.Plan{})
	if err == nil {
		t.Fatal("expected LaunchStaged to reject the launch after a post-resolution file swap, got nil error")
	}
	if !descendantsGone {
		t.Fatal("a rejected pre-launch swap started nothing, so DescendantsGone must be true (nothing to extinguish)")
	}
	if exitCode != 0 {
		t.Fatalf("exitCode = %d, want 0 for a launch that never started", exitCode)
	}
}

// TestNonNodeBackendHasNoClosureProvenTrivially proves P0-4's half of the
// model: a non-Node (plain shell) backend IS its own closure -- SHA256 binds
// the whole executable -- so resolution marks it closure-proven with no
// frozen closure, and its held descriptor is what composeBackendLaunch will
// fd-launch (File() returns it; closureRoot stays empty).
func TestNonNodeBackendHasNoClosureProvenTrivially(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	writeHandleFixture(t, binPath, "printf original\n")

	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: binPath}}}
	h, err := ResolveHandle(context.Background(), cfg, agent)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	defer h.Close()

	if !h.DependencyClosureProven {
		t.Fatal("non-Node backend must be closure-proven (it is its own closure)")
	}
	if h.DependencyClosureHash != "" {
		t.Fatalf("DependencyClosureHash = %q, want empty for a non-Node backend", h.DependencyClosureHash)
	}
	if h.closureRoot != "" {
		t.Fatalf("closureRoot = %q, want empty for a non-Node backend", h.closureRoot)
	}
	if h.File() == nil {
		t.Fatal("non-Node backend must expose its held descriptor for fd-launch")
	}
}

// TestNodeBackendClosureFrozenAndHashed proves P0-5's core: a Node-based
// backend (node shebang) gets its COMPLETE executable closure -- entry
// script + package.json + the resolved node_modules tree -- frozen into a
// private copy and content-hashed into identity, with NO live node_modules
// symlink. A swapped dependency mints a different closure hash; a missing
// package.json is tolerated (shebang-only match).
func TestNodeBackendClosureFrozenAndHashed(t *testing.T) {
	pkgDir := t.TempDir()
	// A node-shebang entry script.
	entryPath := filepath.Join(pkgDir, "cli.js")
	entryBody := []byte("#!/usr/bin/env node\nrequire('dep'); console.log('node backend');\n")
	if err := os.WriteFile(entryPath, entryBody, 0755); err != nil {
		t.Fatal(err)
	}
	// package.json + a lockfile.
	if err := os.WriteFile(filepath.Join(pkgDir, "package.json"), []byte(`{"name":"cli"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0644); err != nil {
		t.Fatal(err)
	}
	// A real node_modules dependency tree the backend resolves at run time.
	depDir := filepath.Join(pkgDir, "node_modules", "dep")
	if err := os.MkdirAll(depDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(depDir, "index.js"), []byte("module.exports = 1;\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(depDir, "package.json"), []byte(`{"name":"dep","version":"1.0.0"}`), 0644); err != nil {
		t.Fatal(err)
	}

	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: entryPath}}}
	h, err := ResolveHandle(context.Background(), cfg, agent)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	defer h.Close()

	if !h.DependencyClosureProven {
		t.Fatal("Node backend with a freezable closure must be closure-proven")
	}
	if h.DependencyClosureHash == "" {
		t.Fatal("DependencyClosureHash must be non-empty for a Node backend")
	}
	if h.closureRoot == "" {
		t.Fatal("closureRoot must be set (frozen closure copy) for a Node backend")
	}
	// NO live symlink: the frozen tree is a real copy under closureRoot.
	linkPath := filepath.Join(h.closureRoot, "node_modules")
	if fi, err := os.Lstat(linkPath); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("frozen node_modules at %s must be a real directory copy, not a symlink (stat err=%v)", linkPath, err)
	}
	// The frozen entry is a byte copy of the original entry.
	frozenEntry := filepath.Join(h.closureRoot, "entry")
	frozenBytes, err := os.ReadFile(frozenEntry)
	if err != nil {
		t.Fatalf("read frozen entry: %v", err)
	}
	if string(frozenBytes) != string(entryBody) {
		t.Fatalf("frozen entry content drifted from the original entry")
	}
	// VerifyUnchanged must re-verify the frozen entry (launchPath), not the
	// original path -- and pass while it is untouched.
	if err := h.VerifyUnchanged(); err != nil {
		t.Fatalf("VerifyUnchanged on untouched frozen entry: %v", err)
	}
	// Swapping a dependency in the ORIGINAL tree must NOT change the closure
	// hash already bound at resolution, and must NOT mutate the frozen copy
	// the launch reads (the frozen copy is isolated from the live tree).
	liveDep := filepath.Join(depDir, "index.js")
	if err := os.WriteFile(liveDep, []byte("module.exports = 'hostile';\n"), 0644); err != nil {
		t.Fatal(err)
	}
	frozenDep := filepath.Join(h.closureRoot, "node_modules", "dep", "index.js")
	frozenDepBytes, err := os.ReadFile(frozenDep)
	if err != nil {
		t.Fatalf("read frozen dep: %v", err)
	}
	if string(frozenDepBytes) != "module.exports = 1;\n" {
		t.Fatalf("frozen dependency drifted after a live-tree swap -- the frozen closure is not isolated: %q", frozenDepBytes)
	}
}

// TestBackendIdentityKnownRequiresProviderAndModelRevision proves an
// operator declaring only a bare bin path (no provider/model_revision) is
// treated as an unknown identity, not a silently-accepted default.
func TestBackendIdentityKnownRequiresProviderAndModelRevision(t *testing.T) {
	unknown := BackendIdentity{}
	if unknown.Known() {
		t.Fatal("zero-value BackendIdentity must not be Known")
	}
	partial := BackendIdentity{Provider: "anthropic"}
	if partial.Known() {
		t.Fatal("Provider alone must not be Known (ModelRevision also required)")
	}
	full := BackendIdentity{Provider: "anthropic", ModelRevision: "claude-opus-4-8"}
	if !full.Known() {
		t.Fatal("Provider+ModelRevision must be Known")
	}
}

// TestResolveHandleCarriesDeclaredIdentity proves ResolveHandle's Identity
// field is populated from the passed config.Config, not a hidden global.
func TestResolveHandleCarriesDeclaredIdentity(t *testing.T) {
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	writeHandleFixture(t, binPath, "echo hi\n")

	agent, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{Backends: map[string]config.Backend{
		"claude-code": {Bin: binPath, Provider: "anthropic", ModelRevision: "claude-opus-4-8", AccountID: "acct-1"},
	}}
	h, err := ResolveHandle(context.Background(), cfg, agent)
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()

	if !h.Identity.Known() {
		t.Fatal("expected a Known identity from the declared config")
	}
	if h.Identity.Provider != "anthropic" || h.Identity.ModelRevision != "claude-opus-4-8" || h.Identity.AccountID != "acct-1" {
		t.Fatalf("Identity = %+v, want declared fields carried through", h.Identity)
	}
}
