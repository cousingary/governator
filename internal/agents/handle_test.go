package agents

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	goruntime "runtime"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/config"
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

	if _, err := LaunchCommand(context.Background(), h, binPath, nil, nil); err == nil {
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

	cmd, err := LaunchCommand(context.Background(), h, binPath, nil, nil)
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

	cmd, err := LaunchCommand(context.Background(), nil, binPath, nil, nil)
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

// TestLaunchCommandWrapperPathRejectsSwap proves LaunchCommand's
// scopeCmd-present branch (simulating a containment.Scope wrapper launch)
// actually calls VerifyUnchanged and fails closed on a swap, rather than
// launching the wrapper over the new content.
func TestLaunchCommandWrapperPathRejectsSwap(t *testing.T) {
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

	writeHandleFixture(t, binPath, "printf swapped\n")

	scopeCmd := func(ctx context.Context, bin string, args []string) *exec.Cmd {
		return exec.CommandContext(ctx, bin, args...)
	}
	if _, err := LaunchCommand(context.Background(), h, binPath, nil, scopeCmd); err == nil {
		t.Fatal("expected LaunchCommand to reject the swap before invoking the wrapper, got nil error")
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
