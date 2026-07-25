package agents

// handle_v12_s3_test.go holds the Sol v12 rc5 Session 3 backend-launch +
// Node-closure corpus (agents/governator-sol-upgrade12-rc5-plan.md Session 3,
// report P0-4/P0-5). It lives in package agents (untagged, like Session 2's
// TestV12Case8 in package containment) because it exercises the unexported
// composeBackendLaunch / freezeNodeDependencyClosure machinery and the held
// descriptor / closureRoot fields directly. Enrolled by exact name in
// internal/redteam/manifest.yaml (cases 209-214).

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/config"
)

// nodeFixtureBackend builds a Node-shebang backend under dir with an optional
// node_modules dependency tree (files maps "node_modules/..." or sibling paths
// to content), writes package.json + a lockfile, and returns the entry path.
func nodeFixtureBackend(t *testing.T, dir string, files map[string]string) string {
	t.Helper()
	entryPath := filepath.Join(dir, "cli.js")
	body := []byte("#!/usr/bin/env node\n// node backend fixture\n")
	if err := os.WriteFile(entryPath, body, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"name":"cli"}`), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "package-lock.json"), []byte(`{"lockfileVersion":3}`), 0644); err != nil {
		t.Fatal(err)
	}
	for rel, content := range files {
		p := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return entryPath
}

func sha256Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// TestV12Case14ReplaceBackendPathAfterVerifyUsesHeldDescriptor proves P0-4's
// core invariant: after final identity verification, replacing the backend
// executable at its pathname (unlink + recreate with hostile content) must NOT
// change what composeBackendLaunch launches, because it threads handle's HELD
// descriptor (/proc/self/fd/<n>), not the pathname. The held fd pins the
// original inode (surviving the unlink) and still reads the originally-hashed
// bytes -- a direct fd-launch therefore still runs the original content. The
// swap is ALSO caught up-front by VerifyUnchanged's dev/inode check (defense
// in depth); the held descriptor is the structural guarantee that even past
// that gate the launch object cannot have changed.
func TestV12Case14ReplaceBackendPathAfterVerifyUsesHeldDescriptor(t *testing.T) {
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
	wantSHA := h.SHA256

	// Swap the executable at its pathname for a hostile script (new inode),
	// exactly as a same-UID process does "in the instant between resolution
	// and launch."
	if err := os.Remove(binPath); err != nil {
		t.Fatal(err)
	}
	writeHandleFixture(t, binPath, "printf swapped-hostile\n")

	// VerifyUnchanged's dev/inode gate catches the unlink+recreate up front.
	if err := h.VerifyUnchanged(); err == nil {
		t.Fatal("VerifyUnchanged must reject an unlink+recreate path swap via its dev/inode check")
	}

	// The held descriptor (what composeBackendLaunch fd-launches via
	// alloc.Arg(h.file)) STILL reads the ORIGINAL bytes: the fd pins the
	// inode, which unlink left on disk for as long as the descriptor is open.
	if h.file == nil {
		t.Fatal("handle holds no open descriptor to fd-launch")
	}
	if _, err := h.file.Seek(0, 0); err != nil {
		t.Fatalf("rewind held fd: %v", err)
	}
	buf := make([]byte, 4096)
	n, _ := h.file.Read(buf)
	if got := sha256Bytes(buf[:n]); got != wantSHA {
		t.Fatalf("held descriptor content SHA = %s, want original %s (a path swap changed what the held fd reads -- composeBackendLaunch would launch the swapped bytes)", got, wantSHA)
	}

	// And a direct fd-launch of that held descriptor (exactly what
	// composeBackendLaunch builds) runs the ORIGINAL content, not the hostile
	// pathname replacement -- the structural P0-4 guarantee, independent of
	// the VerifyUnchanged gate above.
	if _, err := h.file.Seek(0, 0); err != nil {
		t.Fatalf("rewind held fd for launch: %v", err)
	}
	cmd := exec.CommandContext(context.Background(), "/proc/self/fd/3")
	cmd.ExtraFiles = []*os.File{h.file}
	out, runErr := cmd.Output()
	if runErr != nil {
		t.Fatalf("fd-launch run: %v", runErr)
	}
	if got := strings.TrimSpace(string(out)); got != "original" {
		t.Fatalf("fd-launch output = %q, want %q (composeBackendLaunch must launch the held descriptor, not the swapped pathname)", got, "original")
	}
}

// TestV12Case15ModifyNodeDependencyAfterReplayIdentityIsolated proves P0-5's
// isolation: once ResolveHandle has frozen a Node backend's dependency closure
// into a private copy and bound its hash into identity, modifying a live
// dependency AFTER replay-identity construction must NOT affect the bytes the
// governed run actually imports. The frozen closure is a real copy, not the
// pre-P0-5 live node_modules symlink, so the attack (swap a JS dependency, let
// the verified CLI import it, attribute the run to the original identity)
// fails: the run reads the frozen tree.
func TestV12Case15ModifyNodeDependencyAfterReplayIdentityIsolated(t *testing.T) {
	dir := t.TempDir()
	entryPath := nodeFixtureBackend(t, dir, map[string]string{
		"node_modules/dep/index.js":     "module.exports = 1;\n",
		"node_modules/dep/package.json": `{"name":"dep","version":"1.0.0"}`,
	})

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
		t.Fatal("expected a freezable Node closure to be proven")
	}
	wantHash := h.DependencyClosureHash
	frozenDep := filepath.Join(h.closureRoot, "node_modules", "dep", "index.js")
	wantFrozen, err := os.ReadFile(frozenDep)
	if err != nil {
		t.Fatalf("read frozen dep before swap: %v", err)
	}

	// Swap a live dependency AFTER replay identity was constructed.
	if err := os.WriteFile(filepath.Join(dir, "node_modules", "dep", "index.js"), []byte("module.exports = 'hostile';\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// The frozen closure the launch reads is untouched.
	gotFrozen, err := os.ReadFile(frozenDep)
	if err != nil {
		t.Fatalf("read frozen dep after live swap: %v", err)
	}
	if string(gotFrozen) != string(wantFrozen) {
		t.Fatalf("frozen dependency drifted after a live-tree swap -- the frozen closure is not isolated from the live node_modules")
	}
	// The closure hash bound at resolution is unchanged (identity describes the
	// frozen closure, not whatever the live tree happens to hold now).
	if h.DependencyClosureHash != wantHash {
		t.Fatalf("DependencyClosureHash changed after a live-tree swap: got %s, want %s", h.DependencyClosureHash, wantHash)
	}
}

// TestV12Case16RestoreBeforeMeasurementUnnecessaryClosureFrozen proves the
// second half of the P0-5 attack path: "modify a dependency, let it run,
// RESTORE it before final measurement." Because the run reads the frozen
// closure (never the live tree), restoration is irrelevant -- the frozen
// closure's integrity holds whether or not the live tree is restored, so the
// attack cannot smuggle modified bytes past identity even transiently.
func TestV12Case16RestoreBeforeMeasurementUnnecessaryClosureFrozen(t *testing.T) {
	dir := t.TempDir()
	origDep := "module.exports = 1;\n"
	entryPath := nodeFixtureBackend(t, dir, map[string]string{
		"node_modules/dep/index.js": origDep,
	})

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
	wantHash := h.DependencyClosureHash
	frozenDep := filepath.Join(h.closureRoot, "node_modules", "dep", "index.js")

	// Attack: modify, then restore before measurement.
	liveDep := filepath.Join(dir, "node_modules", "dep", "index.js")
	_ = os.WriteFile(liveDep, []byte("module.exports = 'hostile';\n"), 0644)
	_ = os.WriteFile(liveDep, []byte(origDep), 0644)

	got, err := os.ReadFile(frozenDep)
	if err != nil {
		t.Fatalf("read frozen dep: %v", err)
	}
	if string(got) != origDep {
		t.Fatalf("frozen dependency changed despite restore: %q", got)
	}
	if h.DependencyClosureHash != wantHash {
		t.Fatalf("closure hash changed despite restore: %s != %s", h.DependencyClosureHash, wantHash)
	}
}

// TestV12Case17AlterNativeNodeAddonIncludedInClosure proves P0-5 covers native
// addons too: a platform-native .node file inside node_modules is part of the
// frozen closure, content-hashed under its relative path, and isolated from a
// live swap just like a JS dependency. Native addons are how a same-UID
// attacker would smuggle arbitrary shared-object code into a verified Node CLI.
func TestV12Case17AlterNativeNodeAddonIncludedInClosure(t *testing.T) {
	dir := t.TempDir()
	addon := []byte{0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00} // ELF magic bytes (fixture, never loaded)
	entryPath := nodeFixtureBackend(t, dir, map[string]string{
		"node_modules/dep-native/build/Release/native.node": string(addon),
		"node_modules/dep-native/package.json":              `{"name":"dep-native","version":"1.0.0"}`,
	})

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
		t.Fatal("expected freezable Node closure (with native addon) to be proven")
	}
	frozenAddon := filepath.Join(h.closureRoot, "node_modules", "dep-native", "build", "Release", "native.node")
	got, err := os.ReadFile(frozenAddon)
	if err != nil {
		t.Fatalf("native addon not present in frozen closure: %v", err)
	}
	if string(got) != string(addon) {
		t.Fatalf("frozen native addon content drifted from the original")
	}
	wantHash := h.DependencyClosureHash

	// Swap the live native addon for a hostile shared object after resolution.
	liveAddon := filepath.Join(dir, "node_modules", "dep-native", "build", "Release", "native.node")
	_ = os.WriteFile(liveAddon, append(addon, 0xff, 0xff), 0644)

	// The frozen addon and closure hash are unchanged.
	got2, _ := os.ReadFile(frozenAddon)
	if string(got2) != string(addon) {
		t.Fatalf("frozen native addon changed after a live swap: not isolated")
	}
	if h.DependencyClosureHash != wantHash {
		t.Fatalf("closure hash changed after native-addon swap: %s != %s", h.DependencyClosureHash, wantHash)
	}
}

// TestV12Case18BackendDependencyTreeUnavailableDisablesStrictReplay proves
// P0-5's honest fallback: when a Node backend HAS a dependency closure but it
// cannot be frozen+hashed (the tree is unreadable/incomplete), resolution
// leaves DependencyClosureProven=false, and runtime.computeExecutionIdentity
// disables strict replay for the run (an unprovable closure cannot be
// reproduced against a specific verified tree by a later audit). The
// DependencyClosureProven=false signal is what the runtime gate reads; this
// case proves the signal fires. Skipped under root (root bypasses file perms,
// so an unreadable tree is still readable and the freeze would succeed).
func TestV12Case18BackendDependencyTreeUnavailableDisablesStrictReplay(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("unreadable-tree fixture is bypassed by root; run as non-root to exercise the unprovable-closure path")
	}
	dir := t.TempDir()
	entryPath := nodeFixtureBackend(t, dir, map[string]string{
		"node_modules/dep/index.js": "module.exports = 1;\n",
	})
	// Make the dependency file unreadable so copyTreeHashed cannot hash it.
	if err := os.Chmod(filepath.Join(dir, "node_modules", "dep", "index.js"), 0000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(dir, "node_modules", "dep", "index.js"), 0644)
	})

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

	if h.DependencyClosureProven {
		t.Fatal("a Node backend whose dependency tree cannot be frozen must NOT be closure-proven (strict replay would then wrongly engage)")
	}
	if h.DependencyClosureHash != "" {
		t.Fatalf("DependencyClosureHash must be empty when the closure is unprovable, got %q", h.DependencyClosureHash)
	}
}

// TestV12Case19StructuredBackendExecutionBindsDescriptorIdentity proves P0-4's
// "bind the actually-executed object's identity into ExecutionIdentity": for a
// non-Node backend the held descriptor's content SHA IS h.SHA256 (the value
// identity's BackendBinarySHA256 carries), so the identity describes exactly
// the object the fd-launch execs -- not the pathname. For a Node backend the
// frozen entry's content matches h.SHA256 (VerifyUnchanged re-verifies it) AND
// DependencyClosureHash binds the full closure the run imports.
func TestV12Case19StructuredBackendExecutionBindsDescriptorIdentity(t *testing.T) {
	// Non-Node: the held descriptor's content is what identity records.
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	writeHandleFixture(t, binPath, "printf structured\n")
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
	if _, err := h.file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 8192)
	n, _ := h.file.Read(buf)
	if got := sha256Bytes(buf[:n]); got != h.SHA256 {
		t.Fatalf("held descriptor SHA %s != identity SHA %s -- the launched object is not the one identity binds", got, h.SHA256)
	}

	// Node: the frozen entry the launch execs matches identity's SHA, and the
	// closure hash binds the full import tree.
	dir := t.TempDir()
	entryPath := nodeFixtureBackend(t, dir, map[string]string{
		"node_modules/dep/index.js": "module.exports = 1;\n",
	})
	agent2, err := New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	cfg2 := config.Config{Backends: map[string]config.Backend{"claude-code": {Bin: entryPath}}}
	h2, err := ResolveHandle(context.Background(), cfg2, agent2)
	if err != nil {
		t.Fatalf("ResolveHandle (node): %v", err)
	}
	defer h2.Close()
	frozenEntry, err := os.ReadFile(h2.launchPath)
	if err != nil {
		t.Fatalf("read frozen entry: %v", err)
	}
	if sha256Bytes(frozenEntry) != h2.SHA256 {
		t.Fatalf("frozen entry SHA != identity SHA -- the Node launch object is not the one identity binds")
	}
	if err := h2.VerifyUnchanged(); err != nil {
		t.Fatalf("VerifyUnchanged on the frozen entry must pass (it is the identity-bound launch object): %v", err)
	}
	if h2.DependencyClosureHash == "" {
		t.Fatal("Node backend identity must bind a non-empty dependency closure hash")
	}

	// Swapping the frozen entry must be detected by VerifyUnchanged (the
	// identity-bound object must not be swapped past final verification). The
	// frozen tree is locked down read-only (0400); a same-UID attacker must
	// chmod it writable first, so do the same here before overwriting.
	_ = os.Chmod(h2.launchPath, 0600)
	_ = os.WriteFile(h2.launchPath, append(frozenEntry, []byte("// hostile\n")...), 0600)
	if err := h2.VerifyUnchanged(); err == nil {
		t.Fatal("VerifyUnchanged must reject a swapped frozen entry (the identity-bound launch object was mutated)")
	}
}
