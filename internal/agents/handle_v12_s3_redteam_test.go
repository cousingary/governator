//go:build redteam

package agents

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/config"
)

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
