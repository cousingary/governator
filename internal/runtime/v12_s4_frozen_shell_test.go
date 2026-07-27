//go:build redteam

package runtime

// v12_s4_frozen_shell_test.go holds the Sol v12 rc5 Session 4 corpus for
// P0-6 (agents/governator-sol-upgrade12-rc5-plan.md Session 4, report
// "General controller shell execution escapes the frozen transaction").
// shell() (runtime.go) now takes the run's frozen *toolregistry.Registry as
// a parameter instead of calling toolregistry.Load() itself, and its
// subprocess PATH is private to the sealed git+bash directories it already
// resolved and verified -- never the ambient base PATH. These cases prove
// both halves of that invariant directly against the production shell()
// helper: a same-UID registry rotation mid-transaction has no effect on a
// run already carrying its own frozen registry object, and the command
// string this helper runs can resolve nothing beyond git and bash. Enrolled
// by exact name in internal/redteam/manifest.yaml (cases 215-218).

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/toolregistry"
)

// v12s4WriteScript writes an executable shell script at a fresh path inside
// t.TempDir() and returns its path.
func v12s4WriteScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte(body), 0755); err != nil {
		t.Fatal(err)
	}
	return path
}

// v12s4FrozenRunEnvironment enrolls a real git and bash (git preferring the
// canonical /usr/bin/git over whatever a dev host's PATH shim resolves to,
// per lookPathPreferCanonicalGit) into an isolated registry file and returns
// the ONE loaded *toolregistry.Registry object a governed run would carry
// for its whole transaction -- mirroring buildRunEnvironment's exactly-once
// Load().
func v12s4FrozenRunEnvironment(t *testing.T) *toolregistry.Registry {
	t.Helper()
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	for _, name := range []string{"git", "bash"} {
		bin, err := lookPathPreferCanonicalGit(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := toolregistry.Enroll(name, bin); err != nil {
			t.Fatal(err)
		}
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

// TestV12Case20GitRegistryRotatedAfterRunFreezeHasNoEffect is corpus 20:
// rotating the enrolled "git" binary on disk after a run has already loaded
// its own frozen *toolregistry.Registry object must have no effect on
// shell() calls made through that same object for the rest of the
// transaction -- shell() must never reload the registry itself.
func TestV12Case20GitRegistryRotatedAfterRunFreezeHasNoEffect(t *testing.T) {
	dir := t.TempDir()
	registry := v12s4FrozenRunEnvironment(t)

	// The frozen registry resolves the originally-enrolled git before any
	// rotation.
	_, out, err := shell(context.Background(), dir, "git", registry)
	if err != nil {
		t.Fatalf("shell() before rotation: %v", err)
	}
	if !strings.Contains(out, "usage: git") && !strings.Contains(out, "git version") {
		// Real git prints a usage/help block for a bare "git" invocation;
		// either shape confirms the real, originally-enrolled binary ran.
		t.Fatalf("shell() before rotation did not look like real git output: %q", out)
	}

	// Same-UID rotation: re-enroll "git" to a wholly different, fake binary,
	// proving the on-disk registry genuinely changed.
	rotated := v12s4WriteScript(t, "#!/bin/sh\nprintf ROTATED-GIT-MARKER\n")
	if _, err := toolregistry.Enroll("git", rotated); err != nil {
		t.Fatal(err)
	}
	reloaded, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	freshHandle, err := reloaded.ResolveHandle("git", "git", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatal(err)
	}
	if freshHandle.Identity.CanonicalPath != rotated {
		freshHandle.Close()
		t.Fatalf("test bug: rotation did not take effect, a fresh resolve got %q, want %q", freshHandle.Identity.CanonicalPath, rotated)
	}
	freshHandle.Close()

	// The already-frozen registry object must still resolve the ORIGINAL
	// git, never the rotated fake.
	_, out2, err := shell(context.Background(), dir, "git", registry)
	if err != nil {
		t.Fatalf("shell() after rotation (frozen registry): %v", err)
	}
	if strings.Contains(out2, "ROTATED-GIT-MARKER") {
		t.Fatal("shell() resolved a mid-transaction rotated git through the already-frozen registry object -- a run's own registry parameter must never observe a later on-disk enrollment change")
	}
}

// TestV12Case21BashRegistryRotatedAfterRunFreezeHasNoEffect is corpus 21:
// bash's sibling of case 20. bash is launched fd-backed (via
// Handle.CommandWith), so the property under test is even stronger than
// git's PATH-lookup case -- once shell() has opened the frozen registry's
// bash handle for one call, a later on-disk rotation cannot retroactively
// change what that already-open descriptor points at; this proves the
// weaker, more relevant property that the NEXT shell() call (still passed
// the same frozen *Registry) also keeps resolving the original bash.
func TestV12Case21BashRegistryRotatedAfterRunFreezeHasNoEffect(t *testing.T) {
	dir := t.TempDir()
	registry := v12s4FrozenRunEnvironment(t)

	handleBefore, err := registry.ResolveHandle("bash", "bash", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatal(err)
	}
	originalPath := handleBefore.Identity.CanonicalPath
	originalSHA := handleBefore.Identity.SHA256
	handleBefore.Close()

	rotated := v12s4WriteScript(t, "#!/bin/sh\nprintf ROTATED-BASH-MARKER\n")
	if _, err := toolregistry.Enroll("bash", rotated); err != nil {
		t.Fatal(err)
	}
	reloaded, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	freshHandle, err := reloaded.ResolveHandle("bash", "bash", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatal(err)
	}
	if freshHandle.Identity.CanonicalPath != rotated {
		freshHandle.Close()
		t.Fatalf("test bug: rotation did not take effect, a fresh resolve got %q, want %q", freshHandle.Identity.CanonicalPath, rotated)
	}
	freshHandle.Close()

	// The already-frozen registry object must still resolve the ORIGINAL
	// bash identity.
	handleAfter, err := registry.ResolveHandle("bash", "bash", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatal(err)
	}
	defer handleAfter.Close()
	if handleAfter.Identity.CanonicalPath != originalPath || handleAfter.Identity.SHA256 != originalSHA {
		t.Fatalf("frozen registry resolved a rotated bash identity (path=%q sha=%q), want the original pinned identity (path=%q sha=%q)", handleAfter.Identity.CanonicalPath, handleAfter.Identity.SHA256, originalPath, originalSHA)
	}

	// And prove shell() itself, given the frozen registry, still launches
	// end to end (the interpreter that actually runs is bash's held fd, not
	// the rotated pathname).
	code, out, err := shell(context.Background(), dir, "echo ok", registry)
	if err != nil || code != 0 || strings.TrimSpace(out) != "ok" {
		t.Fatalf("shell() with frozen registry after bash rotation: code=%d out=%q err=%v", code, out, err)
	}
}

// TestV12Case22ShellRefusesToRunWithoutAFrozenRegistry is corpus 22
// ("undeclared shell helper changes"): a caller that forgets to thread the
// run's frozen registry through -- the shape an accidental "undeclared
// helper" bug or an unreviewed new call site would take -- must fail
// closed, never silently fall back to reloading the trusted-tool registry
// itself (which would reintroduce the exact per-call reload window P0-6
// closed).
func TestV12Case22ShellRefusesToRunWithoutAFrozenRegistry(t *testing.T) {
	dir := t.TempDir()
	code, out, err := shell(context.Background(), dir, "git status", nil)
	if err == nil {
		t.Fatalf("shell() with a nil registry succeeded (code=%d out=%q), want a closed failure -- it must never fall back to an ambient/self-loaded registry", code, out)
	}
	if !strings.Contains(err.Error(), "not frozen") {
		t.Fatalf("shell() with a nil registry failed for the wrong reason: %v", err)
	}
}

// TestV12Case23ShellCommandStringCannotResolveAmbientTools is corpus 23:
// the git-porcelain command string shell() runs must not be able to reach
// any ambient-PATH tool beyond the sealed git+bash directories it already
// resolved and verified -- not even one this host's real environment
// genuinely provides (sed, in this case: present in the test process's own
// ambient PATH, but absent from shell()'s private launch PATH).
func TestV12Case23ShellCommandStringCannotResolveAmbientTools(t *testing.T) {
	dir := t.TempDir()
	registry := v12s4FrozenRunEnvironment(t)

	code, out, err := shell(context.Background(), dir, "sed --version", registry)
	if err == nil && code == 0 {
		t.Fatalf("shell() resolved \"sed\" through its private launch PATH (out=%q) -- the command string must only ever be able to resolve the declared git+bash controller tools, never an ambient tool merely because this host's real PATH happens to provide it", out)
	}
	if !strings.Contains(out, "not found") && !strings.Contains(out, "No such file") {
		t.Fatalf("shell() failed for an unexpected reason (want a PATH-lookup failure): out=%q err=%v", out, err)
	}
}
