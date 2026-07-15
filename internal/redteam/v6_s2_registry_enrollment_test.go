//go:build redteam

// v6_s2_registry_enrollment_test.go is the Sol redteam v6 Permanent
// Regression Corpus, cases 8-13, owned by Session 2 (Phase 2: controller-
// tool trust must be enrollment-based, never trust-on-first-use). See
// agents/governator-sol-upgrade6-plan.md Session 2 and
// agents/governator-sol-upgrade6.md P0-5/P0-6/P0-9/P0-10. Every test here is
// scaffolding only (Session 0): t.Skip(...) is the literal first statement,
// before any fixture construction.
package redteam

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/runtime"
	"github.com/cousingary/governator/internal/toolregistry"
)

func secureToolTempDir(t *testing.T) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".gov-redteam-tools-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}

func runGovernedS2(t *testing.T, home, bin string, c contracts.Contract) (runtime.RunRecord, error) {
	t.Helper()
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	return runtime.New().RunWithAutoRepair(context.Background(), c)
}

// TestV6Case8FakeBashFirstInPathOnFreshHomeIsRejected is corpus case 8
// (report P0-5). Unlike TestAttack26FakeBashInjectedThroughPathIsRejected
// (toolregistry_test.go), which pins the REAL bash before poisoning PATH
// (testing replacement-after-enrollment only), this attack uses a
// genuinely fresh GOV_HOME/GOV_TOOLREGISTRY_FILE -- no registry file is
// written at all -- and puts a hostile "bash" first on PATH from the very
// first resolution. The default registry entry for bash carries no path or
// SHA-256 (toolregistry.defaultEntries), so on first resolution Governator
// searches ambient PATH and accepts whatever passes ownership/mode checks:
// not cryptographic trust. Per the report, "a missing controller-tool
// identity blocks execution" -- the fix must refuse to run success.validators
// (which shell out through bash) at all rather than trust the first thing
// PATH resolves to.
func TestV6Case8FakeBashFirstInPathOnFreshHomeIsRejected(t *testing.T) {

	root := fixtureRepo(t)

	// Genuinely fresh: no registry file is ever written. Point
	// GOV_TOOLREGISTRY_FILE at a path that does not exist so
	// toolregistry.Load() falls back to nothing but the unpathed shipped
	// defaults -- the exact "fresh install" state the report's attack used.
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "does-not-exist.yaml"))

	fakeBashMarker := filepath.Join(t.TempDir(), "fake-bash-ran.txt")
	fakeBashDir := t.TempDir()
	fakeBash := filepath.Join(fakeBashDir, "bash")
	// Marker-and-fail-loudly shape (mirrors TestAttack26): if this ever
	// executes with Governator's authority, a successful run PROVES it ran;
	// exiting nonzero also means a run that somehow reached APPROVED could
	// not have gone through this fake at all.
	if err := os.WriteFile(fakeBash, []byte("#!/bin/sh\nprintf ran > "+fakeBashMarker+"\nprintf 'fake bash\\n' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBashDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))
	rec, _ := runGovernedS2(t, t.TempDir(), bin, c)

	if _, err := os.Stat(fakeBashMarker); !os.IsNotExist(err) {
		t.Fatal("hostile PATH-first bash executed with Governator's authority on a genuinely fresh install -- a missing controller-tool identity must block execution, not fall back to ambient PATH")
	}
	if rec.Status == "APPROVED" {
		t.Fatalf("run reached APPROVED without ever having a trusted, enrolled bash identity to run success.validators through (status=%s message=%s)", rec.Status, rec.Message)
	}
}

// TestV6Case9FakeGitFirstInPathOnFreshHomeIsRejected is corpus case 9
// (report P0-6): the same shape as case 8, for git. Unlike
// TestAttack10FakeGitInjectedThroughPathIsRejected (backend_identity_test.go),
// which also pre-pins the real git, this attack proves hostile FIRST
// resolution is rejected on a genuinely fresh home -- the fake git would
// (if trusted) run hash-object/write-tree/commit-tree/update-ref, meaning
// Git-tree sovereignty collapses if the Git implementation itself is
// attacker-supplied.
func TestV6Case9FakeGitFirstInPathOnFreshHomeIsRejected(t *testing.T) {

	root := fixtureRepo(t)
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "does-not-exist.yaml"))

	fakeGitMarker := filepath.Join(t.TempDir(), "fake-git-ran.txt")
	fakeGitDir := t.TempDir()
	fakeGit := filepath.Join(fakeGitDir, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\nprintf ran > "+fakeGitMarker+"\nprintf 'fake git\\n' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeGitDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))
	rec, _ := runGovernedS2(t, t.TempDir(), bin, c)

	if _, err := os.Stat(fakeGitMarker); !os.IsNotExist(err) {
		t.Fatal("hostile PATH-first git executed with Governator's authority on a genuinely fresh install -- Git-tree sovereignty requires the Git implementation itself to be trusted, not merely the tree operations run through it")
	}
	if rec.Status == "APPROVED" {
		t.Fatalf("run reached APPROVED without ever having a trusted, enrolled git identity to build/commit the approved tree with (status=%s message=%s)", rec.Status, rec.Message)
	}
}

// TestV6Case10PathPinnedToolReplacedWithDifferentContentIsRejected is
// corpus case 10 (report P0-9): toolregistry.Pin() records the path but
// (today) not a content hash bound to that pin -- the file at a pinned path
// can be swapped for different content after pinning, and Resolve happily
// verifies "the file at this path" rather than "the exact tool identity
// that was pinned." This test pins git the same way TestAttack10/
// TestAttack26 do, then overwrites the pinned path's file with different
// (hostile) content, and asserts resolution now fails closed instead of
// trusting whatever now lives at that path.
func TestV6Case10PathPinnedToolReplacedWithDifferentContentIsRejected(t *testing.T) {

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)

	pinnedPath := filepath.Join(secureToolTempDir(t), "git")
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	realGitBytes, err := os.ReadFile(realGit)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pinnedPath, realGitBytes, 0755); err != nil {
		t.Fatal(err)
	}
	if err := toolregistry.Pin("git", pinnedPath); err != nil {
		t.Fatal(err)
	}

	// Swap the pinned path's content for a different (hostile, always-fails)
	// executable AFTER pinning -- pinning must have bound to the content this
	// path held at pin time, not merely to the path string.
	hostile := "#!/bin/sh\nprintf 'swapped git\\n' >&2\nexit 1\n"
	if err := os.WriteFile(pinnedPath, []byte(hostile), 0755); err != nil {
		t.Fatal(err)
	}

	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	if _, rerr := registry.Resolve("git", "git"); rerr == nil {
		t.Fatal("registry resolved a path-pinned tool whose content was swapped after pinning -- pinning must bind to content identity, not merely a path string")
	}
}

// TestV6Case11RegistryEntryMissingSHA256IsRejected is corpus case 11
// (report P0-10): an operator-declared tools.yaml entry that carries a
// path but no sha256 field is currently accepted (SHA256 is optional and
// content-hash verification is simply skipped when unset). The report
// wants mandatory hash + absolute path -- an entry without a hash should
// be rejected, not silently trusted on path/owner/mode alone.
func TestV6Case11RegistryEntryMissingSHA256IsRejected(t *testing.T) {

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	someTool := filepath.Join(secureToolTempDir(t), "custom-controller-tool")
	if err := os.WriteFile(someTool, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	registryYAML := "tools:\n  - name: custom-controller-tool\n    kind: trusted_controller\n    path: " + someTool + "\n"
	if err := os.WriteFile(registryFile, []byte(registryYAML), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)

	if _, err := toolregistry.Load(); err == nil {
		t.Fatal("registry accepted a trusted_controller entry that declares a path but no sha256 -- a missing content hash must block execution, not fall back to trust-the-path")
	}
}

// TestV6Case12DuplicateTrustedToolRegistryNamesRejected is corpus case 12
// (report P0-10): a tools.yaml with two entries sharing the same name
// (different paths/hashes) is currently accepted with last-write-wins
// semantics (Load's `entries[e.Name] = e` loop silently overwrites). The
// report wants this rejected outright as an invalid registry, since an
// operator (or an attacker who can append to the file) cannot know which
// entry actually governs resolution.
func TestV6Case12DuplicateTrustedToolRegistryNamesRejected(t *testing.T) {

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	dupDir := secureToolTempDir(t)
	pathA := filepath.Join(dupDir, "git-a")
	pathB := filepath.Join(dupDir, "git-b")
	for _, p := range []string{pathA, pathB} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
			t.Fatal(err)
		}
	}
	registryYAML := "tools:\n" +
		"  - name: git\n    kind: trusted_controller\n    path: " + pathA + "\n" +
		"  - name: git\n    kind: trusted_controller\n    path: " + pathB + "\n"
	if err := os.WriteFile(registryFile, []byte(registryYAML), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)

	if _, err := toolregistry.Load(); err == nil {
		t.Fatal("toolregistry.Load() accepted a tools.yaml with duplicate tool names instead of rejecting it as an invalid registry")
	}
}

// TestV6Case13ConcurrentRegistryUpdatesDoNotLoseWrites is corpus case 13
// (report P0-10): Pin() does an unlocked read-modify-write of tools.yaml.
// The report wants a stable lock file, generation number + compare-and-
// swap, and temp-write+atomic-rename so concurrent updates never silently
// clobber each other. This test spins up several goroutines each pinning a
// uniquely named entry concurrently, then asserts every one of them
// actually landed in the final file -- a best-effort black-box concurrency
// check (not a precise lock-contention proof) matching the report's own
// framing.
func TestV6Case13ConcurrentRegistryUpdatesDoNotLoseWrites(t *testing.T) {

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)

	const n = 12
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			name := "concurrent-tool-" + string(rune('a'+i))
			toolPath := filepath.Join(secureToolTempDir(t), name)
			if werr := os.WriteFile(toolPath, []byte("#!/bin/sh\nexit 0\n"), 0755); werr != nil {
				errs[i] = werr
				return
			}
			errs[i] = toolregistry.Pin(name, toolPath)
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Pin goroutine %d failed: %v", i, err)
		}
	}

	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < n; i++ {
		name := "concurrent-tool-" + string(rune('a'+i))
		if _, ok := registry.Entry(name); !ok {
			t.Fatalf("entry %q lost under concurrent registry updates -- unlocked read-modify-write clobbered a concurrent writer's change", name)
		}
	}
}
