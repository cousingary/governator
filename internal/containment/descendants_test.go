package containment

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/toolregistry"
)

// testContainmentEnvironment resolves a ContainmentEnvironment against a
// fresh, isolated tool registry (GOV_TOOLREGISTRY_FILE pointed at a temp
// file) so tests never depend on -- or pollute -- the ambient
// ~/.governator/tools.yaml. Mirrors production's exactly-once-per-run
// resolution (buildRunEnvironment -> ResolveEnvironment). Each named tool is
// enrolled best-effort: silently skipped (not the whole test) when it is not
// on this host's PATH, so a general test exercises whatever primitive the
// host actually supports -- including cgroup-direct/degraded when neither is
// available -- exactly as NewScope's own fallback chain intends.
func testContainmentEnvironment(t *testing.T, enroll ...string) ContainmentEnvironment {
	t.Helper()
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	for _, name := range enroll {
		path, err := exec.LookPath(name)
		if err != nil {
			continue
		}
		if _, err := toolregistry.Enroll(name, path); err != nil {
			t.Fatalf("enroll %s: %v", name, err)
		}
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatalf("load tool registry: %v", err)
	}
	env, err := ResolveEnvironment(registry)
	if err != nil {
		t.Fatalf("ResolveEnvironment: %v", err)
	}
	t.Cleanup(func() { _ = env.Close() })
	return env
}

// testContainmentEnvironmentRequiring is testContainmentEnvironment, but
// skips the whole test (not just enrollment) when any named tool is not on
// PATH -- for tests that specifically exercise a real, held primitive
// handle and have nothing to prove without one.
func testContainmentEnvironmentRequiring(t *testing.T, require ...string) ContainmentEnvironment {
	t.Helper()
	for _, name := range require {
		if _, err := exec.LookPath(name); err != nil {
			t.Skipf("%s not available on this host: %v", name, err)
		}
	}
	return testContainmentEnvironment(t, require...)
}

// TestScopeKillsDetachedSetsidDescendant is the primitive-level regression
// for report P0-4 / §9 attack 8: a setsid'd, double-forked grandchild that
// outlives its parent's own exit must not survive Extinguish, regardless of
// which method NewScope selected for this host.
func TestScopeKillsDetachedSetsidDescendant(t *testing.T) {
	dir := t.TempDir()
	transcriptDir := t.TempDir() // deliberately outside dir -- mirrors runtime.go's transcripts/ living outside the worktree
	marker := filepath.Join(dir, "escaped.txt")

	env := testContainmentEnvironment(t, "systemd-run", "unshare")
	scope, err := NewScope("containment-unit-test-"+t.Name(), false, env)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	t.Logf("scope method: %s", scope.Method())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	script := "#!/bin/sh\nset -eu\nsetsid sh -c 'sleep 2; printf leak > " + marker + "' < /dev/null > /dev/null 2>&1 &\nprintf started\n"
	bin := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := scope.Command(ctx, bin, nil, dir)
	out, err := os.CreateTemp(transcriptDir, "out")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	scope.Started(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	proof, err := scope.Extinguish(ctx, 5*time.Second, dir)
	if err != nil {
		t.Fatalf("Extinguish: %v (proof=%+v)", err, proof)
	}
	if proof.Degraded {
		t.Fatalf("scope degraded to bare process group: %s", proof.Note)
	}
	if !proof.Killed || !proof.WorkspaceFDScanClean {
		t.Fatalf("incomplete extinction proof: %+v", proof)
	}

	// Give the detached child every chance to win the race; Extinguish
	// having returned nil must mean it already lost.
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("detached descendant survived Extinguish and wrote %s: err=%v", marker, err)
	}
}

// TestScopeExtinguishNoopWhenNothingStarted covers the agentTimeout<=0 path
// in runtime.go: a Scope that never launched anything must still produce a
// clean Proof instead of erroring.
func TestScopeExtinguishNoopWhenNothingStarted(t *testing.T) {
	env := testContainmentEnvironment(t, "systemd-run", "unshare")
	scope, err := NewScope("containment-unit-test-noop", false, env)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	proof, err := scope.Extinguish(context.Background(), 2*time.Second, t.TempDir())
	if err != nil {
		t.Fatalf("Extinguish on never-started scope: %v", err)
	}
	if !proof.Frozen || !proof.Killed || !proof.WorkspaceFDScanClean {
		t.Fatalf("expected vacuous success, got %+v", proof)
	}
}

// TestScopeCommandLaunchesThroughSealedCopyNeverPathname is rc4 Session 2
// (Sol10 P0-2): Command used to hand exec.CommandContext the Scope's own
// resolved canonical path (s.primitivePath) for these two methods -- a
// pathname re-resolved by the kernel at every exec, so a same-uid process
// could replace the file between NewScope's verification and this launch
// and the replacement, not the verified binary, would become responsible
// for establishing containment. Command now launches exclusively through a
// freshly sealed, re-verified private copy of s.primitiveHandle's held
// bytes (see Command's doc comment for why a sealed copy, not an fd-argv
// launch): this test pins a real verified binary into a Handle (mirroring
// production's ResolveEnvironment), then REPLACES the file at that same
// enrolled path -- the same-uid tamper the report describes -- and proves
// Command's argv0 is a distinct sealed-copy path (never the now-tampered
// enrolled pathname) whose actual bytes are still the ORIGINAL verified
// content, not the replacement, for both primitive-backed methods.
func TestScopeCommandLaunchesThroughSealedCopyNeverPathname(t *testing.T) {
	for _, method := range []ScopeMethod{ScopeSystemdUserScope, ScopePIDNamespace} {
		t.Run(string(method), func(t *testing.T) {
			t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
			pinned := filepath.Join(t.TempDir(), "primitive-binary")
			const original = "#!/bin/sh\nprintf original\n"
			if err := os.WriteFile(pinned, []byte(original), 0755); err != nil {
				t.Fatal(err)
			}
			toolName := "systemd-run"
			if method == ScopePIDNamespace {
				toolName = "unshare"
			}
			if _, err := toolregistry.Enroll(toolName, pinned); err != nil {
				t.Fatalf("enroll %s: %v", toolName, err)
			}
			registry, err := toolregistry.Load()
			if err != nil {
				t.Fatal(err)
			}
			handle, err := registry.ResolveHandle(toolName, toolName, toolregistry.KindTrustedController)
			if err != nil {
				t.Fatalf("ResolveHandle: %v", err)
			}
			t.Cleanup(func() { _ = handle.Close() })

			// Same-uid tamper: replace the file at the enrolled path AFTER the
			// handle above already holds it open -- via rename, so a NEW
			// inode lands at pinned (an in-place truncate+overwrite would
			// mutate the original inode's bytes, which the held fd would
			// legitimately see too; that is not the TOCTOU this primitive
			// defends against). A pathname-based launch would now run this
			// replacement instead.
			const replacement = "#!/bin/sh\nprintf replacement\n"
			replacementPath := pinned + ".replacement"
			if err := os.WriteFile(replacementPath, []byte(replacement), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(replacementPath, pinned); err != nil {
				t.Fatal(err)
			}

			s := &Scope{method: method, runID: "unit-test", unitName: "unit-test-unit", primitiveHandle: handle}
			cmd := s.Command(context.Background(), "some-backend", []string{"--flag"}, t.TempDir())
			t.Cleanup(func() {
				if s.sealedPrimitive != nil {
					_ = s.sealedPrimitive.Close()
				}
			})
			if cmd.Path == "" || cmd.Path == pinned || strings.Contains(cmd.Path, "nonexistent") {
				t.Fatalf("Command built argv0=%q for method %s, want a distinct sealed-copy path, never the enrolled pathname or a fail-closed sentinel", cmd.Path, method)
			}
			got, err := os.ReadFile(cmd.Path)
			if err != nil {
				t.Fatalf("read sealed primitive copy %q: %v", cmd.Path, err)
			}
			if string(got) != original {
				t.Fatalf("sealed primitive copy at %q reads %q, want the original verified bytes %q -- the same-uid replacement of the enrolled path must have no effect on what actually executes", cmd.Path, got, original)
			}
		})
	}
}

// TestV11Case31CommandWithLaunchesUnshareThroughDescriptorNeverPathname is
// Sol11 rc5 Session 4 corpus case 27 (agents/governator-sol-upgrade11.md
// P0-5): "replace unshare after final Verify and before exec". Mirrors
// TestScopeCommandLaunchesThroughSealedCopyNeverPathname's exact same-uid
// tamper (pin a real verified binary into a Handle, then REPLACE the file
// at that same enrolled path via rename), but exercises CommandWith --
// which launches ScopePIDNamespace's primitive through
// s.primitiveHandle's own held, already-verified descriptor
// (/proc/self/fd/<n>, via a shared toolregistry.FDAllocator) instead of a
// freshly sealed, re-verified private copy referenced by a real pathname.
// The retained descriptor CommandWith registers into alloc is read back
// directly here (rewound first) to prove it still holds the ORIGINAL
// verified bytes, immune to the pathname replacement -- the same
// evidentiary standard the sealed-copy sibling test uses (reading the
// launch target's bytes without actually starting a process).
func TestV11Case31CommandWithLaunchesUnshareThroughDescriptorNeverPathname(t *testing.T) {
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	pinned := filepath.Join(t.TempDir(), "primitive-binary")
	const original = "#!/bin/sh\nprintf original\n"
	if err := os.WriteFile(pinned, []byte(original), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("unshare", pinned); err != nil {
		t.Fatalf("enroll unshare: %v", err)
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	handle, err := registry.ResolveHandle("unshare", "unshare", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	const replacement = "#!/bin/sh\nprintf replacement\n"
	replacementPath := pinned + ".replacement"
	if err := os.WriteFile(replacementPath, []byte(replacement), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacementPath, pinned); err != nil {
		t.Fatal(err)
	}

	s := &Scope{method: ScopePIDNamespace, runID: "unit-test", primitiveHandle: handle}
	alloc := &toolregistry.FDAllocator{}
	cmd := s.CommandWith(context.Background(), alloc, "some-backend", []string{"--flag"}, t.TempDir())
	if cmd.Path == "" || cmd.Path == pinned || strings.Contains(cmd.Path, "nonexistent") || !strings.HasPrefix(cmd.Path, "/proc/self/fd/") {
		t.Fatalf("CommandWith built argv0=%q, want a /proc/self/fd/<n> descriptor path, never the enrolled pathname or a fail-closed sentinel", cmd.Path)
	}
	files := alloc.Files()
	if len(files) == 0 {
		t.Fatal("CommandWith registered no descriptor with the shared allocator")
	}
	f := files[len(files)-1]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read retained primitive descriptor: %v", err)
	}
	if string(got) != original {
		t.Fatalf("retained primitive descriptor reads %q, want the original verified bytes %q -- the same-uid replacement of the enrolled path must have no effect on what would actually execute", got, original)
	}
}

// TestV11Case32CommandWithLaunchesSystemdRunThroughDescriptorNeverPathname
// is corpus case 28: "replace systemd-run after final Verify and before
// exec". Identical to case 31 above for ScopeSystemdUserScope's own
// primitive instead of ScopePIDNamespace's.
func TestV11Case32CommandWithLaunchesSystemdRunThroughDescriptorNeverPathname(t *testing.T) {
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	pinned := filepath.Join(t.TempDir(), "primitive-binary")
	const original = "#!/bin/sh\nprintf original\n"
	if err := os.WriteFile(pinned, []byte(original), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("systemd-run", pinned); err != nil {
		t.Fatalf("enroll systemd-run: %v", err)
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	handle, err := registry.ResolveHandle("systemd-run", "systemd-run", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatalf("ResolveHandle: %v", err)
	}
	t.Cleanup(func() { _ = handle.Close() })

	const replacement = "#!/bin/sh\nprintf replacement\n"
	replacementPath := pinned + ".replacement"
	if err := os.WriteFile(replacementPath, []byte(replacement), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacementPath, pinned); err != nil {
		t.Fatal(err)
	}

	s := &Scope{method: ScopeSystemdUserScope, runID: "unit-test", unitName: "unit-test-unit", primitiveHandle: handle}
	alloc := &toolregistry.FDAllocator{}
	cmd := s.CommandWith(context.Background(), alloc, "some-backend", []string{"--flag"}, t.TempDir())
	if cmd.Path == "" || cmd.Path == pinned || strings.Contains(cmd.Path, "nonexistent") || !strings.HasPrefix(cmd.Path, "/proc/self/fd/") {
		t.Fatalf("CommandWith built argv0=%q, want a /proc/self/fd/<n> descriptor path, never the enrolled pathname or a fail-closed sentinel", cmd.Path)
	}
	files := alloc.Files()
	if len(files) == 0 {
		t.Fatal("CommandWith registered no descriptor with the shared allocator")
	}
	f := files[len(files)-1]
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(f)
	if err != nil {
		t.Fatalf("read retained primitive descriptor: %v", err)
	}
	if string(got) != original {
		t.Fatalf("retained primitive descriptor reads %q, want the original verified bytes %q -- the same-uid replacement of the enrolled path must have no effect on what would actually execute", got, original)
	}
}

func TestSystemdScopeRejectsUnconfirmedObservedCgroup(t *testing.T) {
	if _, err := os.Stat("/proc/self/cgroup"); err != nil {
		t.Skipf("no proc cgroup view: %v", err)
	}
	s := &Scope{method: ScopeSystemdUserScope, runID: "unit-test", unitName: "governator-unit-that-must-not-match"}
	s.resolveCgroupFromPID(os.Getpid())
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.cgroupPath != "" {
		t.Fatalf("unconfirmed systemd unit retained fallback cgroup %q", s.cgroupPath)
	}
	if s.resolveErr == nil {
		t.Fatal("expected resolveErr for unconfirmed generated systemd unit")
	}
}

// --- rc4 Session 2 (Sol10 P0-2) mandatory red-team corpus, report cases 9-14 ---
//
// agents/governator-sol-upgrade10.md "P0-2: Descendant-containment
// primitives remain pathname-executed", agents/governator-sol-upgrade10-rc4-plan.md
// Session 2. Cases 9-11 prove the fd-held-descriptor launch and the
// once-per-run ContainmentEnvironment resolution survive a same-uid tamper
// or a live registry mutation occurring AFTER the environment (and, in
// production, the run's replay identity) was already frozen -- without ever
// needing to actually execute the primitive, so they run on every host.
// Case 12 proves the leak Sol found (a handle opened fresh on every failed
// scope-selection attempt, never closed on the early-return paths) is gone
// now that resolution happens once, not per attempt. Cases 13-14 are the
// real, live end-to-end launches; case 13 is host-gated (a live systemd
// --user bus is not guaranteed present, e.g. this project's own WSL dev
// host) and skips via the manifest's documented conditional/allowed_skip
// mechanism (predicate has_systemd_user) rather than failing the release on
// an environment that structurally cannot provide it.

// v10s2EnrollTamperableScript enrolls name (the tool a ContainmentEnvironment
// resolution will pick up) pointing at a fresh script holding content, and
// returns its path for the caller to tamper with later via
// v10s2TamperViaRename.
func v10s2EnrollTamperableScript(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll(name, path); err != nil {
		t.Fatalf("enroll %s: %v", name, err)
	}
	return path
}

// v10s2TamperViaRename replaces path with content by writing a new file and
// renaming it into place -- a NEW inode lands at the directory entry, the
// same-uid attack a held file descriptor actually defends against (unlike an
// in-place truncate+overwrite of the ORIGINAL inode's bytes, which a held fd
// would legitimately observe too -- see
// TestScopeCommandLaunchesThroughSealedCopyNeverPathname).
func v10s2TamperViaRename(t *testing.T, path, content string) {
	t.Helper()
	replacement := path + ".replacement"
	if err := os.WriteFile(replacement, []byte(content), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
}

// v10s2AssertLaunchesOriginalBytes builds s.Command and asserts it launches
// through a sealed private copy (never a mutable pathname) whose content is
// exactly original -- proving a same-uid tamper or registry mutation that
// happened after the Scope's underlying handle was resolved has no effect
// on what actually executes.
func v10s2AssertLaunchesOriginalBytes(t *testing.T, s *Scope, original string) {
	t.Helper()
	cmd := s.Command(context.Background(), "some-backend", []string{"--flag"}, t.TempDir())
	t.Cleanup(func() {
		if s.sealedPrimitive != nil {
			_ = s.sealedPrimitive.Close()
		}
	})
	if cmd.Path == "" || strings.Contains(cmd.Path, "nonexistent") {
		t.Fatalf("Command failed to seal a primitive copy: argv0=%q", cmd.Path)
	}
	got, err := os.ReadFile(cmd.Path)
	if err != nil {
		t.Fatalf("read sealed primitive copy %q: %v", cmd.Path, err)
	}
	if string(got) != original {
		t.Fatalf("sealed primitive copy at %q reads %q, want the original verified bytes %q -- a same-uid tamper/registry mutation after resolution must have no effect on what executes", cmd.Path, got, original)
	}
}

// TestV10Case9UnshareReplacedAfterFrozenEnvironmentConstructionHasNoEffect is
// report case 9.
func TestV10Case9UnshareReplacedAfterFrozenEnvironmentConstructionHasNoEffect(t *testing.T) {
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	const original = "#!/bin/sh\nprintf original-unshare\n"
	path := v10s2EnrollTamperableScript(t, "unshare", original)
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	// The frozen environment: resolved exactly once, mirroring
	// buildRunEnvironment's exactly-once call before replay identity is
	// computed.
	env, err := ResolveEnvironment(registry)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	if env.Unshare == nil {
		t.Fatal("expected unshare to resolve into the frozen environment")
	}

	v10s2TamperViaRename(t, path, "#!/bin/sh\nprintf REPLACED\n")

	s, err := newPIDNamespaceScope("v10-case9", env.Unshare)
	if err != nil {
		t.Fatalf("newPIDNamespaceScope: %v", err)
	}
	v10s2AssertLaunchesOriginalBytes(t, s, original)
}

// TestV10Case10SystemdRunReplacedAfterFrozenEnvironmentConstructionHasNoEffect
// is report case 10. newSystemdUserScope's own live-availability probe
// (/run/systemd/system + a live user bus) is a host-capability constraint
// this test does not depend on -- it constructs the Scope directly in the
// exact shape newSystemdUserScope itself builds on success, so the property
// under test (a same-uid tamper after the environment holds the handle open
// has no effect on what launches) is verified independent of that
// constraint. Case 13 covers the real, live, host-gated
// construction+launch path end to end.
func TestV10Case10SystemdRunReplacedAfterFrozenEnvironmentConstructionHasNoEffect(t *testing.T) {
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	const original = "#!/bin/sh\nprintf original-systemd-run\n"
	path := v10s2EnrollTamperableScript(t, "systemd-run", original)
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ResolveEnvironment(registry)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	if env.SystemdRun == nil {
		t.Fatal("expected systemd-run to resolve into the frozen environment")
	}

	v10s2TamperViaRename(t, path, "#!/bin/sh\nprintf REPLACED\n")

	s := &Scope{method: ScopeSystemdUserScope, runID: "v10-case10", unitName: "v10-case10-unit", primitiveHandle: env.SystemdRun}
	v10s2AssertLaunchesOriginalBytes(t, s, original)
}

// TestV10Case11ContainmentRegistryMutatedAfterEnvironmentResolvedHasNoEffect
// is report case 11 ("mutate the containment registry after replay identity
// is calculated"). ResolveEnvironment marks the moment a run's replay
// identity would be computed against these primitives in production
// (internal/runtime.buildRunEnvironment); the registry file is mutated on
// disk afterward (re-enrolling unshare to a different binary entirely) and
// proven to have genuinely changed via a fresh, independent Load+Resolve --
// then the ALREADY-frozen env.Unshare must still launch the original
// binary. Before this session, NewScope reloaded the registry itself on
// every call, so a live-running stage could pick up exactly this kind of
// mutation mid-run, diverging from the identity already computed.
func TestV10Case11ContainmentRegistryMutatedAfterEnvironmentResolvedHasNoEffect(t *testing.T) {
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	const original = "#!/bin/sh\nprintf original-unshare\n"
	v10s2EnrollTamperableScript(t, "unshare", original)
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ResolveEnvironment(registry)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	if env.Unshare == nil {
		t.Fatal("expected unshare to resolve into the frozen environment")
	}

	const different = "#!/bin/sh\nprintf DIFFERENT-BINARY\n"
	differentPath := filepath.Join(t.TempDir(), "different-unshare")
	if err := os.WriteFile(differentPath, []byte(different), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll("unshare", differentPath); err != nil {
		t.Fatal(err)
	}
	// Prove the mutation genuinely took effect on disk, independent of env.
	reloaded, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	freshHandle, err := reloaded.ResolveHandle("unshare", "unshare", toolregistry.KindTrustedController)
	if err != nil {
		t.Fatal(err)
	}
	defer freshHandle.Close()
	if freshHandle.Identity.CanonicalPath != differentPath {
		t.Fatalf("test bug: registry mutation did not take effect, a fresh resolve got %q", freshHandle.Identity.CanonicalPath)
	}

	s, err := newPIDNamespaceScope("v10-case11", env.Unshare)
	if err != nil {
		t.Fatalf("newPIDNamespaceScope: %v", err)
	}
	v10s2AssertLaunchesOriginalBytes(t, s, original)
}

// v10s2CountOpenFDs counts this process's own open file descriptors via
// /proc/self/fd.
func v10s2CountOpenFDs(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Skipf("cannot read /proc/self/fd on this host: %v", err)
	}
	return len(entries)
}

// TestV10Case12ScopeSelectionFailureLeaksZeroDescriptors is report case 12.
// Before this session, newSystemdUserScope resolved a fresh handle via
// toolregistry.Load()+ResolveHandle on every call and returned early --
// without closing it -- on both the /run/systemd/system and live user-bus
// checks; on a host without a usable systemd user manager, every single
// stage-selection attempt for the whole run leaked one fd. The fix
// (resolution happens exactly once, in ResolveEnvironment; newSystemdUserScope
// only ever borrows the already-open handle and never owns closing it) makes
// this leak structurally impossible: repeated failed attempts here must
// leak exactly zero descriptors.
//
// Sol12 rc5 Session 2 (P0-1): this case used to skip whenever a live systemd
// --user bus was present, making it mutually exclusive with case 13 (the real
// live-systemd launch) on any single host -- so a correct single-host
// zero-skip red-team run was structurally impossible. The failure is now
// injected deterministically through the ScopeSelectionForceUnavailableForTesting
// seam, so the absent-systemd fallback's zero-descriptor invariant runs and
// passes on EVERY host, including this systemd-enabled dev box. Case 13 stays
// the real live-systemd acceptance test (host-gated, required-in-attestation).
func TestV10Case12ScopeSelectionFailureLeaksZeroDescriptors(t *testing.T) {
	ScopeSelectionForceUnavailableForTesting.Store(true)
	t.Cleanup(func() { ScopeSelectionForceUnavailableForTesting.Store(false) })
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	v10s2EnrollTamperableScript(t, "systemd-run", "#!/bin/sh\nexit 0\n")
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ResolveEnvironment(registry)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	if env.SystemdRun == nil {
		t.Fatal("expected systemd-run to resolve into the frozen environment")
	}

	before := v10s2CountOpenFDs(t)
	for i := 0; i < 20; i++ {
		if _, err := newSystemdUserScope("v10-case12", env.SystemdRun); err == nil {
			t.Fatal("expected newSystemdUserScope to fail under the forced scope-selection failure")
		}
	}
	after := v10s2CountOpenFDs(t)
	if after > before {
		t.Fatalf("20 failed scope-selection attempts leaked descriptors: before=%d after=%d", before, after)
	}
}

// TestV10Case13RealSystemdUserScopeLaunchExecutesExactVerifiedTarget is
// report case 13: a genuinely real, live systemd --user scope launch, not
// just argv/ExtraFiles construction, executes exactly the verified target.
// Host-gated: a live systemd --user bus requires an active login session (or
// loginctl enable-linger), which this project's own WSL dev host does not
// have -- internal/redteam/manifest.yaml marks this case conditional with
// predicate has_systemd_user, matching this exact skip text, so a host that
// genuinely cannot provide it does not block a release.
func TestV10Case13RealSystemdUserScopeLaunchExecutesExactVerifiedTarget(t *testing.T) {
	systemdRunPath, err := exec.LookPath("systemd-run")
	if err != nil {
		t.Skip("systemd-run not available on this host")
	}
	if _, err := os.Stat("/run/systemd/system"); err != nil {
		t.Skip("systemd is not PID 1 on this host")
	}
	if _, err := os.Stat(fmt.Sprintf("/run/user/%d/bus", os.Getuid())); err != nil {
		t.Skip("no live systemd --user bus on this host")
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	if _, err := toolregistry.Enroll("systemd-run", systemdRunPath); err != nil {
		t.Fatal(err)
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ResolveEnvironment(registry)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	if env.SystemdRun == nil {
		t.Fatal("expected systemd-run to resolve into the frozen environment")
	}

	s, err := newSystemdUserScope("v10-case13-"+nonce(), env.SystemdRun)
	if err != nil {
		t.Skipf("no live systemd --user bus on this host: newSystemdUserScope probe failed: %v", err)
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "marker.txt")
	script := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf exact-verified-target > "+marker+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := s.Command(ctx, script, nil, dir)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	s.Started(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if _, err := s.Extinguish(ctx, 5*time.Second, dir); err != nil {
		t.Fatalf("Extinguish: %v", err)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(got) != "exact-verified-target" {
		t.Fatalf("marker = %q, want exact-verified-target -- the real launch must execute exactly the verified target", got)
	}
}

// TestV10Case14RealPIDNamespaceLaunchExecutesExactVerifiedTarget is report
// case 14: a genuinely real, live PID-namespace launch executes exactly the
// verified target.
func TestV10Case14RealPIDNamespaceLaunchExecutesExactVerifiedTarget(t *testing.T) {
	unsharePath, err := exec.LookPath("unshare")
	if err != nil {
		t.Skip("unshare not available on this host")
	}
	if out, err := exec.Command(unsharePath, "--pid", "--fork", "--mount-proc", "true").CombinedOutput(); err != nil {
		t.Skipf("PID namespaces not usable on this host: %v: %s", err, out)
	}
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(t.TempDir(), "tools.yaml"))
	if _, err := toolregistry.Enroll("unshare", unsharePath); err != nil {
		t.Fatal(err)
	}
	registry, err := toolregistry.Load()
	if err != nil {
		t.Fatal(err)
	}
	env, err := ResolveEnvironment(registry)
	if err != nil {
		t.Fatal(err)
	}
	defer env.Close()
	if env.Unshare == nil {
		t.Fatal("expected unshare to resolve into the frozen environment")
	}

	s, err := newPIDNamespaceScope("v10-case14-"+nonce(), env.Unshare)
	if err != nil {
		t.Fatalf("newPIDNamespaceScope: %v", err)
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "marker.txt")
	script := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nprintf exact-verified-target > "+marker+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := s.Command(ctx, script, nil, dir)
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start (pid namespace launch failed on this host): %v", err)
	}
	s.Started(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}
	if _, err := s.Extinguish(ctx, 5*time.Second, dir); err != nil {
		t.Fatalf("Extinguish: %v", err)
	}
	got, err := os.ReadFile(marker)
	if err != nil {
		t.Fatalf("read marker: %v", err)
	}
	if string(got) != "exact-verified-target" {
		t.Fatalf("marker = %q, want exact-verified-target", got)
	}
}
