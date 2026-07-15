//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/attest"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/observability"
)

// TestAttack6BackendReplacementBetweenHashAndLaunchIsDetected is report
// P0-6 / §9 attack 6: the runtime hashes a resolved backend path, then
// separately asks the OS to execute that path -- a classic TOCTOU window.
// This test swaps the file at the resolved path for a different
// (differently-behaving) executable in the instant between resolution and
// launch. Fixed by S3: one immutable BackendExecutionHandle carrying an
// already-open file descriptor / device+inode, launched via
// /proc/self/fd/<n> (or an immediate re-stat+re-hash reject) so a swap in
// that window is either impossible or caught.
//
// The swap must land AFTER resolution but BEFORE launch to actually
// exercise the TOCTOU window -- swapping before the run even starts just
// configures a malicious-from-the-start backend, which identity/launch
// binding cannot and need not catch (that's attestation/sandboxing's job,
// not this fix's). This test synchronizes on the run's disposable worktree
// appearing under home/worktrees: resolution (agents.ResolveHandle, which
// hashes the executable) always completes before runner.Prepare creates
// that worktree, and substantial additional work -- policy gate, spend/quota
// reservation, canary write, fingerprinting, prompt compilation -- still
// separates worktree creation from the actual backend launch, giving a
// background swap ample real time to land inside the window without a
// precisely-tuned sleep.
func TestAttack6BackendReplacementBetweenHashAndLaunchIsDetected(t *testing.T) {
	root := fixtureRepo(t)
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")

	honest := "#!/bin/sh\nset -eu\n" + standardBackendBody("")
	if err := os.WriteFile(binPath, []byte(honest), 0755); err != nil {
		t.Fatal(err)
	}

	swapMarker := filepath.Join(t.TempDir(), "swapped-ran.txt")
	hostile := "#!/bin/sh\nset -eu\nprintf swapped > " + swapMarker + "\n" + standardBackendBody("")

	home := t.TempDir()
	worktreesDir := filepath.Join(home, "worktrees")
	swapped := make(chan struct{})
	go func() {
		defer close(swapped)
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if entries, _ := os.ReadDir(worktreesDir); len(entries) > 0 {
				break
			}
			time.Sleep(2 * time.Millisecond)
		}
		_ = os.WriteFile(binPath, []byte(hostile), 0755)
	}()

	c := baseContract(root)
	rec := runGoverned(t, home, binPath, c)
	<-swapped // the run has already finished; just confirm the swap goroutine is done
	if rec.Status == "APPROVED" {
		if _, err := os.Stat(swapMarker); err == nil {
			t.Fatal("swapped executable ran and was still APPROVED: launch identity did not match the hashed/attested executable")
		}
	}
}

// TestAttack7PathResolvedBinaryReplacedBetweenRuns is report P0-6 / §9
// attack 7: the same bare backend name (e.g. "pi") resolves through PATH
// differently across two runs because PATH's target changed between them
// -- replay/identity must notice, not silently accept whatever PATH
// currently resolves to.
func TestAttack7PathResolvedBinaryReplacedBetweenRuns(t *testing.T) {
	root := fixtureRepo(t)
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "claude")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\nset -eu\n"+standardBackendBody("")), 0755); err != nil {
		t.Fatal(err)
	}

	// This fixture must exercise replay identity, not transcript conformance:
	// both binaries emit valid, approving transcripts; the only trust-bearing
	// input that changes is the PATH-resolved executable's content hash. Use a
	// bare backend name plus one GOV_HOME so the second run would replay the
	// first approval if executable identity were not part of the replay key.
	t.Setenv("PATH", binDir+string(os.PathListSeparator)+os.Getenv("PATH"))
	home := t.TempDir()
	c := baseContract(root)
	first := runGoverned(t, home, "claude", c)
	if first.Status != "APPROVED" || first.Replayed {
		t.Fatalf("expected first run fresh APPROVED, got status=%s replayed=%v message=%s", first.Status, first.Replayed, first.Message)
	}

	// Replace the PATH-resolved binary's content before the replay-eligible
	// second run, while keeping the backend transcript valid.
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\nset -eu\n# different implementation hash, same valid transcript\n"+standardBackendBody("")), 0755); err != nil {
		t.Fatal(err)
	}
	second := runGoverned(t, home, "claude", c)
	if second.Replayed {
		t.Fatal("second run replayed the first approval after the PATH-resolved executable hash changed")
	}
	if second.Status != "APPROVED" {
		t.Fatalf("changed executable should force a fresh valid run, not rely on an adjacent failure; got status=%s message=%s", second.Status, second.Message)
	}
	if second.ID == first.ID {
		t.Fatalf("fresh run reused first run ID %s", first.ID)
	}
}

// TestAttack10FakeGitInjectedThroughPathIsRejected is report P0-5/P0-6 /
// §9 attack 10: a hostile `git` shadowing the real one earlier on PATH.
// Fixed jointly by S3 (canonical resolution, not a bare PATH lookup
// trusted at face value) and S4 (trusted-tool registry: `git` must resolve
// to a canonical, hashed, non-writable-parent path or the run refuses).
//
// A hostile binary that is itself self-owned with restrictive permissions
// (exactly what a legitimate install also looks like) cannot be told apart
// from a real one by hygiene checks alone — the only thing that actually
// distinguishes "PATH pointed somewhere new" from "this is the tool I
// already trust" is a prior trust decision to compare against. This
// fixture establishes that prior trust the way `gov doctor` does in real
// use (toolregistry.Pin, wired into doctor.checkGit on first successful
// resolution): it resolves and pins the REAL git before the attacker's
// PATH change, then asserts the hostile git injected afterward never
// actually runs — gitplumb/runtime's git-invoking helpers all resolve
// through this same pinned registry entry (see gitplumb.TrustedGitPath),
// so they keep using the pinned file regardless of what a later PATH
// prepend contains.
func TestAttack10FakeGitInjectedThroughPathIsRejected(t *testing.T) {
	root := fixtureRepo(t)

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	realGit, err := exec.LookPath("git")
	if err != nil {
		t.Fatal(err)
	}
	if canonical, everr := filepath.EvalSymlinks(realGit); everr == nil {
		realGit = canonical
	}
	if err := os.WriteFile(registryFile, []byte("tools:\n  - name: git\n    kind: trusted_controller\n    path: "+realGit+"\n"), 0644); err != nil {
		t.Fatal(err)
	}

	fakeGitMarker := filepath.Join(t.TempDir(), "fake-git-ran.txt")
	fakeGitDir := t.TempDir()
	fakeGit := filepath.Join(fakeGitDir, "git")
	if err := os.WriteFile(fakeGit, []byte("#!/bin/sh\nprintf ran > "+fakeGitMarker+"\nprintf 'fake git\\n' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeGitDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED using the registry-pinned real git despite a hostile git earlier on PATH, got status=%s message=%s", rec.Status, rec.Message)
	}
	if _, err := os.Stat(fakeGitMarker); !os.IsNotExist(err) {
		t.Fatal("hostile PATH-shadowing git executed instead of the registry-pinned real git")
	}
}

// TestAttack5FakeBackendBehavesSafelyOnlyDuringAttestation is report P0-3
// / §9 attack 5: a fake backend prints a plausible version, creates
// expected probe files, avoids forbidden probe files, emits conforming
// transcript events, and claims network operations were denied -- every
// declared/probe-observed capability comes back true -- then escapes to
// the host during the real run. Fixed by S5 (internal/enforce): only
// *externally enforced* capabilities (Landlock LSM filesystem confinement
// + a network namespace with no configured route, applied to the launched
// process from OUTSIDE it, independent of anything it claims about itself)
// may authorize a high-risk local run; self-reported probe behavior --
// even a stored attestation claiming every probe passed, exactly what this
// fixture plants -- is evidence, never proof, and no longer gates
// authorization (see containment.EnforcePolicy's externallyEnforced
// argument).
//
// The fixture goes one step further than "probes lied": it plants a fully
// passing attestation record for the exact executable that is about to
// run, then has that same executable attempt a host escape during the real
// run. If Session 5 had left the old probe-outcome gate in place, this is
// precisely the record that would have satisfied it. It doesn't -- the
// run is authorized on external enforcement alone (with or without this
// attestation on file), and the escape write itself must still fail: this
// is the "we asked it nicely" -> "the kernel said no" boundary the report
// names.
func TestAttack5FakeBackendBehavesSafelyOnlyDuringAttestation(t *testing.T) {
	root := fixtureRepo(t)
	home := t.TempDir()

	// escapeTarget lives entirely outside the governed worktree -- the host
	// file the report's fake Codex wrote to during the real run despite
	// every probe reporting success.
	escapeTarget := filepath.Join(t.TempDir(), "host-escape.txt")

	bin := fakeBackend(t, `if [ "${1:-}" = "--version" ]; then echo "claude-code fake 1.0"; exit 0; fi
`+standardBackendBody(`printf pwned > "`+escapeTarget+`" 2>/dev/null || true
`))

	t.Setenv("GOV_CLAUDE_BIN", bin)
	res, rerr := agents.ResolvePath(agentClaudeCodeForTest(t))
	if rerr != nil {
		t.Fatal(rerr)
	}
	cfg := config.Current()
	db, dberr := observability.Open(home)
	if dberr != nil {
		t.Fatal(dberr)
	}
	// Plant the lie: a stored attestation declaring every behavioral probe
	// for this EXACT executable/config passed -- SandboxProbe, ReadOnlyProbe,
	// NetworkProbe, TranscriptProbe, ApprovalProbe all true, matching report
	// attack 5's "attestation reported all of the following as successful."
	if err := attest.Store(db, attest.Attestation{
		ID: "attack5-perfect-lie", Backend: "claude-code", AdapterID: "claude-code", AdapterVersion: "claude-code-adapter-v1",
		RequestedExecutable: res.Requested, ResolvedExecutable: res.ResolvedPath,
		ExecutablePath: res.CanonicalPath, ExecutableFileIdentity: res.FileIdentity, ExecutableSHA256: res.SHA256,
		ModelID: "claude-code", AccountID: "default", ConfigHash: cfg.Hash(), BackendConfigHash: attest.EffectiveBackendConfigHash(cfg, "claude-code"),
		ProbeSuiteVersion: attest.ProbeSuiteVersion,
		SupportedFlags:    true, SandboxProbe: true, ReadOnlyProbe: true, NetworkProbe: true, TranscriptProbe: true, ApprovalProbe: true,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano), ExpiresAt: time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}); err != nil {
		t.Fatal(err)
	}
	db.Close()

	c := baseContract(root)
	c.RiskClass = "high" // exercises Session 5's external-enforcement gate

	// enforce.NewPlan re-execs the TRUSTED gov binary (os.Executable()) as
	// `gov __sandbox_exec` so Landlock is applied by code the launched
	// backend cannot substitute. This test drives RunWithAutoRepair directly
	// inside the `go test` binary, which doesn't understand that subcommand
	// -- point the re-exec at the real compiled CLI instead, exactly as a
	// production `gov run` would resolve itself.
	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	rec := runGoverned(t, home, bin, c)

	if _, statErr := os.Stat(escapeTarget); !os.IsNotExist(statErr) {
		t.Fatal("fake backend escaped the workspace and wrote a host file despite a planted attestation claiming every probe passed -- externally enforced containment did not block it")
	}
	if rec.Status == "APPROVED" {
		if _, statErr := os.Stat(escapeTarget); statErr == nil {
			t.Fatal("run was APPROVED with a host escape file present")
		}
	}
}

// agentClaudeCodeForTest builds the same Agent instance a real run resolves,
// so this fixture's planted attestation binds to the exact resolution the
// real run will perform (same canonical path/hash/file-identity lookup keys
// attest.Current matches on).
func agentClaudeCodeForTest(t *testing.T) agents.Agent {
	t.Helper()
	agent, err := agents.New("claude-code")
	if err != nil {
		t.Fatal(err)
	}
	return agent
}

// TestAttack11MutableDockerTagChangesBeforeReplay is report P1-1 / §9
// attack 11: replay/identity binds to a mutable image tag string; the tag
// is repointed at a different image digest between the attested run and
// replay. Fixed by S3: runner.ResolveImageIdentity resolves the image's
// content-addressed ID before every run, and computeExecutionIdentity folds
// it into the replay key, so a retagged reference never matches the prior
// approval's identity hash even though the contract's configured "image:"
// string never changed.
func TestAttack11MutableDockerTagChangesBeforeReplay(t *testing.T) {
	requireDockerRedteam(t)
	setUpDockerHostFallback(t)

	tag := "gov-redteam-attack11:latest"
	altTag := "gov-redteam-attack11-alt:latest"
	dockerBuildFakeBackendImage(t, tag, dockerFakeBackendScript)
	dockerBuildFakeBackendImage(t, altTag, "#!/bin/sh\nset -eu\n"+dockerFakeBackendScript)
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", tag, altTag).Run() })

	root := fixtureRepo(t)
	home := t.TempDir()
	c := dockerContract(root, tag)

	first := runGovernedDocker(t, home, c)
	if first.Status != "APPROVED" {
		t.Fatalf("expected first docker run APPROVED, got status=%s message=%s", first.Status, first.Message)
	}
	if first.Replayed {
		t.Fatal("first run must not itself be a replay")
	}

	// Repoint the EXACT SAME tag the contract already declares at a
	// different image -- the contract's "image:" string is byte-for-byte
	// unchanged.
	if out, err := exec.Command("docker", "tag", altTag, tag).CombinedOutput(); err != nil {
		t.Fatalf("docker tag (retag %s -> %s): %v: %s", tag, altTag, err, out)
	}

	second := runGovernedDocker(t, home, c)
	if second.Replayed {
		t.Fatal("second run replayed the first run's approval after its image tag was repointed at a different image -- identity did not bind to the resolved image ID")
	}
}

// TestAttack12InContainerBackendDiffersFromHostAttestedBinary is report
// P1-1 / §9 attack 12: Governator attests the host-side backend CLI while
// Docker actually runs a different binary already baked into the image.
// Fixed by S3: resolve and record the in-container image identity
// independently of whatever the host CLI reports. This test holds the
// HOST-side resolution completely constant across both runs (same
// GOV_CLAUDE_BIN placeholder, same host file, same hash throughout) and
// changes only which image the container actually runs -- proving the
// overall execution identity does NOT rely on host CLI attestation to
// detect the swap.
func TestAttack12InContainerBackendDiffersFromHostAttestedBinary(t *testing.T) {
	requireDockerRedteam(t)
	setUpDockerHostFallback(t)

	imageA := "gov-redteam-attack12-a:latest"
	imageB := "gov-redteam-attack12-b:latest"
	dockerBuildFakeBackendImage(t, imageA, dockerFakeBackendScript)
	dockerBuildFakeBackendImage(t, imageB, "#!/bin/sh\nset -eu\n"+dockerFakeBackendScript)
	t.Cleanup(func() { _ = exec.Command("docker", "rmi", imageA, imageB).Run() })

	root := fixtureRepo(t)
	home := t.TempDir()

	first := runGovernedDocker(t, home, dockerContract(root, imageA))
	if first.Status != "APPROVED" {
		t.Fatalf("expected first docker run (image A) APPROVED, got status=%s message=%s", first.Status, first.Message)
	}

	// The contract now names a DIFFERENT image outright (imageB) -- the
	// host-side backend resolution (GOV_CLAUDE_BIN="claude", the same
	// placeholder script on the same PATH) is completely unchanged between
	// these two runs.
	second := runGovernedDocker(t, home, dockerContract(root, imageB))
	if second.Replayed {
		t.Fatal("second run replayed the first run's approval despite running a different in-container image -- identity was bound to the unchanging host CLI instead of the actual in-container reality")
	}
}
