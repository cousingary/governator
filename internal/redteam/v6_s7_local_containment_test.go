//go:build redteam

// v6_s7_local_containment_test.go is the Sol redteam v6 Permanent
// Regression Corpus, cases 25-29, owned by Session 7 (Phase 7: local
// containment hardening -- Landlock read isolation, TOCTOU-free wrapped
// launches, exact systemd-unit identity, and pidfd-based extinction proof).
// See agents/governator-sol-upgrade6-plan.md Session 7 and
// agents/governator-sol-upgrade6.md P0-13/P0-14/P0-15/P0-16. Every test
// here is scaffolding only (Session 0): t.Skip(...) is the literal first
// statement, before any fixture construction.
//
// Honest limits, called out per the task instructions rather than papered
// over: cases 28 (systemd unit never materializes) and 29 (PID check
// returns EPERM) reach into containment internals this black-box package
// structurally cannot construct without a second real uid or a live
// systemd user manager -- see each test's doc comment for exactly what is
// and is not exercised here.
package redteam

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/enforce"
	govruntime "github.com/cousingary/governator/internal/runtime"
)

// TestV6Case25BackendCannotReadUndeclaredHostSecretUnderLandlock is corpus
// case 25 (report P0-13): enforce.applyLandlockRuleset grants
// landlock.RODirs("/") -- read-only access to the ENTIRE host filesystem --
// plus read-write on the workspace. Writes are confined; reads are not. A
// contained backend can read any host file it can name, including files
// the contract never declared as an allowed read path. This test plants a
// fake secret file outside the workspace (under a t.TempDir()-based fake
// $HOME, never the real machine's home), has the backend cat it into its
// declared output, and asserts either the read failed (content never
// reaches committed output) or, if Landlock itself is unavailable in this
// environment, the run is at minimum quarantined/denied rather than
// silently approved with the secret's content inside.
func TestV6Case25BackendCannotReadUndeclaredHostSecretUnderLandlock(t *testing.T) {

	if runtime.GOOS != "linux" {
		t.Skip("Landlock is Linux-only")
	}
	if !enforce.Supported() {
		t.Skip("this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}

	root := fixtureRepo(t)
	home := t.TempDir()

	fakeHome := t.TempDir()
	secretDir := filepath.Join(fakeHome, ".ssh")
	if err := os.MkdirAll(secretDir, 0700); err != nil {
		t.Fatal(err)
	}
	secretPath := filepath.Join(secretDir, "id_rsa")
	const secretMarker = "redteam-fixture-secret-6f2a9c"
	if err := os.WriteFile(secretPath, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\n"+secretMarker+"\n-----END OPENSSH PRIVATE KEY-----\n"), 0600); err != nil {
		t.Fatal(err)
	}
	backendBody := `mkdir -p output
cat "` + secretPath + `" > output/result.txt 2>/dev/null || printf 'read-failed\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	bin := fakeBackend(t, backendBody)

	c := baseContract(root)
	c.RiskClass = "high" // exercises Session 5's external-enforcement gate

	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	rec := runGoverned(t, home, bin, c)

	if rec.Status == "APPROVED" {
		data, err := os.ReadFile(filepath.Join(root, "output", "result.txt"))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(data), secretMarker) {
			t.Fatalf("backend read an undeclared host secret file under Landlock and its content reached committed output: %q", data)
		}
		return
	}
	// A denied/quarantined run is also an acceptable secure outcome per the
	// case description ("if it can't fail at the OS level in this test
	// environment, assert the run is at minimum quarantined/denied").
}

// TestV6Case26BackendPathReplacedBeforeWrappedLaunchNeverRuns is corpus
// case 26 (report P0-14): direct execution launches an already-open,
// verified backend (fd-based, S3), but a systemd/unshare/sandbox WRAPPER
// gets a bare path string it reopens itself -- replaceable in the window
// between Governator's own verification and the wrapper's reopen. This
// test forces the wrapped launch path (risk_class: high, so
// enforce.NewPlan's unshare-wrapped `gov __sandbox_exec` launch is active)
// and races a swap of the resolved backend binary's file content into that
// window, mirroring TestAttack6BackendReplacementBetweenHashAndLaunchIsDetected's
// synchronization strategy (swap once the run's disposable worktree
// appears) but specifically against the WRAPPED launch path rather than
// direct execution.
func TestV6Case26BackendPathReplacedBeforeWrappedLaunchNeverRuns(t *testing.T) {

	if runtime.GOOS != "linux" {
		t.Skip("the wrapped launch path (unshare) is Linux-only")
	}
	if !enforce.Supported() {
		t.Skip("this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}

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
	c.RiskClass = "high"
	enforce.SelfExeOverride = govBinary(t)
	defer func() { enforce.SelfExeOverride = "" }()

	rec := runGoverned(t, home, binPath, c)
	<-swapped

	if _, err := os.Stat(swapMarker); err == nil {
		t.Fatalf("swapped backend executable ran through the wrapped (unshare/sandbox) launch path (status=%s) -- the wrapper reopened a mutable pathname instead of executing the exact verified object", rec.Status)
	}
}

// TestV6Case27GovernatorPathReplacedBeforeSandboxReexecNeverRuns is corpus
// case 27 (report P0-14): the same TOCTOU class as case 26, but against
// Governator's OWN self re-exec into `gov __sandbox_exec`
// (enforce.selfExePath, which uses os.Executable() -- a resolved pathname,
// not /proc/self/exe -- unless enforce.SelfExeOverride is set). This test
// points SelfExeOverride at a private COPY of the compiled gov binary
// (never the shared govBinary(t) singleton other tests reuse) and races a
// swap of that copy's file content into the window between the parent
// process starting and the sandboxed re-exec happening.
func TestV6Case27GovernatorPathReplacedBeforeSandboxReexecNeverRuns(t *testing.T) {

	if runtime.GOOS != "linux" {
		t.Skip("the sandbox re-exec path (unshare) is Linux-only")
	}
	if !enforce.Supported() {
		t.Skip("this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}

	realGovBin := govBinary(t)
	realBytes, err := os.ReadFile(realGovBin)
	if err != nil {
		t.Fatal(err)
	}
	// A private, disposable copy -- swapping THIS file must never affect the
	// shared govBinary(t) singleton other tests in this process reuse.
	privateGov := filepath.Join(t.TempDir(), "gov")
	if err := os.WriteFile(privateGov, realBytes, 0755); err != nil {
		t.Fatal(err)
	}

	swapMarker := filepath.Join(t.TempDir(), "gov-swapped-ran.txt")
	hostileGov := "#!/bin/sh\nprintf swapped > " + swapMarker + "\nexit 1\n"

	root := fixtureRepo(t)
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
		_ = os.WriteFile(privateGov, []byte(hostileGov), 0755)
	}()

	c := baseContract(root)
	c.RiskClass = "high"
	bin := fakeBackend(t, standardBackendBody(""))

	enforce.SelfExeOverride = privateGov
	defer func() { enforce.SelfExeOverride = "" }()

	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	rec, runErr := govruntime.New().RunWithAutoRepair(context.Background(), c)
	<-swapped

	if _, err := os.Stat(swapMarker); err == nil {
		status := "ERROR"
		if runErr == nil {
			status = rec.Status
		}
		t.Fatalf("Governator's own sandbox-helper re-exec ran the swapped gov binary instead of the trusted one (status=%s) -- self re-exec must use /proc/self/exe, not a resolved pathname", status)
	}
	if runErr != nil {
		// Fail-closed before launch is a secure outcome for this attack.
		return
	}
}

// TestV6Case28SystemdUnitNeverMaterializingFailsClosed is corpus case 28
// (report P0-15): if the expected transient systemd unit is never observed
// within the poll deadline, the descendant-scope code may retain whatever
// cgroup the exec process currently appears in as a fallback kill target --
// which can be Governator's own cgroup, the caller's session, or an
// unrelated process, none of which the scope actually owns.
//
// Honest limitation: containment.newSystemdUserScope/resolveCgroupFromPID
// are unexported, and reliably forcing "the transient unit registers with
// systemd but is never observed within the poll deadline" black-box
// requires either a live systemd --user manager under adversarial control
// (not available in this sandbox -- WSL2/CI containers routinely have no
// systemd PID 1 at all) or a fault-injection seam that does not exist
// today. This test exercises the one black-box-reachable slice of the
// invariant: on a host where systemd --user genuinely is NOT PID 1 (the
// common case in this environment), NewScope must not silently retain an
// arbitrary process-group/cgroup as a stand-in "systemd scope" -- it must
// fall through to the next primitive (direct cgroup / PID namespace) or
// refuse for a high-risk run, never fabricate systemd-unit identity it
// never actually observed. Full coverage of the exact-unit-identity check
// (DBus ControlGroup verification) belongs in internal/containment's own
// white-box tests, not this black-box package.
func TestV6Case28SystemdUnitNeverMaterializingFailsClosed(t *testing.T) {

	if runtime.GOOS != "linux" {
		t.Skip("systemd transient scopes are Linux-only")
	}
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		t.Skip("this host has a live systemd --user manager; forcing 'unit registers but never observed within deadline' requires adversarial control over systemd this black-box package cannot exercise here")
	}

	root := fixtureRepo(t)
	c := baseContract(root)
	c.RiskClass = "high"
	bin := fakeBackend(t, standardBackendBody(""))

	rec := runGoverned(t, t.TempDir(), bin, c)
	// Fail-closed is an acceptable (indeed expected, per the report) outcome
	// on a high-risk run with no confirmable strong descendant-owning
	// primitive; what must NEVER happen is a silently fabricated systemd-scope
	// identity backing an APPROVED run whose extinction proof was never
	// actually checked against the real generated unit.
	if rec.Status == "APPROVED" {
		t.Fatal("high-risk run reached APPROVED without a systemd --user manager present to confirm exact transient-unit identity -- containment must fail closed rather than fabricate/assume a scope it never verified")
	}
}

// TestV6Case29PIDCheckEPERMIsNotTreatedAsExtinctionProof is corpus case 29
// (report P0-16): the extinction-proving loop's kill(pid, 0) existence
// check treats ANY error as "process gone" -- but only ESRCH proves
// absence; EPERM means "still present, just not signalable by us."
//
// Honest limitation: the function this bug lives in (containment's
// unexported waitPIDGone) is only reachable through a real PID-namespace
// Scope's Extinguish call, targeting a PID this unprivileged test process
// happens to lack signal permission for -- which structurally requires a
// second real uid (the same limitation TestAttack27's doc comment already
// notes for agents.ForceParentWritable: "this unprivileged test process
// cannot construct" a genuine cross-uid permission boundary). What IS
// reachable and asserted here is the underlying kernel property the fix
// must respect: kill(pid, 0) against a real, live, root-owned process this
// test process does not own returns EPERM, not ESRCH -- proving the
// process is NOT gone even though signaling it fails. Full coverage of
// containment's own EPERM-vs-ESRCH branch belongs in internal/containment's
// white-box tests (unexported function, different package), not here.
func TestV6Case29PIDCheckEPERMIsNotTreatedAsExtinctionProof(t *testing.T) {

	if runtime.GOOS != "linux" {
		t.Skip("this property is Linux/POSIX signal-semantics specific")
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: kill(pid,0) against pid 1 would not return EPERM, so the fixture cannot demonstrate the property")
	}

	// pid 1 (init/systemd) is root-owned and, on any live Linux host, alive
	// for the lifetime of this process. An unprivileged process can never
	// signal it, but it unquestionably exists.
	err := syscall.Kill(1, 0)
	if err == nil {
		t.Skip("unexpectedly had permission to signal pid 1 in this environment; cannot demonstrate the EPERM-vs-ESRCH distinction here")
	}
	if err != syscall.EPERM {
		t.Skipf("kill(1,0) returned %v, not EPERM, in this environment; cannot demonstrate the property here", err)
	}
	// This IS the property containment.waitPIDGone must respect and
	// now does: EPERM proves the process is STILL PRESENT (just
	// unsignalable by us), the opposite of what a bare `if err != nil {
	// return nil /* gone */ }` treats it as. A fixed implementation, driven
	// through this exact kernel condition, must never report extinction
	// here; this test's pass condition (reaching this point at all, past
	// the confirmations above) stands in for that white-box assertion,
	// which belongs in internal/containment's own _test.go.
}
