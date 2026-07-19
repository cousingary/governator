//go:build redteam

// v9_s1_wrapper_composition_test.go is Sol redteam v9's rc3 Session 1
// corpus (agents/governator-sol-upgrade9-rc3-plan.md Session 1,
// agents/governator-sol-upgrade9.md P0-1/P0-2): "report cases 1, 2, 3".
//
// P0-1 was that a network-denied launch built an argv equivalent to
// `trusted-unshare --net --map-root-user -- /proc/self/exe __sandbox_exec
// ...` -- and "/proc/self/exe" resolved by unshare(1) at its own exec names
// unshare, not Governator, so the real launch chain never reached
// Governator's sandbox helper on a host with real unshare/Landlock at all.
// P0-2 was that the unshare(1) primitive itself was resolved/verified once
// and then executed by its enrolled PATHNAME, leaving a same-uid TOCTOU
// window between verification and exec.
//
// TestV9Case1 is the report's own "Required regression" for P0-1: a
// production-mode integration test with enforce.SelfExeOverride == "" (every
// other test in this corpus points SelfExeOverride at a private copy --
// see enforce.SelfExeOverride's doc comment -- so none of them exercise the
// real production /proc/self/exe path at all). TestV9Case2 and
// TestV9Case3 are the P0-1/P0-2 same-uid swap proofs.
package redteam

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
	"gopkg.in/yaml.v3"
)

// writeContractYAML marshals c to a job YAML file a real `gov run` subprocess
// can parse -- contracts.Success/Cleanup carry custom MarshalYAML methods
// specifically so a Contract value round-trips through YAML this way.
func writeContractYAML(t *testing.T, c contracts.Contract) string {
	t.Helper()
	data, err := yaml.Marshal(c)
	if err != nil {
		t.Fatalf("marshal contract: %v", err)
	}
	path := filepath.Join(t.TempDir(), "job.yaml")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

// runRecordStatus is the minimal shape this file needs from a subprocess
// `gov run`'s stdout (govruntime.MarshalRecord's full JSON record).
type runRecordStatus struct {
	Status string `json:"status"`
}

// TestV9Case1ProductionSandboxHelperReachesGovernatorNotUnshare is the Sol
// v9 P0-1 "Required regression": drives the REAL COMPILED gov binary as an
// actual subprocess (never internal/runtime.RunWithAutoRepair called
// in-process, and never enforce.SelfExeOverride) through `gov run`, forcing
// the unshare-wrapped network-denied launch (risk_class: high, plus
// baseContract's own forbidden.behaviors: [network]). Only Governator's own
// __sandbox_exec handler understands that argument; the pre-fix chain
// (unshare resolving "/proc/self/exe" as itself) failed with "exe:
// '__sandbox_exec': No such file or directory" before ever reaching the
// backend at all (Sol's own reproduction). Reaching APPROVED here is
// therefore direct behavioral proof of correct identity at the helper
// boundary, not just "network was denied" -- combined with
// TestV9Case3's explicit same-uid swap-immunity proof below for the
// identity claim itself.
func TestV9Case1ProductionSandboxHelperReachesGovernatorNotUnshare(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the unshare-wrapped sandbox re-exec path is Linux-only")
	}
	if !enforce.Supported() {
		t.Skip("this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}
	if enforce.SelfExeOverride != "" {
		t.Fatalf("test invariant violated: SelfExeOverride must be unset to exercise the production path, got %q", enforce.SelfExeOverride)
	}
	enrollRealControllerTools(t)

	var received int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&received, 1)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	root := fixtureRepo(t)
	home := t.TempDir()
	bin := fakeBackend(t, standardBackendBody(`
curl -s -m 3 -X POST --data governator-network-escape `+srv.URL+` >/dev/null 2>&1 || true
`))

	c := baseContract(root)
	c.RiskClass = "high"
	contractPath := writeContractYAML(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, govBinary(t), "run", contractPath)
	cmd.Env = append(os.Environ(), "GOV_HOME="+home, "GOV_CLAUDE_BIN="+bin)
	out, _ := cmd.CombinedOutput()

	var rec runRecordStatus
	if err := json.Unmarshal(bytes.TrimSpace(out), &rec); err != nil {
		t.Fatalf("gov run (real subprocess, SelfExeOverride unset) did not print a parseable record: %v\noutput: %s", err, out)
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("production unshare-wrapped launch did not reach the backend: status=%s output=%s", rec.Status, out)
	}
	if atomic.LoadInt32(&received) > 0 {
		t.Fatalf("network-denied production launch reached the network (%d request(s)) despite APPROVED status", atomic.LoadInt32(&received))
	}
}

// TestV9Case2EnrolledUnshareSwapAfterPlanResolutionCannotChangeExecutedBytes
// is Sol v9 report case 2 (P0-2's required correction): NewPlanForExecutable
// resolves and opens unshare through the trusted-tool registry exactly
// once, holding a sealed descriptor; Wrap must launch through that held
// descriptor, never by reopening the registry's pinned pathname a second
// time. This enrolls a disposable "unshare" stand-in, resolves a Plan
// against it, replaces the enrolled file's on-disk content with a hostile
// script, and proves Wrap's returned bin/args/extraFiles still execute the
// pre-swap object.
func TestV9Case2EnrolledUnshareSwapAfterPlanResolutionCannotChangeExecutedBytes(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fd-backed launch requires Linux")
	}
	if !enforce.Supported() {
		t.Skip("this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}

	dir := t.TempDir()
	unsharePath := filepath.Join(dir, "unshare")
	honest := "#!/bin/sh\nprintf honest-unshare\nexit 0\n"
	if err := os.WriteFile(unsharePath, []byte(honest), 0755); err != nil {
		t.Fatal(err)
	}
	regDir := t.TempDir()
	t.Setenv("GOV_TOOLREGISTRY_FILE", filepath.Join(regDir, "tools.yaml"))
	if _, err := toolregistry.Enroll("unshare", unsharePath); err != nil {
		t.Fatal(err)
	}

	plan, err := enforce.NewPlanForExecutable(true, t.TempDir(), false, false, false, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = plan.Close() }()
	if !plan.Active {
		t.Fatal("expected an active plan (Supported() already confirmed above)")
	}

	// Same-uid replacement of the enrolled unshare binary AFTER Plan
	// resolution already holds an open, verified descriptor to the honest
	// object -- this must have no effect on what actually executes. Rename,
	// not an in-place WriteFile: WriteFile truncates and rewrites the SAME
	// inode the already-open handle points to, so an already-held fd would
	// see the new content too and this wouldn't test anything. Rename
	// detaches the pathname from that inode and attaches it to a freshly
	// created one, leaving the held descriptor pointing at the untouched
	// original -- exactly the v7S4ToolSwap pattern this mirrors.
	hostileDir := t.TempDir()
	hostilePath := filepath.Join(hostileDir, "unshare")
	hostile := "#!/bin/sh\nexit 1\n"
	if err := os.WriteFile(hostilePath, []byte(hostile), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(hostilePath, unsharePath); err != nil {
		t.Fatal(err)
	}

	bin, args, extraFiles := plan.Wrap("/bin/true", nil)
	cmd := exec.Command(bin, args...)
	cmd.ExtraFiles = extraFiles
	out, runErr := cmd.Output()
	if runErr != nil {
		t.Fatalf("verified unshare object did not run (the swapped replacement may have executed instead): %v", runErr)
	}
	if strings.TrimSpace(string(out)) != "honest-unshare" {
		t.Fatalf("swap changed the executed bytes: %q", out)
	}
}

// TestV9Case3GovernatorOnDiskSwapAfterProcessStartCannotChangeSandboxHelperIdentity
// is Sol v9 report case 3 (P0-1's identity requirement: "verify the
// Governator executable identity at the helper boundary"). Unlike every
// other swap test in this corpus (which race a file replacement into a
// window BEFORE a vulnerable pathname reopen), this target is
// process-intrinsic: once a process has exec'd, Linux's /proc/self/exe for
// that process is pinned to the inode active at exec time for the rest of
// its life, regardless of any later rename/unlink/replace of that pathname
// -- the kernel additionally refuses an in-place overwrite of a currently
// mapped executable (ETXTBSY), so a same-uid attacker's only lever is
// rename(), which this test uses. No race window is needed: the swap is
// correct at any point after Start() returns. This drives the real compiled
// gov binary (copied to a private, disposable path so the shared govBinary(t)
// singleton other tests reuse is never touched) with SelfExeOverride unset,
// proving the production self-exec is immune.
func TestV9Case3GovernatorOnDiskSwapAfterProcessStartCannotChangeSandboxHelperIdentity(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the fd-backed self-exec path is Linux-only")
	}
	if !enforce.Supported() {
		t.Skip("this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}
	if enforce.SelfExeOverride != "" {
		t.Fatalf("test invariant violated: SelfExeOverride must be unset to exercise the production path, got %q", enforce.SelfExeOverride)
	}
	enrollRealControllerTools(t)

	realBytes, err := os.ReadFile(govBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	privateGov := filepath.Join(t.TempDir(), "gov")
	if err := os.WriteFile(privateGov, realBytes, 0755); err != nil {
		t.Fatal(err)
	}

	root := fixtureRepo(t)
	home := t.TempDir()
	bin := fakeBackend(t, standardBackendBody(""))

	c := baseContract(root)
	c.RiskClass = "high"
	contractPath := writeContractYAML(t, c)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, privateGov, "run", contractPath)
	cmd.Env = append(os.Environ(), "GOV_HOME="+home, "GOV_CLAUDE_BIN="+bin)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	hostileMarker := filepath.Join(t.TempDir(), "hostile-ran.txt")
	hostileDir := t.TempDir()
	hostilePath := filepath.Join(hostileDir, "gov")
	hostileScript := "#!/bin/sh\nprintf swapped > " + hostileMarker + "\nexit 1\n"
	if err := os.WriteFile(hostilePath, []byte(hostileScript), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(hostilePath, privateGov); err != nil {
		t.Fatal(err)
	}

	waitErr := cmd.Wait()

	if _, statErr := os.Stat(hostileMarker); statErr == nil {
		t.Fatalf("swapped gov binary ran through the production /proc/self/exe sandbox re-exec (SelfExeOverride unset): output=%s waitErr=%v", out.String(), waitErr)
	}

	var rec runRecordStatus
	if err := json.Unmarshal(bytes.TrimSpace(out.Bytes()), &rec); err != nil {
		t.Fatalf("gov run did not print a parseable record: %v\noutput: %s", err, out.String())
	}
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED (the on-disk swap after process start must have no effect on the real production launch), got status=%s\noutput: %s", rec.Status, out.String())
	}
}
