//go:build redteam

// v10_s7_graph_replay_test.go is Sol10's rc4 Session 7 corpus (report P0-7,
// "report cases 32-35"), owned by agents/governator-sol-upgrade10-rc4-plan.md
// Session 7. Case 31 (report: "isolated
// TestV6Case23GraphDatabaseChangeBeforeReplayInvalidatesReplay") is the
// pre-existing test in v6_s6_replay_identity_test.go -- Sol found it
// contradicted release evidence (docs/security.md declared it a permanent
// unfixed defect while the release log claimed a blanket PASS with no named
// manifest entry and no raw log to check), not that it needed a new
// fixture. Re-running it in isolation (10x, see docs/security.md) shows it
// already passes: internal/runtime/runtime.go's `preReplayGraph` (introduced
// by commit c28c80e, "Complete Sol v6 S9 assayer lifecycle hardening") reads
// the graph snapshot via the non-mutating contextgraph.CurrentWithStatus
// BEFORE replayMatch, and that same value (never a second, later Prepare
// call) becomes the run's recorded Graph -- so a replayed run's Graph is
// never a zero Snapshot, and the ordering bug the stale doc text describes
// no longer exists in this codebase. This file's job is enrolling case 31 by
// its existing exact name (done in manifest.yaml) and adding cases 32-35,
// which probe adjacent angles the existing v6/v9 graph corpus did not cover.
package redteam

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/enforce"
	govruntime "github.com/cousingary/governator/internal/runtime"
	"github.com/cousingary/governator/internal/toolregistry"
)

// TestV10Case33GraphProviderEmptyFingerprintNeverReportsSnapshotAvailable is
// report case 33 ("graph provider returns empty fingerprint"). Before this
// session, contextgraph.snapshotFromStats set Snapshot.Available = true
// before even attempting to hash the reported index file; a hashFile
// failure (index path missing/unreadable) still returned Available=true
// with an empty Fingerprint, and for any mode other than "required" the
// caller (prepareFailure) swallowed the error entirely -- so a caller
// checking only Available (CommandPatterns, PromptAnnotation) would treat
// this as a legitimate, if empty, graph snapshot. Fixed:
// contextgraph.go's Available is now set only after Fingerprint is
// actually computed. Lives in this package (rather than
// internal/contextgraph's own test file) because contextgraph.Current
// always launches its provider probe through stage.Executor's externally
// enforced plan, which requires a real gov binary for
// enforce.SelfExeOverride -- this package's govBinary/enrollRealControllerTools
// already provide that; internal/contextgraph's own tests have no such
// harness and always skip on this repo's default `go test` invocation.
func TestV10Case33GraphProviderEmptyFingerprintNeverReportsSnapshotAvailable(t *testing.T) {
	enforce.SelfExeOverride = govBinary(t)
	t.Cleanup(func() { enforce.SelfExeOverride = "" })
	if !enforce.Supported() {
		t.Skip("this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	enrollRealControllerTools(t)
	// A real compiled ELF binary, not a #!/bin/sh script: scopedCommandOutput
	// (internal/contextgraph) declares only the executable's own path as the
	// authority-bearing launch target, with no interpreter closure -- a
	// production graph provider is a compiled tool, never a script (see
	// buildFakeCodegraphBinary's own doc comment).
	bin := buildFakeCodegraphBinary(t, "", "", `{"initialized":true,"indexPath":"/nonexistent/codegraph.db"}`)
	if _, err := toolregistry.Enroll("codegraph", bin); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_GRAPH_MODE", "auto")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", bin)

	snapshot, err := contextgraph.Current(t.TempDir())
	if err != nil {
		t.Fatalf("unexpected hard error in auto mode: %v", err)
	}
	if snapshot.Available {
		t.Fatalf("snapshot=%+v: Available must be false when the fingerprint could not be computed", snapshot)
	}
	if snapshot.Fingerprint != "" {
		t.Fatalf("snapshot=%+v: Fingerprint must be empty alongside Available=false", snapshot)
	}
	if snapshot.Warning == "" {
		t.Fatal("expected a Warning explaining why the snapshot is unavailable")
	}
}

// TestV10Case32GraphDatabaseChangeImmediatelyBeforeReplayLookupInvalidatesReplayAcrossRepeatedCycles
// is report case 32. TestV6Case23 already proves a single mutate-then-run
// pair never replays; this closes the "immediately before" framing more
// aggressively -- three back-to-back mutate/run cycles with zero gap
// between the mutation and the very next run, proving the fingerprint
// difference is a genuine content-addressed distinction every cycle, not a
// coincidence that happens to survive one iteration or that depends on a
// timing gap (e.g. a stale mtime-based comparison, which this codebase does
// not use, but which the black-box corpus should positively rule out).
func TestV10Case32GraphDatabaseChangeImmediatelyBeforeReplayLookupInvalidatesReplayAcrossRepeatedCycles(t *testing.T) {
	s6BypassHostContainment(t)

	root := fixtureRepo(t)
	home := t.TempDir()
	_ = govBinary(t)

	fakeCodegraph := buildFakeCodegraphBinary(t, "\t\"path/filepath\"\n", `
		dbFile := filepath.Join(os.Getenv("HOME"), "graph.db")
		info, statErr := os.Stat(dbFile)
		var size int64
		if statErr == nil {
			size = info.Size()
		}
		fmt.Printf("{\"version\":\"1.0.0\",\"initialized\":true,\"projectPath\":\"\",\"indexPath\":%q,\"fileCount\":1,\"nodeCount\":1,\"edgeCount\":1,\"dbSizeBytes\":%d}\n", dbFile, size)
		return
`, "")

	graphHome := t.TempDir()
	t.Setenv("HOME", graphHome)
	dbFile := filepath.Join(graphHome, "graph.db")

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	s6EnrollControllerTools(t)
	if _, err := toolregistry.Enroll("codegraph", fakeCodegraph); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "auto")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", fakeCodegraph)

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	var lastFingerprint string
	for i := 0; i < 3; i++ {
		content := fmt.Sprintf("graph-state-cycle-%d", i)
		if err := os.WriteFile(dbFile, []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
		// No gap between the mutation above and the run below -- the
		// tightest window a black-box test can create.
		r := runGoverned(t, home, bin, c)
		if r.Status != "APPROVED" {
			t.Fatalf("cycle %d: expected APPROVED, got status=%s message=%s", i, r.Status, r.Message)
		}
		if i > 0 && r.Replayed {
			t.Fatalf("cycle %d replayed a stale approval immediately after the graph database changed", i)
		}
		if r.Graph.Fingerprint == "" {
			t.Fatalf("cycle %d: empty graph fingerprint", i)
		}
		if r.Graph.Fingerprint == lastFingerprint {
			t.Fatalf("cycle %d: graph fingerprint (%q) did not change even though the underlying graph database content changed", i, r.Graph.Fingerprint)
		}
		lastFingerprint = r.Graph.Fingerprint
	}
}

// TestV10Case34GraphIndexMutationDuringRunHasNoEffectOnThatRunsRecordedSnapshot
// is report case 34 ("graph sync changes the fingerprint after identity
// calculation"): runtime.go computes preReplayGraph (and folds its hash
// into replay identity) before the workspace is even prepared, well before
// the backend ever launches. Like TestV6Case23, the live graph index file
// lives under a test-owned $HOME rather than inside root's own working
// tree -- root directly (contextgraph.CurrentWithStatus runs on the bare
// repo before any per-run worktree exists) rejects an untracked file
// sitting there as "live root dirty before merge" and quarantines the run,
// confirmed empirically by TestV6Case23's own fixture rationale. This test
// proves the identity-freezing property with a real intra-run race instead
// of two separate runs: the fake backend signals (via a marker file) the
// instant it has actually started -- which can only happen after runOnce
// has already captured preReplayGraph, since workspace preparation and
// backend launch both happen well after that point in runOnce -- and only
// then does the test mutate the live graph index file directly, racing
// against (but strictly after) this run's own identity calculation. The
// completed run's recorded Graph.Fingerprint must still equal the
// pre-mutation content's hash, not the concurrently written content,
// proving the graph snapshot used for this transaction's identity is
// genuinely frozen at run start rather than silently re-read at
// completion.
func TestV10Case34GraphIndexMutationDuringRunHasNoEffectOnThatRunsRecordedSnapshot(t *testing.T) {
	s6BypassHostContainment(t)

	root := fixtureRepo(t)
	home := t.TempDir()
	_ = govBinary(t)

	fakeCodegraph := buildFakeCodegraphBinary(t, "\t\"path/filepath\"\n", `
		dbFile := filepath.Join(os.Getenv("HOME"), "graph.db")
		info, statErr := os.Stat(dbFile)
		var size int64
		if statErr == nil {
			size = info.Size()
		}
		fmt.Printf("{\"version\":\"1.0.0\",\"initialized\":true,\"projectPath\":\"\",\"indexPath\":%q,\"fileCount\":1,\"nodeCount\":1,\"edgeCount\":1,\"dbSizeBytes\":%d}\n", dbFile, size)
		return
`, "")

	graphHome := t.TempDir()
	t.Setenv("HOME", graphHome)
	dbFile := filepath.Join(graphHome, "graph.db")
	if err := os.WriteFile(dbFile, []byte("v1"), 0644); err != nil {
		t.Fatal(err)
	}

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	s6EnrollControllerTools(t)
	if _, err := toolregistry.Enroll("codegraph", fakeCodegraph); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_GRAPH_MODE", "required")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", fakeCodegraph)

	// The backend sleeps before producing its result -- run 1 (workspace
	// prep, preReplayGraph capture, backend launch) always happens well
	// before this sleep even starts, so a short fixed wait below reliably
	// lands the mutation while the backend is still inside its sleep,
	// without needing the backend to signal anything itself (which would
	// require a marker write -- but a marker path outside this contract's
	// declared write authority fails under real enforcement even in
	// "degraded" containment mode, since write-root scoping is a property
	// of the compiled enforce.Plan, not the containment/descendant-tracking
	// mechanism s6BypassHostContainment relaxes).
	c := baseContract(root)
	backendBin := fakeBackend(t, standardBackendBody("sleep 1\n"))

	// Everything runGovernedAllowError would normally do, performed here on
	// the test's own goroutine before the run is launched on a separate one
	// below -- t.Setenv and enforce.SelfExeOverride must not be touched
	// concurrently from a non-test goroutine.
	enrollRealControllerTools(t)
	if enforce.SelfExeOverride == "" {
		enforce.SelfExeOverride = govBinary(t)
		t.Cleanup(func() { enforce.SelfExeOverride = "" })
	}
	t.Setenv("GOV_HOME", home)
	t.Setenv("GOV_CLAUDE_BIN", backendBin)

	type outcome struct {
		rec govruntime.RunRecord
		err error
	}
	done := make(chan outcome, 1)
	go func() {
		rec, err := govruntime.New().RunWithAutoRepair(context.Background(), c)
		done <- outcome{rec, err}
	}()

	time.Sleep(400 * time.Millisecond)
	if err := os.WriteFile(dbFile, []byte("v2-concurrent-mutation"), 0644); err != nil {
		t.Fatal(err)
	}

	var res outcome
	select {
	case res = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("timed out waiting for the run to complete")
	}
	if res.err != nil {
		t.Fatalf("RunWithAutoRepair: %v", res.err)
	}
	if res.rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED, got status=%s message=%s", res.rec.Status, res.rec.Message)
	}

	wantFrozen := "3bfc269594ef649228e9a74bab00f042efc91d5acc6fbee31a382e80d42388fe" // sha256("v1")
	if res.rec.Graph.Fingerprint != wantFrozen {
		t.Fatalf("run's recorded Graph.Fingerprint = %q, want %q (the pre-mutation content's hash) -- a concurrent external mutation of the graph index during this run must not retroactively change what this run's identity/record describes", res.rec.Graph.Fingerprint, wantFrozen)
	}
	liveContent, err := os.ReadFile(dbFile)
	if err != nil {
		t.Fatal(err)
	}
	if string(liveContent) != "v2-concurrent-mutation" {
		t.Fatalf("graph index live content = %q, want the concurrent mutation to have actually landed (otherwise the Fingerprint assertion above is vacuous)", liveContent)
	}
}

// TestV10Case35GraphProviderRequiredButUntrustedFailsRunBeforeBackendLaunch
// is report case 35 ("graph-dependent strict replay with unavailable
// provider"): contextgraph.ResolveConfigWithRegistry already returns a hard
// error for an unenrolled/untrusted provider name in "required" mode
// (report P0-5/attack 9's existing fail-closed contract), and
// buildRunEnvironment (internal/runtime/environment.go) already propagates
// that error before resolving containment or preparing any workspace. This
// proves that chain end to end through the real governed-run entry point:
// the whole run must fail closed -- never launch the backend, never merge
// anything -- rather than silently running with strict replay enabled and
// no graph state actually accounted for.
func TestV10Case35GraphProviderRequiredButUntrustedFailsRunBeforeBackendLaunch(t *testing.T) {
	s6BypassHostContainment(t)

	root := fixtureRepo(t)
	home := t.TempDir()

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	// Deliberately do NOT enroll "codegraph" under this fresh registry.
	t.Setenv("GOV_GRAPH_MODE", "required")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", "codegraph")

	marker := filepath.Join(t.TempDir(), "backend-ran")
	c := baseContract(root)
	bin := fakeBackend(t, "printf '' > "+marker+"\n"+standardBackendBody(""))

	_, err := runGovernedAllowError(t, home, bin, c)
	if err == nil || !strings.Contains(err.Error(), "required but not trusted") {
		t.Fatalf("expected a required-but-not-trusted graph provider failure, got err=%v", err)
	}
	if _, statErr := os.Stat(marker); statErr == nil {
		t.Fatal("backend executed even though the required graph provider was untrusted -- the run must fail closed before launch")
	}
	log := strings.TrimSpace(gitOutput(t, root, "log", "--oneline"))
	lines := strings.Split(log, "\n")
	if len(lines) != 1 {
		t.Fatalf("expected only the seed commit (no run merged after a fail-closed graph resolution), got %d commits: %v", len(lines), lines)
	}
}
