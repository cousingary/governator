//go:build redteam

// v6_s6_replay_identity_test.go is the Sol redteam v6 Permanent Regression
// Corpus, cases 22-24, owned by Session 6 (Phase 6: every trust-bearing
// dynamic input -- consumed artifacts, the graph database, the graph
// provider itself -- must be resolved and hashed into ExecutionIdentity
// BEFORE the replay lookup, not after). See
// agents/governator-sol-upgrade6-plan.md Session 6 and
// agents/governator-sol-upgrade6.md P0-11/P0-12. Confirmed directly from
// source: internal/runtime/runtime.go computes ExecutionIdentity and checks
// replayMatch (~line 2576-2583) BEFORE contextgraph.Prepare ever runs
// (~line 2623) and before stageConsumedArtifacts (~line 2643) -- a replayed
// run returns immediately, never touching either. internal/runtime/identity.go's
// ExecutionIdentity struct has no consumed-artifact, graph-provider, or
// graph-snapshot field at all. Every test here is scaffolding only (Session
// 0): t.Skip(...) is the literal first statement, before any fixture
// construction.
package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/toolregistry"
)

func s6EnrollControllerTool(t *testing.T, name string) {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := toolregistry.Enroll(name, path); err != nil {
		t.Fatal(err)
	}
}

func s6EnrollControllerTools(t *testing.T) {
	t.Helper()
	s6EnrollControllerTool(t, "git")
	s6EnrollControllerTool(t, "bash")
}

func s6SecureExecutable(t *testing.T, src string) string {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".gov-s6-tool-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	dst := filepath.Join(dir, filepath.Base(src))
	if err := os.WriteFile(dst, data, 0755); err != nil {
		t.Fatal(err)
	}
	return dst
}

func s6BypassHostContainment(t *testing.T) {
	t.Helper()
	// Sol11 P0-3/P0-4: the env vars this formerly set
	// (GOV_CONTAINMENT_FORCE_DEGRADED, GOV_CONTAINMENT_LOCAL_EFFECTFUL_TIERING)
	// are gone -- they were inherited-environment production bypasses. The
	// corpus now uses the test-only descendant-containment seam, which cannot
	// be flipped by environment, so production authority is never weakened
	// while these fixtures still run without real systemd/cgroup/PID-namespace
	// primitives.
	useDegradedContainmentScopeForTest(t)
}

// TestV6Case22ConsumedArtifactChangeBeforeConsumerReplayInvalidatesReplay
// is corpus case 22 (report P0-11): a producer->consumer scenario. The
// producer job emits an artifact; a consumer job (Consumes the artifact,
// ArtifactSources naming the producer) runs once and is APPROVED, its
// output literally copied from the staged consumed-artifact content. The
// SAME producer job_id then re-runs (a different backend binary, so it is
// not itself a replay) and emits DIFFERENT artifact content. The consumer
// contract is then run again, byte-for-byte identical to its first
// invocation (same backend binary, same everything) -- since
// ExecutionIdentity does not hash the consumed artifact, this replays the
// FIRST (stale) approval instead of re-running against the producer's new
// output. Fixed, this second consumer run must not replay, and its
// (re-executed) output must reflect the producer's NEW artifact content.
func TestV6Case22ConsumedArtifactChangeBeforeConsumerReplayInvalidatesReplay(t *testing.T) {
	s6BypassHostContainment(t)

	root := fixtureRepo(t)
	home := t.TempDir()

	producer := contracts.Contract{
		Task: "producer", JobID: "v6-case22-producer", JobType: "test", Agent: "claude-code", Mode: contracts.ModeSurgeon,
		Workspace:   contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:     contracts.Permissions{Read: []string{"**"}, Write: []string{"output/**", ".governator/artifacts/**"}, Execute: []string{"test"}},
		Forbidden:   contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:      contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxLinesChanged: 20, MaxNewFiles: 5, MaxDeleted: 0},
		Preflight:   contracts.Preflight{IntendedWrites: []string{"output/**", ".governator/artifacts/**"}},
		Success:     contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}},
		Produces:    []contracts.ArtifactSpec{{Name: "art", Path: ".governator/artifacts/art.txt", MaxBytes: 1024}},
		OnViolation: "quarantine",
		Local:       &contracts.LocalRunnerConfig{ReadRoots: shellReadRootsForFixtures()},
	}
	producerBody := func(content string) string {
		return `mkdir -p .governator/artifacts
printf '%s' '` + content + `' > .governator/artifacts/art.txt
mkdir -p output
printf 'ok\n' > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt",".governator/artifacts/art.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	}

	producerBinV1 := fakeBackend(t, producerBody("v1"))
	p1 := runGoverned(t, home, producerBinV1, producer)
	if p1.Status != "APPROVED" {
		t.Fatalf("producer v1 expected APPROVED, got status=%s message=%s", p1.Status, p1.Message)
	}

	consumer := contracts.Contract{
		Task: "consumer", JobID: "v6-case22-consumer", JobType: "test", Agent: "claude-code", Mode: contracts.ModeSurgeon,
		Workspace:       contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:         contracts.Permissions{Read: []string{"**"}, Write: []string{"output/**"}, Execute: []string{"test"}},
		Forbidden:       contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf"}, Behaviors: []string{"network"}},
		Budget:          contracts.Budget{MaxMinutes: 1, MaxCommands: 5, MaxFilesChanged: 5, MaxLinesChanged: 20, MaxNewFiles: 5, MaxDeleted: 0},
		Preflight:       contracts.Preflight{IntendedWrites: []string{"output/**"}},
		Success:         contracts.Success{RequiredFiles: []string{"output/result.txt"}, Validators: []string{"test -f output/result.txt"}},
		Consumes:        []string{"art"},
		ArtifactSources: map[string]string{"art": "v6-case22-producer"},
		OnViolation:     "quarantine",
		Local:           &contracts.LocalRunnerConfig{ReadRoots: shellReadRootsForFixtures()},
	}
	consumerBody := `mkdir -p output
cat .governator/consumed/art > output/result.txt
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.25}\n'
`
	consumerBin := fakeBackend(t, consumerBody)

	c1 := runGoverned(t, home, consumerBin, consumer)
	if c1.Status != "APPROVED" {
		t.Fatalf("consumer run 1 expected APPROVED, got status=%s message=%s", c1.Status, c1.Message)
	}
	got1 := gitOutput(t, root, "show", "HEAD:output/result.txt")
	if got1 != "v1" {
		t.Fatalf("consumer run 1 output = %q, want %q (staged consumed artifact was not the producer's v1 content)", got1, "v1")
	}

	// Producer re-runs with a DIFFERENT backend (so it is not itself a
	// replay) and emits DIFFERENT artifact content.
	producerBinV2 := fakeBackend(t, producerBody("v2"))
	p2 := runGoverned(t, home, producerBinV2, producer)
	if p2.Status != "APPROVED" {
		t.Fatalf("producer v2 expected APPROVED, got status=%s message=%s", p2.Status, p2.Message)
	}

	// Consumer runs again, byte-for-byte identical contract and backend
	// binary as its first invocation.
	c2 := runGoverned(t, home, consumerBin, consumer)
	if c2.Replayed {
		t.Fatal("consumer replayed a stale approval after its consumed artifact changed (producer emitted new content) -- replay identity does not bind consumed-artifact hashes")
	}
	got2 := gitOutput(t, root, "show", "HEAD:output/result.txt")
	if got2 != "v2" {
		t.Fatalf("consumer run 2 output = %q, want %q -- consumer served a stale artifact instead of the producer's updated content", got2, "v2")
	}
}

// TestV6Case23GraphDatabaseChangeBeforeReplayInvalidatesReplay is corpus
// case 23 (report P0-11/P0-12): between two otherwise-identical runs of the
// same contract/backend, the context-graph database content changes (a
// registered, pinned "codegraph" provider reports a different index file
// each time, via a test-controlled db-content file). contextgraph.Prepare
// is called AFTER the replay lookup in runOnce, so a replayed run's
// RunRecord.Graph is the zero Snapshot -- Prepare never runs at all for a
// replayed run. This test asserts the second run does not replay, proving
// the changed graph state was actually accounted for rather than silently
// ignored by an early, graph-blind replay lookup.
func TestV6Case23GraphDatabaseChangeBeforeReplayInvalidatesReplay(t *testing.T) {
	s6BypassHostContainment(t)

	root := fixtureRepo(t)
	home := t.TempDir()

	// Force govBinary's one-time build (sync.Once) to happen now, under the
	// real ambient HOME, before the HOME override below. Otherwise, if this
	// is the first test in the process to call runGoverned (as it is when
	// run standalone via -run), the build's own module-cache resolution
	// happens under the redirected HOME instead -- a full, slow re-download
	// into an empty cache, with read-only module files t.TempDir() cleanup
	// can't remove.
	_ = govBinary(t)

	// A compiled ELF binary, not a #!/bin/sh script -- see TestV6Case24's
	// comment just below for why (scopedCommandOutput's enforce.Plan has no
	// declared interpreter closure by design). Reads the marker file's size
	// at call time via $HOME (forwarded through the frozen controller
	// environment, unlike an arbitrary env var) so the reported fingerprint
	// tracks the file's live content, same as the original script. Built
	// BEFORE the HOME override below: buildFakeCodegraphBinary shells out to
	// `go build`, which resolves its own module cache under $HOME/go/pkg/mod
	// -- redirecting HOME first forces a fresh, slow module download here
	// and leaves read-only cache files t.TempDir() cleanup can't remove.
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

	// The live "db" file cannot live in root's own working tree: the graph
	// provider stage reads root directly (contextgraph.CurrentWithStatus
	// runs on the bare repo, before any per-run worktree is even created),
	// but an untracked file sitting there fails runtime's "live root dirty
	// before merge" check and quarantines the run (confirmed empirically:
	// placing it under root turned this test's own APPROVED assertion into
	// a QUARANTINED failure). It also cannot travel via an ad hoc env var
	// like the original GOV_V6_GRAPH_DB: controllerenv.Allowlist (PATH/HOME/
	// TMPDIR/LANG/LC_ALL/TZ/XDG_RUNTIME_DIR) strips every other env var
	// before a controller subprocess launches, so the fake binary always
	// saw "" regardless of what the test set, making the fingerprint check
	// below silently vacuous (empty on every run, not just an unchanged
	// one). HOME, in contrast, IS on the allowlist and is read fresh from
	// the process environment at Freeze()-time (controllerenv.With), so
	// redirecting it to a test-owned temp dir is the one channel that both
	// reaches the subprocess and stays outside the git-tracked workspace.
	graphHome := t.TempDir()
	t.Setenv("HOME", graphHome)
	dbFile := filepath.Join(graphHome, "graph.db")
	if err := os.WriteFile(dbFile, []byte("graph-state-v1"), 0644); err != nil {
		t.Fatal(err)
	}

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

	r1 := runGoverned(t, home, bin, c)
	if r1.Status != "APPROVED" {
		t.Fatalf("run 1 expected APPROVED, got status=%s message=%s", r1.Status, r1.Message)
	}
	fp1 := r1.Graph.Fingerprint

	if err := os.WriteFile(dbFile, []byte("graph-state-v2-completely-different"), 0644); err != nil {
		t.Fatal(err)
	}

	r2 := runGoverned(t, home, bin, c)
	if r2.Replayed {
		t.Fatalf("run 2 replayed a stale approval after the graph database changed (run 1 fingerprint=%q) -- replay identity does not bind the graph-database fingerprint", fp1)
	}
	if r2.Graph.Fingerprint == "" {
		t.Fatal("run 2's graph snapshot was never computed (empty fingerprint) -- a replayed run never calls contextgraph.Prepare at all")
	}
	if r2.Graph.Fingerprint == fp1 {
		t.Fatalf("run 2's graph fingerprint (%q) matches run 1's even though the underlying graph database content changed", r2.Graph.Fingerprint)
	}
}

// TestV6Case24GraphProviderChangeBeforeReplayInvalidatesReplay is corpus
// case 24 (report P0-12): the same idea as case 23, but the graph
// PROVIDER's own identity changes between two runs (a different registry
// pin -- a different binary at a different verified path -- rather than
// just the data it reports), still reporting a stable-looking version
// string. The report wants graph-provider identity bound into replay
// identity, not just its output.
func TestV6Case24GraphProviderChangeBeforeReplayInvalidatesReplay(t *testing.T) {
	s6BypassHostContainment(t)

	root := fixtureRepo(t)
	home := t.TempDir()

	// Sol redteam v7 S1/contextgraph gap-closure (Task #3, 2026-07-16) gave
	// the graph provider stage a real enforce.Plan, so its launch target
	// must be a real ELF binary now -- a #!/bin/sh script fixture (this
	// test's original shape) can no longer even launch under Landlock
	// without a separately declared interpreter closure, which
	// scopedCommandOutput deliberately does not offer (production graph
	// providers are compiled tools, not scripts). buildFakeCodegraphBinary
	// is the shared compiled-binary equivalent (see
	// v7_s1_stage_containment_test.go's cases 9/10, which hit this exact
	// gap first).
	statusJSON := func(fileCount string) string {
		return `{"version":"1.0.0","initialized":true,"projectPath":"","indexPath":"","fileCount":` + fileCount + `,"nodeCount":1,"edgeCount":1,"dbSizeBytes":1}`
	}
	providerA := buildFakeCodegraphBinary(t, "", "", statusJSON("1"))
	providerB := buildFakeCodegraphBinary(t, "", "", statusJSON("2"))

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)
	s6EnrollControllerTools(t)
	pin := func(path string) {
		if _, err := toolregistry.Enroll("codegraph", path); err != nil {
			t.Fatal(err)
		}
	}
	pin(providerA)
	t.Setenv("GOV_GRAPH_MODE", "auto")
	t.Setenv("GOV_GRAPH_PROVIDER", "codegraph")
	t.Setenv("GOV_GRAPH_BIN", providerA)

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))

	r1 := runGoverned(t, home, bin, c)
	if r1.Status != "APPROVED" {
		t.Fatalf("run 1 expected APPROVED, got status=%s message=%s", r1.Status, r1.Message)
	}

	// Swap the REGISTERED PROVIDER ITSELF -- a different verified binary at
	// a different path -- reporting a different fileCount but the same
	// version string, so only provider identity (not merely reported
	// content) distinguishes the two runs.
	pin(providerB)
	t.Setenv("GOV_GRAPH_BIN", providerB)

	r2 := runGoverned(t, home, bin, c)
	if r2.Replayed {
		t.Fatal("run 2 replayed a stale approval after the registered graph-provider binary itself was swapped for a different one -- replay identity does not bind graph-provider identity")
	}
	if r2.Graph.FileCount == r1.Graph.FileCount {
		t.Fatalf("run 2's graph snapshot (fileCount=%d) does not reflect the swapped provider's own output (expected different from run 1's fileCount=%d) -- the new provider may never have actually run", r2.Graph.FileCount, r1.Graph.FileCount)
	}
}
