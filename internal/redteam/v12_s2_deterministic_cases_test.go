//go:build redteam

package redteam

import (
	"context"
	"testing"
	"time"

	"github.com/cousingary/governator/internal/containment"
	"github.com/cousingary/governator/internal/redteamgate"
)

// v12_s2_deterministic_cases_test.go is the Sol v12 rc5 Session 2
// release-truth corpus (agents/governator-sol-upgrade12-rc5-plan.md Session 2,
// report P0-1): the mutually-exclusive-cases defect and the case-8 timing
// fixture. Case 9 proves the live-systemd success path (case 13) stays
// correctly bound to the has_systemd_user capability attestation now that its
// mutually-exclusive partner (case 12) is deterministic; case 10 proves the
// case-8 readiness gate makes extinction fire only after a confirmed
// blocking-read state. Both are deterministic (no host-dependent skip).
// Enrolled by exact name in internal/redteam/manifest.yaml (cases 207-208).

// TestV12Case9LiveSystemdSuccessPathRequiredInAttestation proves that case 13
// (TestV10Case13RealSystemdUserScopeLaunchExecutesExactVerifiedTarget -- the
// REAL live-systemd launch, intentionally kept host-gated by P0-1) stays
// correctly required-in-attestation after Session 2 made case 12
// deterministic. A single host still cannot satisfy both case 12 (now
// deterministic, runs everywhere) and case 13 (genuinely needs a live systemd
// --user manager); case 13 therefore remains conditional on has_systemd_user,
// and the tri-state capability gate must: authorize its skip only when
// has_systemd_user is proven ABSENT, refuse when it is proven PRESENT (the
// case should have run for real), and refuse on CAPABILITY_EVIDENCE_INCOMPLETE
// when the predicate is unproven. Deterministic: manipulates the manifest and
// capability record in-memory; no live systemd interaction, no host skip.
func TestV12Case9LiveSystemdSuccessPathRequiredInAttestation(t *testing.T) {
	const case13 = "TestV10Case13RealSystemdUserScopeLaunchExecutesExactVerifiedTarget"

	// Part A: the REAL manifest must still declare case 13 conditional on
	// has_systemd_user (the live-systemd success path is NOT collapsed into a
	// deterministic case -- it stays the real capability-attestation gate).
	m, err := redteamgate.LoadManifest("manifest.yaml")
	if err != nil {
		t.Fatalf("load real manifest: %v", err)
	}
	var entry *redteamgate.CaseEntry
	for i := range m.Cases {
		if m.Cases[i].Name == case13 {
			entry = &m.Cases[i]
			break
		}
	}
	if entry == nil {
		t.Fatalf("manifest does not enroll case 13 (%s)", case13)
	}
	if !entry.Required {
		t.Fatalf("case 13 must remain required (it is the live-systemd success path)")
	}
	if !entry.Conditional || entry.AllowedSkip == nil || entry.AllowedSkip.Predicate != "has_systemd_user" {
		t.Fatalf("case 13 must remain conditional on has_systemd_user, got conditional=%v allowed_skip=%+v", entry.Conditional, entry.AllowedSkip)
	}

	// Part B: the capability-attestation binding, isolated to case 13 so the
	// many other corpus cases do not pollute the tallies. Mirrors the real
	// declaration exactly.
	isolated := redteamgate.Manifest{
		Cases: []redteamgate.CaseEntry{{
			Case: entry.Case, Name: case13, Required: true, Conditional: true,
			AllowedSkip: &redteamgate.AllowedSkip{Predicate: "has_systemd_user", Reason: entry.AllowedSkip.Reason},
		}},
	}
	log := "=== RUN   " + case13 + "\n            " + entry.AllowedSkip.Reason + "\n--- SKIP: " + case13 + " (0.00s)\n"
	inv := []string{case13}

	// has_systemd_user proven ABSENT: the skip is the sanctioned exception.
	absent := redteamgate.EvaluateWithOptions(isolated, log,
		map[string]redteamgate.CapabilityRecord{"has_systemd_user": {State: redteamgate.CapabilityAbsent}},
		redteamgate.Options{DiscoveredTests: inv})
	if !absent.OK {
		t.Fatalf("case 13 skip must be authorized when has_systemd_user is proven absent: %+v", absent)
	}

	// has_systemd_user proven PRESENT: the case should have run for real; the
	// skip is unexpected and must block the release.
	present := redteamgate.EvaluateWithOptions(isolated, log,
		map[string]redteamgate.CapabilityRecord{"has_systemd_user": {State: redteamgate.CapabilityPresent}},
		redteamgate.Options{DiscoveredTests: inv})
	if present.OK {
		t.Fatalf("case 13 skip must NOT be authorized when has_systemd_user is proven present (the live-systemd host should have run it): %+v", present)
	}
	if !contains(present.UnexpectedSkips, case13) {
		t.Fatalf("expected case 13 in UnexpectedSkips when has_systemd_user is present, got %+v", present)
	}

	// has_systemd_user unproven (missing): CAPABILITY_EVIDENCE_INCOMPLETE.
	unknown := redteamgate.EvaluateWithOptions(isolated, log,
		map[string]redteamgate.CapabilityRecord{},
		redteamgate.Options{DiscoveredTests: inv})
	if unknown.OK {
		t.Fatalf("case 13 must block the release when has_systemd_user is unproven: %+v", unknown)
	}
	if !incompleteFor(unknown.IncompleteCapabilities, "has_systemd_user") {
		t.Fatalf("expected CAPABILITY_EVIDENCE_INCOMPLETE for has_systemd_user, got %+v", unknown)
	}
}

// TestV12Case10ExtinctionFiresOnlyAfterConfirmedBlockingRead proves the
// explicit synchronization primitive (P0-1) that replaces case 8's timing
// assumption: Scope.Extinguish blocks at its kill-boundary on
// containment.ExtinguishGateForTesting and cannot proceed until that gate
// returns, so extinction fires only AFTER the fixture confirms the descendant
// reached its intended blocking-read state. A degraded scope (no systemd,
// cgroup, Landlock, or hangfuse needed) is sufficient to exercise the gate, so
// this case is fully deterministic and never host-skips.
func TestV12Case10ExtinctionFiresOnlyAfterConfirmedBlockingRead(t *testing.T) {
	ready := make(chan struct{})
	gateFired := make(chan struct{}, 1)
	containment.ExtinguishGateForTesting = func() error {
		gateFired <- struct{}{}
		<-ready
		return nil
	}
	t.Cleanup(func() { containment.ExtinguishGateForTesting = nil })

	containment.ForceDegradedScopeForTesting.Store(true)
	t.Cleanup(func() { containment.ForceDegradedScopeForTesting.Store(false) })

	scope, err := containment.NewScope("v12-case10", false, containment.ContainmentEnvironment{})
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}

	type extResult struct {
		err error
	}
	done := make(chan extResult, 1)
	go func() {
		_, err := scope.Extinguish(context.Background(), 5*time.Second, t.TempDir())
		done <- extResult{err}
	}()

	// Confirm the gate actually fired, then prove Extinguish has NOT returned
	// while the blocking-read state remains unconfirmed (ready still open).
	select {
	case <-gateFired:
	case <-time.After(2 * time.Second):
		t.Fatal("Extinguish never reached the pre-extinction readiness gate within 2s")
	}
	select {
	case <-done:
		t.Fatal("Extinguish completed BEFORE the blocking-read state was confirmed (the gate must block extinction until readiness)")
	case <-time.After(300 * time.Millisecond):
		// good: still blocked in the gate, exactly as required.
	}

	// Confirm the blocking-read state (release the gate); extinction may now fire.
	close(ready)
	select {
	case r := <-done:
		// A degraded scope with no launched process extinguishes cleanly once
		// the gate releases; the point of this case is the ordering, not the
		// kill outcome, so any non-nil error here is acceptable as long as it
		// is not a panic -- but we expect nil.
		if r.err != nil {
			t.Fatalf("Extinguish returned an unexpected error after the gate released: %v", r.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Extinguish did not complete after the blocking-read state was confirmed (the gate released but extinction never finished)")
	}
}
