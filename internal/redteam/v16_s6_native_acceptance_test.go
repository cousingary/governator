//go:build redteam

// v16_s6_native_acceptance_test.go is the v16-release Session 6 corpus, cases
// 401-402 (R4: "every published archive carries executed native acceptance
// evidence, or is not published"). Session 6 is where standing rule 12's
// constraint lifts: real macos-latest (arm64) and ubuntu-24.04-arm runners
// execute native acceptance evidence, so approval keys on executed evidence
// rather than on this WSL host alone.
//
// These two cases pin the evidence-based publication gate that makes that
// promotion honest: a platform is approving only with executed native
// acceptance evidence, and an archive for a platform absent from the approving
// set is refused at publication. They are mutation-verified (strip the
// evidence, confirm the demotion) so the classifier cannot silently widen to
// approve a platform the evidence never covered.
//
// They reflect the CURRENT true state: darwin remains non-approving (it sits
// in degradedPlatforms until real native evidence promotes it) and only linux
// platforms are eligible for approval-with-evidence. The day darwin's evidence
// lands and it moves into approvingPlatforms, these cases' darwin assertions
// must be revisited -- but the strip-mutation invariant (no evidence, no
// approval) holds for every eligible platform forever.
package redteam

import (
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

// TestV16Case401PlatformWithoutExecutedAcceptanceEvidenceIsNeverApproving
// (R4 / Sol15 P1-2): a platform declared approving without executed native
// acceptance evidence fails classification. Mutation-verified by stripping the
// evidence from an approving platform and confirming it demotes to
// non-approving with a specific reason -- the evidence is load-bearing, not
// decorative. This holds for every platform eligible for approval (linux_*),
// and evidence for one platform never transfers to another.
func TestV16Case401PlatformWithoutExecutedAcceptanceEvidenceIsNeverApproving(t *testing.T) {
	// A platform eligible for approval (linux GOOS) WITH its own evidence is
	// approving; this is the only state the classifier may call approving.
	evidence := map[string]bool{"linux_amd64": true, "linux_arm64": true}
	for _, pid := range []string{"linux_amd64", "linux_arm64"} {
		status, reason := redteamgate.ClassifyPlatformWithEvidence(pid, evidence)
		if status != redteamgate.PlatformApproving {
			t.Fatalf("ClassifyPlatformWithEvidence(%q, with own evidence) = %q (%q), want approving", pid, status, reason)
		}
	}

	// MUTATION: strip each platform's evidence and confirm it demotes to
	// non-approving. Evidence is load-bearing -- removing it must never leave
	// the platform approving.
	for _, pid := range []string{"linux_amd64", "linux_arm64"} {
		stripped := map[string]bool{}
		for k, v := range evidence {
			if k != pid {
				stripped[k] = v
			}
		}
		status, reason := redteamgate.ClassifyPlatformWithEvidence(pid, stripped)
		if status == redteamgate.PlatformApproving {
			t.Fatalf("ClassifyPlatformWithEvidence(%q, evidence STRIPPED) = approving; removing executed acceptance evidence must demote the platform (mutation verifies evidence is load-bearing)", pid)
		}
		if reason == "" {
			t.Fatalf("ClassifyPlatformWithEvidence(%q, evidence stripped) returned empty reason; the demotion must carry a specific explanation", pid)
		}
		if !strings.Contains(reason, "cross-compiled") {
			t.Fatalf("reason %q must name cross-compilation as the specific cause of the demotion, not a generic label", reason)
		}
	}

	// Evidence does not transfer: linux_amd64 evidence must not approve linux_arm64.
	amd64Only := map[string]bool{"linux_amd64": true}
	status, reason := redteamgate.ClassifyPlatformWithEvidence("linux_arm64", amd64Only)
	if status == redteamgate.PlatformApproving {
		t.Fatalf("ClassifyPlatformWithEvidence(\"linux_arm64\", {linux_amd64}) = approving; evidence for a different platform must not transfer")
	}
	if reason == "" {
		t.Fatal("expected a specific reason for linux_arm64 non-approval under linux_amd64-only evidence")
	}

	// darwin is ineligible for approval regardless of evidence: it sits in
	// degradedPlatforms until real native acceptance evidence promotes it
	// (Sol12 P1-1). Asserting this here keeps the promotion honest -- the day
	// darwin moves to approvingPlatforms this assertion must change, and the
	// strip-mutation above must then cover it too.
	status, _ = redteamgate.ClassifyPlatformWithEvidence("darwin_arm64", map[string]bool{"darwin_arm64": true})
	if status == redteamgate.PlatformApproving {
		t.Fatal("ClassifyPlatformWithEvidence(\"darwin_arm64\", {darwin_arm64}) = approving; darwin must remain non-approving until real native evidence promotes it out of degradedPlatforms (Sol12 P1-1)")
	}

	// An unknown GOOS is unsupported, never silently approving.
	status, _ = redteamgate.ClassifyPlatformWithEvidence("windows_amd64", map[string]bool{})
	if status != redteamgate.PlatformUnsupported {
		t.Fatalf("ClassifyPlatformWithEvidence(\"windows_amd64\") = %q, want unsupported", status)
	}
}

// TestV16Case402ArchivePublishedForPlatformAbsentFromApprovingSetFailsGate
// (R4): an archive published for a platform absent from the approving set
// fails the pre-publication check. PublicationDecision is the gate that makes
// ClassifyPlatformWithEvidence load-bearing at the point an archive leaves the
// release: a non-approving platform's archive is refused with a named error,
// never silently shipped marked approving. Mutation-verified by adding the
// platform's evidence and confirming the refusal clears.
func TestV16Case402ArchivePublishedForPlatformAbsentFromApprovingSetFailsGate(t *testing.T) {
	// An evidence-less linux_arm64 archive is refused: it is eligible by GOOS
	// but lacks executed native acceptance evidence.
	empty := map[string]bool{}
	err := redteamgate.PublicationDecision("linux_arm64", empty)
	if err == nil {
		t.Fatal("PublicationDecision(\"linux_arm64\", no evidence) = nil; an archive for an evidence-less platform must be refused")
	}
	if !strings.HasPrefix(err.Error(), "PUBLICATION_REFUSED:") {
		t.Fatalf("refusal error %q must carry the PUBLICATION_REFUSED: prefix so the cause is named at the publication boundary", err.Error())
	}

	// MUTATION: add linux_arm64's evidence and the refusal clears -- the gate
	// is reversible by real evidence, not a permanent block.
	withEvidence := map[string]bool{"linux_arm64": true}
	if err := redteamgate.PublicationDecision("linux_arm64", withEvidence); err != nil {
		t.Fatalf("PublicationDecision(\"linux_arm64\", {linux_arm64}) = %v, want nil -- real native acceptance evidence must clear the publication gate", err)
	}

	// Evidence does not transfer across platforms at the publication boundary
	// either: linux_amd64 evidence must not publish a linux_arm64 archive.
	amd64Only := map[string]bool{"linux_amd64": true}
	if err := redteamgate.PublicationDecision("linux_arm64", amd64Only); err == nil {
		t.Fatal("PublicationDecision(\"linux_arm64\", {linux_amd64}) = nil; evidence for a different platform must not clear publication")
	}

	// darwin is refused at publication regardless of evidence (degradedPlatforms).
	if err := redteamgate.PublicationDecision("darwin_arm64", map[string]bool{"darwin_arm64": true}); err == nil {
		t.Fatal("PublicationDecision(\"darwin_arm64\", {darwin_arm64}) = nil; darwin must be refused at publication until it leaves degradedPlatforms")
	}

	// An unsupported platform is refused outright, never defaulting to approving.
	if err := redteamgate.PublicationDecision("freebsd_amd64", map[string]bool{"freebsd_amd64": true}); err == nil {
		t.Fatal("PublicationDecision(\"freebsd_amd64\") = nil; an unsupported platform must be refused at publication, never silently approved")
	}
}
