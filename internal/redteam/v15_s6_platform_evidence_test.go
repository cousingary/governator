//go:build redteam

// v15_s6_platform_evidence_test.go is rc8-upg15 Session 6's corpus, cases
// 388-389 (Sol15 P1-2 "Linux ARM64 is declared approving without native
// acceptance evidence"). Session 6 keyed platform approval on executed
// acceptance evidence rather than on GOOS alone: a platform is approving
// only if its GOOS is in the approving set AND it has a corresponding
// acceptance-evidence object. Cross-compiled platforms without native
// acceptance are non-approving with a specific reason string.
package redteam

import (
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

func TestV15Case388PlatformWithoutExecutedAcceptanceEvidenceIsNotApproving(t *testing.T) {
	empty := map[string]bool{}
	platforms := []string{"linux_amd64", "linux_arm64", "linux_386", "linux_riscv64"}
	for _, pid := range platforms {
		status, reason := redteamgate.ClassifyPlatformWithEvidence(pid, empty)
		if status == redteamgate.PlatformApproving {
			t.Fatalf("ClassifyPlatformWithEvidence(%q, no evidence) = approving; a platform without executed acceptance evidence must never be approving (Sol15 P1-2)", pid)
		}
		if reason == "" {
			t.Fatalf("ClassifyPlatformWithEvidence(%q, no evidence) returned empty reason; non-approving must carry a specific explanation", pid)
		}
	}

	withEvidence := map[string]bool{"linux_amd64": true}
	status, reason := redteamgate.ClassifyPlatformWithEvidence("linux_amd64", withEvidence)
	if status != redteamgate.PlatformApproving {
		t.Fatalf("ClassifyPlatformWithEvidence(\"linux_amd64\", {linux_amd64}) = %q (%q), want approving", status, reason)
	}
	status, reason = redteamgate.ClassifyPlatformWithEvidence("linux_arm64", withEvidence)
	if status == redteamgate.PlatformApproving {
		t.Fatalf("ClassifyPlatformWithEvidence(\"linux_arm64\", {linux_amd64}) = approving; evidence for a different platform must not transfer")
	}
	if reason == "" {
		t.Fatal("expected a specific reason for linux_arm64 non-approval")
	}

	status, _ = redteamgate.ClassifyPlatformWithEvidence("darwin_arm64", withEvidence)
	if status == redteamgate.PlatformApproving {
		t.Fatal("darwin_arm64 must not borrow linux_amd64 evidence")
	}
	status, reason = redteamgate.ClassifyPlatformWithEvidence("darwin_arm64", map[string]bool{"darwin_arm64": true})
	if status != redteamgate.PlatformApproving {
		t.Fatalf("darwin_arm64 WITH its own native S6b evidence = %q (%q), want approving", status, reason)
	}

	status, _ = redteamgate.ClassifyPlatformWithEvidence("windows_amd64", empty)
	if status != redteamgate.PlatformUnsupported {
		t.Fatalf("ClassifyPlatformWithEvidence(\"windows_amd64\") = %q, want unsupported", status)
	}
}

func TestV15Case389CrossCompiledLinuxArm64IsLabeledNonApprovingWithReason(t *testing.T) {
	empty := map[string]bool{}
	status, reason := redteamgate.ClassifyPlatformWithEvidence("linux_arm64", empty)
	if status != redteamgate.PlatformNonApproving {
		t.Fatalf("ClassifyPlatformWithEvidence(\"linux_arm64\", no evidence) = %q, want non-approving (Sol15 P1-2)", status)
	}
	if !strings.Contains(reason, "cross-compiled") {
		t.Fatalf("reason %q must name the specific degradation (cross-compiled), not a generic label", reason)
	}
	if !strings.Contains(reason, "acceptance") {
		t.Fatalf("reason %q must reference the missing acceptance evidence", reason)
	}

	amd64Evidence := map[string]bool{"linux_amd64": true}
	status, reason = redteamgate.ClassifyPlatformWithEvidence("linux_arm64", amd64Evidence)
	if status != redteamgate.PlatformNonApproving {
		t.Fatalf("linux_arm64 with only linux_amd64 evidence = %q, want non-approving", status)
	}
	if !strings.Contains(reason, "cross-compiled") {
		t.Fatalf("reason %q must still name cross-compilation as the specific cause", reason)
	}

	arm64Evidence := map[string]bool{"linux_arm64": true}
	status, reason = redteamgate.ClassifyPlatformWithEvidence("linux_arm64", arm64Evidence)
	if status != redteamgate.PlatformApproving {
		t.Fatalf("linux_arm64 WITH its own acceptance evidence = %q (%q), want approving -- the demotion is reversible by real evidence", status, reason)
	}
}
