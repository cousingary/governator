//go:build redteam

package redteam

import (
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

// TestV14Case343OpenGapTestSkipFailsTheReleaseGate proves that an attack
// enrolled as required cannot retain the old exclusion-era behavior of
// skipping while the release gate stays green.
func TestV14Case343OpenGapTestSkipFailsTheReleaseGate(t *testing.T) {
	manifest := redteamgate.Manifest{Cases: []redteamgate.CaseEntry{{
		Case:     343,
		Name:     "TestLegacyOpenGap",
		Required: true,
		Status:   "implemented",
	}}}
	log := "=== RUN   TestLegacyOpenGap\n--- SKIP: TestLegacyOpenGap (0.00s)\n"
	result := redteamgate.Evaluate(manifest, log, nil)
	if result.OK || len(result.UnexpectedSkips) != 1 || result.UnexpectedSkips[0] != "TestLegacyOpenGap" {
		t.Fatalf("required open-gap skip was accepted: %+v", result)
	}
}

// TestV14Case344UnmanifestedIntegrationSecuritySkipFailsTheReleaseGate
// proves the JSON integration gate rejects every skip in the tier, not only
// skips among its expected-name list.
func TestV14Case344UnmanifestedIntegrationSecuritySkipFailsTheReleaseGate(t *testing.T) {
	log := `{"Action":"run","Package":"example/integration","Test":"TestRequiredIntegration"}
{"Action":"pass","Package":"example/integration","Test":"TestRequiredIntegration"}
{"Action":"run","Package":"example/integration","Test":"TestHiddenSecurityCheck"}
{"Action":"skip","Package":"example/integration","Test":"TestHiddenSecurityCheck"}`
	result := redteamgate.EvaluateIntegration(log, []string{"TestRequiredIntegration"}, "")
	if result.OK || len(result.SkippedTests) != 1 || result.SkippedTests[0] != "TestHiddenSecurityCheck" {
		t.Fatalf("unmanifested integration security skip was accepted: %+v", result)
	}
}
