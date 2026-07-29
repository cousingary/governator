//go:build redteam

package redteam

import (
	"path/filepath"
	"runtime"
	"sort"
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

// TestV14Case343OpenGapTestSkipFailsTheReleaseGate proves that the real
// manifest set contains no OPEN GAP exclusions and that an enrolled attack
// skipping without proven capability evidence fails the gate under
// RequireZeroSkips. S9d hardens this from the original synthetic one-case
// fixture (which passed tautologically with all 41 open gaps still excluded)
// to loading the actual release manifest set.
func TestV14Case343OpenGapTestSkipFailsTheReleaseGate(t *testing.T) {
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file path")
	}
	repoRoot, err := filepath.Abs(filepath.Join(filepath.Dir(thisFile), "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	corpusPath := filepath.Join(repoRoot, "internal", "redteam", "manifest.yaml")
	exactPaths, err := filepath.Glob(filepath.Join(repoRoot, "internal", "redteam", "manifests", "*.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(exactPaths) == 0 {
		t.Fatal("no exact manifests found")
	}
	sort.Strings(exactPaths)

	set, err := redteamgate.LoadManifestSet(corpusPath, exactPaths)
	if err != nil {
		t.Fatalf("LoadManifestSet: %v", err)
	}

	for _, e := range set.Corpus.Exclusions {
		if e.Status != "non-production" {
			t.Errorf("OPEN GAP exclusion still present: %q (status %q) — S9c drained all open gaps", e.Name, e.Status)
		}
	}

	capabilities := map[string]redteamgate.CapabilityRecord{
		"linux": {State: redteamgate.CapabilityPresent, Probe: "runtime.GOOS", Result: "linux"},
	}

	var attackNames []string
	for _, em := range set.ExactManifests {
		if em.Name == "red-team-attacks" {
			attackNames = em.Tests
			break
		}
	}
	if len(attackNames) == 0 {
		t.Fatal("red-team-attacks exact manifest not found or empty")
	}

	victim := attackNames[0]
	log := "=== RUN   " + victim + "\n--- SKIP: " + victim + " (0.00s)\n"
	var discovered []string
	for _, em := range set.ExactManifests {
		for _, n := range em.Tests {
			discovered = append(discovered, n)
			if n != victim {
				log += "=== RUN   " + n + "\n--- PASS: " + n + " (0.01s)\n"
			}
		}
	}
	for _, c := range set.Corpus.Cases {
		discovered = append(discovered, c.Name)
		log += "=== RUN   " + c.Name + "\n--- PASS: " + c.Name + " (0.01s)\n"
	}

	result := redteamgate.EvaluateWithOptions(set.Corpus, log, capabilities, redteamgate.Options{
		RequireZeroSkips: true,
		DiscoveredTests:  discovered,
		ExactManifests:   set.ExactManifests,
	})
	if result.OK {
		t.Fatalf("gate accepted an unaccounted skip of %q with linux proven present: %+v", victim, result)
	}
	found := false
	for _, s := range result.UnexpectedSkips {
		if s == victim {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected %q in UnexpectedSkips, got: %+v", victim, result.UnexpectedSkips)
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
