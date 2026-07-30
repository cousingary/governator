package redteamgate

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// IntegrationOutcome is one integration-tier test's result parsed from a
// `go test -json` stream (Sol14 P0-2, rc7 Session 5).
type IntegrationOutcome struct {
	Name   string
	Result string // pass, fail, skip
}

// jsonTestEvent is the subset of `go test -json`'s event schema the
// integration gate reads. Every line of a -json stream is one such object.
type jsonTestEvent struct {
	Action  string `json:"Action"`
	Test    string `json:"Test"`
	Package string `json:"Package"`
}

// ParseJSONLog extracts one IntegrationOutcome per test from a `go test
// -json` stream. Only the final pass/fail/skip action per named test is
// retained; "run"/"output" events and package-level events (Test == "") are
// ignored. Unlike ParseVerboseLog (text), the JSON stream is the only
// evidence shape that can distinguish "the test passed" from "the test
// skipped" at the per-test level -- which is exactly why the prior
// integration tier (no -v, no -json) could hide a skip behind a package-
// level `ok` line.
func ParseJSONLog(log string) map[string]IntegrationOutcome {
	out := make(map[string]IntegrationOutcome)
	sc := bufio.NewScanner(strings.NewReader(log))
	sc.Buffer(make([]byte, 0, 64*1024), 64*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var ev jsonTestEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			// Non-JSON lines (e.g. a compiler error emitted before the JSON
			// stream, or the package's final FAIL/PASS line) are ignored:
			// the gate keys off structured test events only. A build failure
			// surfaces as a nonzero tier exit (release_tier_pipeline) and as
			// zero parsed tests (TestsRun == 0) here, which fails the gate.
			continue
		}
		if ev.Test == "" {
			continue
		}
		switch ev.Action {
		case "pass", "fail", "skip":
			out[ev.Test] = IntegrationOutcome{Name: ev.Test, Result: ev.Action}
		}
	}
	return out
}

// IntegrationResult is the integration-tier gate's structured verdict,
// mirroring Result (the redteam gate's verdict) so the release pipeline and
// evidence bundle treat both gates uniformly.
type IntegrationResult struct {
	OK              bool     `json:"ok"`
	TestsRun        int      `json:"tests_run"`
	SkippedTests    []string `json:"skipped_tests,omitempty"`
	FailedTests     []string `json:"failed_tests,omitempty"`
	MissingTests    []string `json:"missing_tests,omitempty"`
	NotPassing      []string `json:"not_passing,omitempty"`
	HarnessOK       bool     `json:"harness_ok,omitempty"`
	HarnessProblems []string `json:"harness_problems,omitempty"`
	Problems        []string `json:"problems,omitempty"`
}

// HarnessEvidence is the machine-readable record the integration-tier
// TestMain (internal/integrationharness) writes alongside the test run. The
// gate requires it (when supplied) to carry a real Governator binary
// identity, a proven sandbox mechanism, and a non-empty Assayer identity,
// so the release gate binds the tier to the exact components it claims to
// have exercised rather than to a self-asserted "ok".
type HarnessEvidence struct {
	GovernorBinarySHA256 string `json:"governor_binary_sha256"`
	GovernorBinarySource string `json:"governor_binary_source"`
	EnforceSupported     bool   `json:"enforce_supported"`
	SandboxMechanism     string `json:"sandbox_mechanism"`
	// SelfExeRoute must equal requiredSelfExeRoute (rc8-upg15 S3, Sol15
	// P0-4 B): enforce.SelfExeRouteFDOverride, duplicated here as a literal
	// so this package need not import internal/enforce.
	SelfExeRoute           string `json:"self_exe_route,omitempty"`
	AssayerSource          string `json:"assayer_source"`
	AssayerCommit          string `json:"assayer_commit"`
	AssayerVersion         string `json:"assayer_version,omitempty"`
	AssayerTag             string `json:"assayer_tag,omitempty"`
	AssayerPackageTreeHash string `json:"assayer_package_tree_hash,omitempty"`
	AssayerSchemaVersion   string `json:"assayer_schema_version,omitempty"`
	AssayerPythonRuntime   string `json:"assayer_python_runtime,omitempty"`
	AssayerClean           bool   `json:"assayer_clean"`
	FailClosedReason       string `json:"fail_closed_reason,omitempty"`
}

// IntegrationOptions supplies the release-bound facts that cannot be learned
// from the test log alone. In particular, the expected Governor binary hash
// binds every package TestMain's SelfExeOverride to the exact candidate the
// release built before starting the tier.
type IntegrationOptions struct {
	HarnessEvidencePath          string
	ExpectedGovernorBinarySHA256 string
	ExpectedEvidencePackages     []string
	ExpectedAssayerCommit        string
}

// requiredSelfExeRoute is checked unconditionally against every evidence
// record's SelfExeRoute (rc8-upg15 S3, Sol15 P0-4 B): the mandatory
// integration tier must always exercise the fd-backed self-exec route, never
// SelfExeOverride's sealed-copy pathname route. Must equal
// enforce.SelfExeRouteFDOverride -- duplicated as a literal to avoid this
// package importing internal/enforce.
const requiredSelfExeRoute = "fd-override"

// EvaluateIntegration checks a parsed `go test -json` integration-tier log
// against the exact set of expected test names. It enforces (Sol14 P0-2):
//   - the tier ran at least one test (nonzero count) -- a TestMain that
//     fail-closed before running any test, or a mis-scoped package list,
//     cannot pass as an empty green tier;
//   - zero skipped tests -- the prior defect: the sole integration test
//     always skipped behind a package-level `ok` line because the release
//     command used neither -v nor -json;
//   - zero failed tests;
//   - every expected test name is present and passed -- a tier that ran
//     fewer tests than the compiler-determined expected set (e.g. TestMain
//     aborted partway, or a test was accidentally re-tagged out of the
//     tier) is a coverage gap, not a pass.
//
// When harnessEvidencePath is non-empty, EvaluateIntegration reads and
// validates that record too: a FailClosedReason is a hard fail (the tier
// must not pass on a recorded blocking gap), and the Governor binary
// identity, sandbox mechanism, and Assayer identity must all be present and
// non-default. S6 tightens the Assayer check to require the exact released
// checkout; S5 only requires one was recorded.
func EvaluateIntegration(log string, expected []string, harnessEvidencePath string) IntegrationResult {
	return EvaluateIntegrationWithOptions(log, expected, IntegrationOptions{
		HarnessEvidencePath: harnessEvidencePath,
	})
}

// EvaluateIntegrationWithOptions is EvaluateIntegration with release-bound
// candidate and package evidence requirements. The wrapper above remains for
// callers that only need log/evidence validation outside a release cut.
func EvaluateIntegrationWithOptions(log string, expected []string, opts IntegrationOptions) IntegrationResult {
	outcomes := ParseJSONLog(log)
	var res IntegrationResult
	for _, o := range outcomes {
		res.TestsRun++
		switch o.Result {
		case "skip":
			res.SkippedTests = append(res.SkippedTests, o.Name)
		case "fail":
			res.FailedTests = append(res.FailedTests, o.Name)
		}
	}
	for _, name := range expected {
		o, ok := outcomes[name]
		if !ok {
			res.MissingTests = append(res.MissingTests, name)
		} else if o.Result != "pass" {
			res.NotPassing = append(res.NotPassing, name)
		}
	}
	sort.Strings(res.SkippedTests)
	sort.Strings(res.FailedTests)
	sort.Strings(res.MissingTests)
	sort.Strings(res.NotPassing)

	res.HarnessOK = true
	if opts.HarnessEvidencePath != "" {
		evidences, packages, ok := readHarnessEvidenceDir(opts.HarnessEvidencePath)
		if !ok {
			res.HarnessOK = false
			res.HarnessProblems = append(res.HarnessProblems, fmt.Sprintf("harness evidence directory %s could not be read (expected one %s/<pkg>.json per integration package)", opts.HarnessEvidencePath, opts.HarnessEvidencePath))
		} else if len(evidences) == 0 {
			res.HarnessOK = false
			res.HarnessProblems = append(res.HarnessProblems, fmt.Sprintf("harness evidence directory %s contains no *.json records (the integration TestMain never recorded evidence)", opts.HarnessEvidencePath))
		} else {
			expectedPackages := make(map[string]bool, len(opts.ExpectedEvidencePackages))
			for _, pkg := range opts.ExpectedEvidencePackages {
				expectedPackages[pkg] = true
			}
			seenPackages := make(map[string]bool, len(packages))
			for i := range evidences {
				hev := evidences[i]
				pkg := packages[i]
				seenPackages[pkg] = true
				check := func(cond bool, msg string) {
					if !cond {
						res.HarnessOK = false
						res.HarnessProblems = append(res.HarnessProblems, pkg+": "+msg)
					}
				}
				check(hev.FailClosedReason == "", fmt.Sprintf("TestMain recorded a fail-closed gap: %s", hev.FailClosedReason))
				check(hev.EnforceSupported, "evidence records enforce_supported=false (real sandbox not established)")
				check(strings.TrimSpace(hev.GovernorBinarySHA256) != "", "evidence records no governator_binary_sha256")
				check(hev.GovernorBinarySource == "env" || hev.GovernorBinarySource == "built", fmt.Sprintf("unrecognized governator_binary_source %q", hev.GovernorBinarySource))
				if opts.ExpectedGovernorBinarySHA256 != "" {
					check(hev.GovernorBinarySHA256 == opts.ExpectedGovernorBinarySHA256, "evidence governator_binary_sha256 does not match the exact rc-candidate binary")
					// rc8-upg15 S3 (Sol15 P0-4, "integration executable from
					// unpackaged path is rejected"): a release cut always
					// supplies ExpectedGovernorBinarySHA256 (the archive-
					// extracted, release-bound candidate's hash). In that
					// context governor_binary_source must be "env" -- the
					// release passed GOV_INTEGRATION_GOV_BIN explicitly -- and
					// never "built", which means the TestMain fell back to
					// compiling its own throwaway candidate for a standalone
					// developer run. A matching hash alone is not proof of
					// packaged provenance.
					check(hev.GovernorBinarySource == "env", fmt.Sprintf("release-bound integration evidence records governor_binary_source %q, want \"env\" (the release-extracted, packaged candidate) -- a self-built/unpackaged binary must never satisfy the mandatory release gate", hev.GovernorBinarySource))
				}
				check(hev.SandboxMechanism == "landlock+unshare (enforce.Supported)", fmt.Sprintf("evidence records non-proven sandbox_mechanism %q", hev.SandboxMechanism))
				check(hev.SelfExeRoute == requiredSelfExeRoute, fmt.Sprintf("evidence records self_exe_route %q, want %q (the production fd-backed self-exec route was not exercised)", hev.SelfExeRoute, requiredSelfExeRoute))
				// S5 requires an Assayer identity was recorded; S6 will require it
				// equal the released Assayer checkout. The contextgraph package
				// legitimately records assayer_source "n/a (contextgraph)" with an
				// empty commit, so a non-empty source satisfies "recorded" here
				// even when the commit is blank.
				check(strings.TrimSpace(hev.AssayerSource) != "", "evidence records no assayer_source (Assayer identity not recorded)")
				if pkg == "assay" {
					check(strings.TrimSpace(hev.AssayerCommit) != "", "evidence records no assayer_commit for the real Assayer bridge")
					if opts.ExpectedAssayerCommit != "" {
						check(hev.AssayerSource == "ASSAYER_REPO", fmt.Sprintf("evidence assayer_source %q is not the required ASSAYER_REPO checkout", hev.AssayerSource))
						check(hev.AssayerCommit == opts.ExpectedAssayerCommit, "evidence assayer_commit does not match the immutable release Assayer commit")
						check(strings.TrimSpace(hev.AssayerVersion) != "", "evidence records no Assayer version")
						check(strings.TrimSpace(hev.AssayerTag) != "", "evidence records no Assayer tag")
						check(strings.TrimSpace(hev.AssayerPackageTreeHash) != "", "evidence records no Assayer package-tree hash")
						check(strings.TrimSpace(hev.AssayerSchemaVersion) != "", "evidence records no Assayer schema version")
						check(strings.TrimSpace(hev.AssayerPythonRuntime) != "", "evidence records no Assayer Python runtime")
						check(hev.AssayerClean, "evidence reports a dirty Assayer checkout")
					}
				}
			}
			for pkg := range expectedPackages {
				if !seenPackages[pkg] {
					res.HarnessOK = false
					res.HarnessProblems = append(res.HarnessProblems, fmt.Sprintf("missing harness evidence for required integration package %q", pkg))
				}
			}
			for pkg := range seenPackages {
				if len(expectedPackages) > 0 && !expectedPackages[pkg] {
					res.HarnessOK = false
					res.HarnessProblems = append(res.HarnessProblems, fmt.Sprintf("unexpected harness evidence package %q", pkg))
				}
			}
		}
	}

	res.OK = res.TestsRun > 0 &&
		len(res.SkippedTests) == 0 &&
		len(res.FailedTests) == 0 &&
		len(res.MissingTests) == 0 &&
		len(res.NotPassing) == 0 &&
		res.HarnessOK

	if res.TestsRun == 0 {
		res.Problems = append(res.Problems, "integration tier ran zero tests (TestMain fail-closed, build failure, or empty package scope)")
	}
	if len(res.SkippedTests) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("integration tier had skipped test(s) -- a skip is never a pass (P0-2): %s", strings.Join(res.SkippedTests, ", ")))
	}
	if len(res.FailedTests) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("integration tier had failed test(s): %s", strings.Join(res.FailedTests, ", ")))
	}
	if len(res.MissingTests) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("expected integration test(s) did not run: %s", strings.Join(res.MissingTests, ", ")))
	}
	if len(res.NotPassing) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("expected integration test(s) did not pass: %s", strings.Join(res.NotPassing, ", ")))
	}
	res.Problems = append(res.Problems, res.HarnessProblems...)
	return res
}

// VerifyArtifactUnchanged fails when currentSHA256 no longer equals
// recordedSHA256 for the named artifact -- the release-mandatory guard
// against any rebuild happening after the integration tier already bound an
// artifact's identity into the release checkpoint (rc8-upg15 S3, Sol15
// P0-4: "rerun final acceptance after integration without rebuilding").
// label names the artifact in the error for release operators (e.g.
// "linux_amd64 archive", "host executable"). release.sh's own no-rebuild
// guard re-hashes each build artifact immediately before writing
// build-manifest.json and compares against the hash recorded at build time,
// following this exact contract.
func VerifyArtifactUnchanged(label, recordedSHA256, currentSHA256 string) error {
	if strings.TrimSpace(recordedSHA256) == "" {
		return fmt.Errorf("%s: no recorded sha256 to compare against", label)
	}
	if strings.TrimSpace(currentSHA256) == "" {
		return fmt.Errorf("%s: no current sha256 to compare", label)
	}
	if recordedSHA256 != currentSHA256 {
		return fmt.Errorf("%s: sha256 changed from %s to %s -- a rebuild occurred after the integration tier bound this artifact's identity", label, recordedSHA256, currentSHA256)
	}
	return nil
}

func readHarnessEvidenceDir(dir string) ([]HarnessEvidence, []string, bool) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, false
	}
	var evidences []HarnessEvidence
	var packages []string
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}
		var hev HarnessEvidence
		if err := json.Unmarshal(data, &hev); err != nil {
			continue
		}
		evidences = append(evidences, hev)
		packages = append(packages, strings.TrimSuffix(entry.Name(), ".json"))
	}
	return evidences, packages, true
}
