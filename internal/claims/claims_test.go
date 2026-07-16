package claims

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadRejectsUnknownFields(t *testing.T) {
	path := writeFile(t, t.TempDir(), "claims.yaml", `
version: 1
claims:
  - id: x
    title: t
    claimed_maturity: implemented
    implementation: []
    tests: []
    not_a_real_field: oops
`)
	if _, err := Load(path); err == nil {
		t.Fatal("expected error for unknown field, got nil")
	}
}

func TestLoadRejectsDuplicateID(t *testing.T) {
	path := writeFile(t, t.TempDir(), "claims.yaml", `
version: 1
claims:
  - id: dup
    title: a
    claimed_maturity: implemented
    implementation: []
    tests: []
  - id: dup
    title: b
    claimed_maturity: implemented
    implementation: []
    tests: []
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("expected duplicate id error, got %v", err)
	}
}

func TestLoadRejectsInvalidClaimedMaturity(t *testing.T) {
	path := writeFile(t, t.TempDir(), "claims.yaml", `
version: 1
claims:
  - id: x
    title: t
    claimed_maturity: definitely-shipped
    implementation: []
    tests: []
`)
	if _, err := Load(path); err == nil || !strings.Contains(err.Error(), "claimed_maturity") {
		t.Fatalf("expected claimed_maturity validation error, got %v", err)
	}
}

func TestVerifyImplementedMissingSymbolCapsAtUnimplemented(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pkg/foo.go", "package pkg\n\nfunc RealFunc() {}\n")

	doc := Document{Claims: []Claim{{
		ID:              "missing-symbol",
		ClaimedMaturity: MaturityImplemented,
		Implementation:  []FileSymbols{{File: "pkg/foo.go", Symbols: []string{"DoesNotExist"}}},
		Tests:           []FileFuncs{{File: "pkg/foo.go", Funcs: nil}},
	}}}

	results, err := Verify(root, doc)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	r := results[0]
	if r.ComputedMaturity != MaturityUnimplemented {
		t.Fatalf("computed = %s, want unimplemented", r.ComputedMaturity)
	}
	if r.OK() {
		t.Fatal("expected OK() to be false when claim overclaims implemented")
	}
	if !containsSubstring(r.Problems, "DoesNotExist") {
		t.Fatalf("expected a problem naming the missing symbol, got %v", r.Problems)
	}
}

func TestVerifyTestedMissingFuncCapsAtImplemented(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pkg/foo.go", "package pkg\n\nfunc RealFunc() {}\n")
	writeFile(t, root, "pkg/foo_test.go", "package pkg\n\nfunc TestSomethingElse(t *testing.T) {}\n")

	doc := Document{Claims: []Claim{{
		ID:              "missing-test",
		ClaimedMaturity: MaturityTested,
		Implementation:  []FileSymbols{{File: "pkg/foo.go", Symbols: []string{"RealFunc"}}},
		Tests:           []FileFuncs{{File: "pkg/foo_test.go", Funcs: []string{"TestRealFunc"}}},
	}}}

	results, err := Verify(root, doc)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	r := results[0]
	if r.ComputedMaturity != MaturityImplemented {
		t.Fatalf("computed = %s, want implemented", r.ComputedMaturity)
	}
	if r.OK() {
		t.Fatal("expected OK() false: claim asserts tested but func is missing")
	}
}

func TestVerifyAcceptedMissingArtifactCapsAtTested(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pkg/foo.go", "package pkg\n\nfunc RealFunc() {}\n")
	writeFile(t, root, "pkg/foo_test.go", "package pkg\n\nfunc TestRealFunc(t *testing.T) {}\n")

	doc := Document{Claims: []Claim{{
		ID:                  "missing-acceptance",
		ClaimedMaturity:     MaturityAccepted,
		Implementation:      []FileSymbols{{File: "pkg/foo.go", Symbols: []string{"RealFunc"}}},
		Tests:               []FileFuncs{{File: "pkg/foo_test.go", Funcs: []string{"TestRealFunc"}}},
		AcceptanceArtifacts: []ArtifactRef{{Path: "evidence/nope.json"}},
	}}}

	results, err := Verify(root, doc)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	r := results[0]
	if r.ComputedMaturity != MaturityTested {
		t.Fatalf("computed = %s, want tested", r.ComputedMaturity)
	}
	if r.OK() {
		t.Fatal("expected OK() false: claim asserts accepted but artifact is missing")
	}
}

// TestVerifyTestedClaimIsUnaffectedByMissingAcceptanceEvidence confirms a
// claim that only asserts "tested" is not penalized for lacking acceptance
// artifacts it never promised to have (the early-stop behavior in
// verifyOne).
func TestVerifyTestedClaimIsUnaffectedByMissingAcceptanceEvidence(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "pkg/foo.go", "package pkg\n\nfunc RealFunc() {}\n")
	writeFile(t, root, "pkg/foo_test.go", "package pkg\n\nfunc TestRealFunc(t *testing.T) {}\n")

	doc := Document{Claims: []Claim{{
		ID:              "tested-only",
		ClaimedMaturity: MaturityTested,
		Implementation:  []FileSymbols{{File: "pkg/foo.go", Symbols: []string{"RealFunc"}}},
		Tests:           []FileFuncs{{File: "pkg/foo_test.go", Funcs: []string{"TestRealFunc"}}},
	}}}

	results, err := Verify(root, doc)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	r := results[0]
	if !r.OK() || r.ComputedMaturity != MaturityTested {
		t.Fatalf("expected OK tested result, got %+v", r)
	}
	if len(r.Problems) != 0 {
		t.Fatalf("expected no problems for a claim that never asserted acceptance, got %v", r.Problems)
	}
}

func TestVerifyShippedRequiresAncestorCommitEvidenceAndHistoricalSymbol(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "test@example.com")
	runGit(t, root, "config", "user.name", "test")

	writeFile(t, root, "pkg/foo.go", "package pkg\n\nfunc OldFunc() {}\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "first")
	firstCommit := runGitOutput(t, root, "rev-parse", "HEAD")

	writeFile(t, root, "pkg/foo.go", "package pkg\n\nfunc OldFunc() {}\n\nfunc NewFunc() {}\n")
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "second")

	writeFile(t, root, "evidence/release.json", `{
		"release": {"source_commit": "`+firstCommit+`"},
		"binaries": {"targets": [{"platform": "linux_amd64", "sha256": "deadbeef"}]}
	}`)

	base := Claim{
		Implementation: []FileSymbols{{File: "pkg/foo.go", Symbols: []string{"OldFunc"}}},
		Tests:          []FileFuncs{{File: "pkg/foo.go", Funcs: nil}},
	}

	t.Run("shipped when commit is ancestor with matching evidence and symbol present historically", func(t *testing.T) {
		c := base
		c.ID = "shipped-ok"
		c.ClaimedMaturity = MaturityShipped
		c.AcceptanceArtifacts = []ArtifactRef{{Path: "evidence/release.json"}}
		c.BinaryBuildEvidence = &BinaryEvidence{EvidenceFile: "evidence/release.json", Commit: firstCommit, Platform: "linux_amd64"}

		results, err := Verify(root, Document{Claims: []Claim{c}})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if r := results[0]; !r.OK() || r.ComputedMaturity != MaturityShipped {
			t.Fatalf("expected shipped OK, got %+v", r)
		}
	})

	t.Run("not shipped when symbol only exists after the evidenced commit", func(t *testing.T) {
		c := base
		c.ID = "shipped-symbol-too-new"
		c.ClaimedMaturity = MaturityShipped
		c.Implementation = []FileSymbols{{File: "pkg/foo.go", Symbols: []string{"NewFunc"}}}
		c.AcceptanceArtifacts = []ArtifactRef{{Path: "evidence/release.json"}}
		c.BinaryBuildEvidence = &BinaryEvidence{EvidenceFile: "evidence/release.json", Commit: firstCommit, Platform: "linux_amd64"}

		results, err := Verify(root, Document{Claims: []Claim{c}})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		r := results[0]
		if r.OK() {
			t.Fatal("expected OK() false: NewFunc did not exist at the evidenced commit")
		}
		if r.ComputedMaturity != MaturityAccepted {
			t.Fatalf("computed = %s, want accepted (capped below shipped)", r.ComputedMaturity)
		}
	})

	t.Run("not shipped when commit is unknown to the repository", func(t *testing.T) {
		c := base
		c.ID = "shipped-unknown-commit"
		c.ClaimedMaturity = MaturityShipped
		c.AcceptanceArtifacts = []ArtifactRef{{Path: "evidence/release.json"}}
		c.BinaryBuildEvidence = &BinaryEvidence{EvidenceFile: "evidence/release.json", Commit: strings.Repeat("a", 40), Platform: "linux_amd64"}

		results, err := Verify(root, Document{Claims: []Claim{c}})
		if err != nil {
			t.Fatalf("Verify: %v", err)
		}
		if r := results[0]; r.OK() {
			t.Fatal("expected OK() false: commit does not exist in repo history")
		}
	})
}

func TestCLIReachableFindsDispatchCasesAcrossFiles(t *testing.T) {
	root := t.TempDir()
	writeFile(t, root, "cmd/gov/main.go", `package main

func run(args []string) int {
	switch args[0] {
	case "run":
		return runCmd(args[1:])
	case "ask":
		return askCmd(args[1:])
	}
	return 2
}
`)
	writeFile(t, root, "cmd/gov/ask.go", `package main

func askCmd(args []string) int {
	switch args[0] {
	case "approve", "deny":
		return 0
	}
	return 2
}
`)

	reachable, err := cliReachable(root, "gov ask approve")
	if err != nil {
		t.Fatalf("cliReachable: %v", err)
	}
	if !reachable {
		t.Fatal("expected \"gov ask approve\" to be reachable")
	}

	reachable, err = cliReachable(root, "gov ask reject")
	if err != nil {
		t.Fatalf("cliReachable: %v", err)
	}
	if reachable {
		t.Fatal("expected \"gov ask reject\" to be unreachable (no such case label)")
	}
}

func TestReportFlagsOverclaimAsFail(t *testing.T) {
	results := []Result{
		{ID: "a", ClaimedMaturity: MaturityShipped, ComputedMaturity: MaturityTested, Problems: []string{"absent from shipped binary: x"}},
		{ID: "b", ClaimedMaturity: MaturityTested, ComputedMaturity: MaturityTested},
	}
	out, exit := Report(results)
	if exit != 1 {
		t.Fatalf("exit = %d, want 1", exit)
	}
	if !strings.Contains(out, "[FAIL] a") || !strings.Contains(out, "[OK] b") {
		t.Fatalf("unexpected report:\n%s", out)
	}
}

func TestVerifyRealClaimsFileIsFullyConsistent(t *testing.T) {
	repoRoot := findRepoRoot(t)
	doc, err := Load(filepath.Join(repoRoot, "docs", "claims.yaml"))
	if err != nil {
		t.Fatalf("Load real docs/claims.yaml: %v", err)
	}
	if len(doc.Claims) == 0 {
		t.Fatal("expected docs/claims.yaml to declare at least one claim")
	}
	results, err := Verify(repoRoot, doc)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	for _, r := range results {
		if !r.OK() {
			t.Errorf("claim %s overclaims: claimed=%s computed=%s problems=%v", r.ID, r.ClaimedMaturity, r.ComputedMaturity, r.Problems)
		}
	}
}

func TestVerifyReleaseArtifactChecksExactBinaryAndSelfReportedVersion(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go not available")
	}
	root := t.TempDir()
	runGit(t, root, "init")
	runGit(t, root, "config", "user.email", "test@example.com")
	runGit(t, root, "config", "user.name", "test")
	writeFile(t, root, "go.mod", "module example.com/releaseclaim\n\ngo 1.22\n")
	writeFile(t, root, "pkg/foo.go", "package pkg\n\nfunc RealFunc() {}\n")
	writeFile(t, root, "docs/claims.yaml", "version: 1\nclaims: []\n")
	writeFile(t, root, "cmd/gov/main.go", `package main

import (
	"encoding/json"
	"fmt"
	"os"
)

var version = "dev"
var sourceCommit = "unknown"
var claimsHash = "unknown"

func main() {
	if len(os.Args) == 3 && os.Args[1] == "version" && os.Args[2] == "--json" {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"version": version, "source_commit": sourceCommit, "claims_hash": claimsHash})
		return
	}
	fmt.Println("gov", version)
}
`)
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-m", "seed")
	commit := runGitOutput(t, root, "rev-parse", "HEAD")
	claimsHash, err := fileSHA256(filepath.Join(root, "docs", "claims.yaml"))
	if err != nil {
		t.Fatal(err)
	}

	build := func(name, version string) string {
		t.Helper()
		out := filepath.Join(root, name)
		cmd := exec.Command("go", "build", "-o", out, "-ldflags", "-X main.version="+version+" -X main.sourceCommit="+commit+" -X main.claimsHash="+claimsHash, "./cmd/gov")
		cmd.Dir = root
		if data, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("go build %s: %v\n%s", name, err, data)
		}
		return out
	}
	artifact := build("gov-good", "v1.4.1")
	artifactHash, err := fileSHA256(artifact)
	if err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(root, "evidence", "release.json")
	writeFile(t, root, "evidence/test-summary.json", `{
  "source_commit": "`+commit+`",
  "environment_capabilities": {"goos": "test", "machine": "test"},
  "suites": {
    "redteam": {
      "command": "go test -v -tags redteam -count=1 ./...",
      "result": "PASS",
      "source_commit": "`+commit+`",
      "log_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "tests_discovered": 38,
      "tests_run": 38,
      "tests_skipped": 0,
      "tests_failed": 0,
      "identity_gate": {"ok": true, "discovered": 38, "run": 38, "skipped": 0, "failed": 0}
    }
  }
}`)
	writeFile(t, root, "evidence/release.json", `{
  "version": "v1.4.1",
  "source_commit": "`+commit+`",
  "go_version": "",
  "build_flags": "test ldflags",
  "artifact_path": "`+filepath.ToSlash(artifact)+`",
  "artifact_sha256": "`+artifactHash+`",
  "build_info": {},
  "claims_hash": "`+claimsHash+`",
  "test_run_id": "unit-test",
  "test_result": "PASS",
  "test_summary_path": "test-summary.json",
  "acceptance_run_id": "acceptance-test",
  "acceptance_result": "PASS",
  "binaries": {"targets": [{"platform": "linux_amd64", "sha256": "`+artifactHash+`"}]}
}`)
	claim := Claim{
		ID:                  "release-artifact",
		Title:               "release artifact",
		FirstShippedVersion: "v1.4.1",
		ClaimedMaturity:     MaturityShipped,
		Implementation:      []FileSymbols{{File: "pkg/foo.go", Symbols: []string{"RealFunc"}}},
		Tests:               []FileFuncs{{File: "pkg/foo.go", Funcs: nil}},
		AcceptanceArtifacts: []ArtifactRef{{Path: "evidence/release.json"}},
		BinaryBuildEvidence: &BinaryEvidence{EvidenceFile: "evidence/release.json", Commit: commit, Platform: "linux_amd64", ArtifactPath: artifact, ManifestPath: manifest, Version: "v1.4.1"},
	}
	results, err := Verify(root, Document{Claims: []Claim{claim}})
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if r := results[0]; !r.OK() || r.ComputedMaturity != MaturityShipped {
		t.Fatalf("expected artifact-backed shipped claim, got %+v", r)
	}

	badArtifact := build("gov-rc1", "1.0.0-rc1")
	badHash, err := fileSHA256(badArtifact)
	if err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(manifest)
	if err != nil {
		t.Fatal(err)
	}
	body = []byte(strings.ReplaceAll(string(body), filepath.ToSlash(artifact), filepath.ToSlash(badArtifact)))
	body = []byte(strings.ReplaceAll(string(body), artifactHash, badHash))
	if err := os.WriteFile(manifest, body, 0644); err != nil {
		t.Fatal(err)
	}
	claim.BinaryBuildEvidence.ArtifactPath = badArtifact
	results, err = Verify(root, Document{Claims: []Claim{claim}})
	if err != nil {
		t.Fatalf("Verify bad artifact: %v", err)
	}
	if r := results[0]; r.OK() || !containsSubstring(r.Problems, "artifact version 1.0.0-rc1") {
		t.Fatalf("expected rc1 self-reporting binary to fail verification, got %+v", r)
	}
}

// --- test helpers ---

func writeFile(t *testing.T, root, rel, content string) string {
	t.Helper()
	full := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
	return full
}

func runGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, out)
	}
}

func runGitOutput(t *testing.T, dir string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git %v: %v", args, err)
	}
	return strings.TrimSpace(string(out))
}

func containsSubstring(items []string, sub string) bool {
	for _, s := range items {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// TestVerifyRedteamSuiteRequiresIdentityGate is Sol v7 S7 (HS4): a redteam
// suite record with the old count-only fields but no identity_gate object
// must fail closed, not be silently accepted as before.
func TestVerifyRedteamSuiteRequiresIdentityGate(t *testing.T) {
	suite := map[string]any{
		"command":          "go test -v -tags redteam -count=1 ./...",
		"result":           "PASS",
		"tests_discovered": float64(38),
		"tests_failed":     float64(0),
	}
	ok, problems := verifyRedteamSuite(suite, "")
	if ok {
		t.Fatalf("expected verifyRedteamSuite to fail closed without identity_gate, got ok=true")
	}
	if !containsSubstring(problems, "identity_gate") {
		t.Fatalf("expected a problem naming identity_gate, got %v", problems)
	}
}

// TestVerifyRedteamSuiteRejectsFailingIdentityGate confirms the gate's own
// ok=false verdict (any missing/unexpected/failed/unauthorized-skip test)
// propagates as a claims failure, not just its aggregate counts.
func TestVerifyRedteamSuiteRejectsFailingIdentityGate(t *testing.T) {
	suite := map[string]any{
		"command":          "go test -v -tags redteam -count=1 ./...",
		"result":           "PASS",
		"tests_discovered": float64(38),
		"tests_failed":     float64(0),
		"identity_gate": map[string]any{
			"ok":               false,
			"unexpected_skips": []any{"TestV7Case5ValidatorExternalWriteBlockedOrContained"},
		},
	}
	ok, problems := verifyRedteamSuite(suite, "")
	if ok {
		t.Fatalf("expected verifyRedteamSuite to reject identity_gate.ok=false")
	}
	if !containsSubstring(problems, "TestV7Case5ValidatorExternalWriteBlockedOrContained") {
		t.Fatalf("expected the unauthorized skip's name in problems, got %v", problems)
	}
}

// TestVerifyClaimedRedteamCasesBlocksOnUnauthorizedSkip is the claims-vs-
// enforcement check (Sol v7 S7 secondary finding 5): a claim naming a
// specific manifest case must have that exact case passing, not merely an
// overall-passing suite.
func TestVerifyClaimedRedteamCasesBlocksOnUnauthorizedSkip(t *testing.T) {
	repoRoot := findRepoRoot(t)
	evidence := map[string]any{
		"suites": map[string]any{
			"redteam": map[string]any{
				"identity_gate": map[string]any{
					"ok":               false,
					"unexpected_skips": []any{"TestV7Case4LowRiskHostSecretUnreadableUnderNarrowLandlock"},
				},
			},
		},
	}
	ok, problems := verifyClaimedRedteamCases(repoRoot, []int{4}, evidence)
	if ok {
		t.Fatalf("expected case 4 (currently skipped in the fixture) to block the claim")
	}
	if !containsSubstring(problems, "case 4") {
		t.Fatalf("expected a problem naming case 4, got %v", problems)
	}

	okPass, problemsPass := verifyClaimedRedteamCases(repoRoot, []int{1}, evidence)
	if !okPass {
		t.Fatalf("expected case 1 (not in any blocked list) to pass, got %v", problemsPass)
	}
}

// findRepoRoot walks up from the current package directory to the
// governator repository root (identified by go.mod), so this test works
// regardless of the working directory `go test` is invoked from.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find repository root (no go.mod found)")
		}
		dir = parent
	}
}
