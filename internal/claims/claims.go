// Package claims implements the v1.4 Session 6 (Sol Phase 11) machine-verified
// documentation ledger: docs/claims.yaml maps each feature claim to the
// concrete, checkable facts that back it (implementation symbols, CLI
// reachability, tests, integration tests, acceptance artifacts, and binary
// build evidence), and Verify re-derives those facts from the repository on
// every CI run instead of trusting a hand-written status field. This is what
// makes "implemented," "tested," "accepted," and "shipped" mechanically
// distinct: each is a computed boolean gated on the one below it, not a
// claim's own say-so.
package claims

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/cousingary/governator/internal/gitplumb"
	"github.com/cousingary/governator/internal/redteamgate"
	"gopkg.in/yaml.v3"
)

// probeTimeout bounds every git/subprocess lookup Verify performs. These are
// read-only, local, and diagnostic — a hung git call must never hang CI.
const probeTimeout = 10 * time.Second

// Maturity levels, in ascending order. Each requires every level below it to
// hold, plus its own additional check — see Result.Computed.
const (
	MaturityUnimplemented = "unimplemented"
	MaturityImplemented   = "implemented"
	MaturityTested        = "tested"
	MaturityAccepted      = "accepted"
	MaturityShipped       = "shipped"
)

var maturityRank = map[string]int{
	MaturityUnimplemented: 0,
	MaturityImplemented:   1,
	MaturityTested:        2,
	MaturityAccepted:      3,
	MaturityShipped:       4,
}

// FileSymbols names top-level symbols (funcs, types, consts, vars — methods
// are matched by name only, ignoring their receiver type) a claim depends on
// within one file.
type FileSymbols struct {
	File    string   `yaml:"file"`
	Symbols []string `yaml:"symbols"`
}

// FileFuncs names test functions within one file. BuildTag, if set, is
// required to appear as a `//go:build <tag>` line near the top of the file
// (e.g. "integration" for the mandatory real-Assayer-CLI tier).
type FileFuncs struct {
	File     string   `yaml:"file"`
	Funcs    []string `yaml:"funcs"`
	BuildTag string   `yaml:"build_tag,omitempty"`
}

// CLIRef declares the gov command line a claim must be reachable from.
// Command may be a multi-word command ("gov ask approve"); every word after
// "gov" is checked against every `case "<word>":` label found anywhere under
// cmd/gov — a heuristic that confirms the verbs exist as dispatch targets,
// not that they nest exactly as written.
type CLIRef struct {
	Command string `yaml:"command"`
}

// ArtifactRef points at a real acceptance-evidence file. Pointer, if set, is
// a dot-separated path into that file's parsed JSON that must resolve to a
// present key (e.g. "acceptance_evidence.4_safe_pre_mutation_fallback").
type ArtifactRef struct {
	Path    string `yaml:"path"`
	Pointer string `yaml:"pointer,omitempty"`
}

// BinaryEvidence points at the commit and evidence file recording the
// rebuilt-binary proof that Commit's code was actually shipped, not merely
// merged. Platform, if set, additionally requires that evidence file's
// binaries list to carry a non-empty sha256 for that platform.
type BinaryEvidence struct {
	EvidenceFile string `yaml:"evidence_file"`
	Commit       string `yaml:"commit"`
	Platform     string `yaml:"platform,omitempty"`
	ArtifactPath string `yaml:"artifact_path,omitempty"`
	ManifestPath string `yaml:"manifest_path,omitempty"`
	Version      string `yaml:"version,omitempty"`
}

// VerifyOptions lets the CLI bind a claims verification run to the exact
// release artifact under inspection without editing docs/claims.yaml.
type VerifyOptions struct {
	ArtifactPath     string
	ManifestPath     string
	ClaimsPath       string
	PortableVerifier bool
}

type BuildManifest struct {
	Version       string `json:"version"`
	SourceCommit  string `json:"source_commit"`
	GoVersion     string `json:"go_version"`
	BuildFlags    string `json:"build_flags"`
	ArchivePath   string `json:"archive_path"`
	ArchiveSHA256 string `json:"archive_sha256"`
	// ExecutablePath/ExecutableSHA256 are the rc8-upg15 S3 (Sol15 P2-2)
	// canonical names: archive_path names an archive, executable_path names
	// the contained/extracted binary itself -- the ambiguity Sol found in
	// the old artifact_path/artifact_sha256 pair (one path label serving
	// both an archive and the binary it contains). ExtractedBinarySHA256 and
	// ArtifactPath/ArtifactSHA256 remain for one release as deprecated
	// aliases (see docs/migration.md); expectedExtractedBinarySHA256 prefers
	// ExecutableSHA256 first.
	ExecutablePath        string            `json:"executable_path,omitempty"`
	ExecutableSHA256      string            `json:"executable_sha256,omitempty"`
	ExtractedBinarySHA256 string            `json:"extracted_binary_sha256,omitempty"`
	ArtifactPath          string            `json:"artifact_path,omitempty"`
	ArtifactSHA256        string            `json:"artifact_sha256,omitempty"`
	BuildInfo             map[string]string `json:"build_info"`
	ClaimsHash            string            `json:"claims_hash"`
	TestRunID             string            `json:"test_run_id"`
	TestResult            string            `json:"test_result"`
	TestSummaryPath       string            `json:"test_summary_path"`
	AcceptanceRunID       string            `json:"acceptance_run_id"`
	AcceptanceResult      string            `json:"acceptance_result"`
}

// Claim is one docs/claims.yaml entry.
func (m BuildManifest) expectedExtractedBinarySHA256() string {
	return firstNonEmpty(m.ExecutableSHA256, m.ExtractedBinarySHA256, m.ArtifactSHA256)
}

type Claim struct {
	ID                  string          `yaml:"id"`
	Title               string          `yaml:"title"`
	FirstShippedVersion string          `yaml:"first_shipped_version"`
	ClaimedMaturity     string          `yaml:"claimed_maturity"`
	Implementation      []FileSymbols   `yaml:"implementation"`
	CLI                 *CLIRef         `yaml:"cli,omitempty"`
	Tests               []FileFuncs     `yaml:"tests"`
	IntegrationTests    []FileFuncs     `yaml:"integration_tests,omitempty"`
	AcceptanceArtifacts []ArtifactRef   `yaml:"acceptance_artifacts,omitempty"`
	BinaryBuildEvidence *BinaryEvidence `yaml:"binary_build_evidence,omitempty"`
	// RedteamCases lists internal/redteam/manifest.yaml case numbers this
	// claim's "shipped" maturity depends on (Sol v7 S7, secondary finding 5:
	// "claims verification rejects evidence ... and fails when a claim
	// exceeds executable enforcement"). A claim naming case 4 ("narrow
	// Landlock is enforced") must have case 4 actually passing in the
	// shipped binary's redteam evidence, not merely skipped or absent —
	// verifyShipped checks this against the manifest and the evidence
	// file's identity_gate results.
	RedteamCases []int `yaml:"redteam_cases,omitempty"`

	// ClaimScope is P1-7 (Sol10 rc4 Session 8): "introduce claim states
	// implemented | partial | platform-dependent | development-only |
	// production-required" so a claim can honestly describe a degraded
	// control instead of leaving an absolute claim standing next to a
	// known limitation. Empty defaults to ScopeProductionRequired (the
	// strictest, pre-existing behavior: fully absolute, no allowlisted
	// gap marker may remain in its implementation files). Only
	// ScopePartial, ScopePlatformDependent, and ScopeDevelopmentOnly
	// exempt a claim from the active-gap-marker rejection below --
	// declaring one of those is itself the honest disclosure Sol asked
	// for, not a loophole.
	ClaimScope string `yaml:"claim_scope,omitempty"`
}

const (
	ScopeImplemented        = "implemented"
	ScopePartial            = "partial"
	ScopePlatformDependent  = "platform-dependent"
	ScopeDevelopmentOnly    = "development-only"
	ScopeProductionRequired = "production-required"
)

var validClaimScopes = map[string]bool{
	"":                      true,
	ScopeImplemented:        true,
	ScopePartial:            true,
	ScopePlatformDependent:  true,
	ScopeDevelopmentOnly:    true,
	ScopeProductionRequired: true,
}

// isAbsoluteClaimScope reports whether c's scope asserts the claim holds
// unconditionally in production -- the only case the gap-marker rejection
// applies to. Partial/platform-dependent/development-only claims already
// disclose their own limitation and are exempt.
func isAbsoluteClaimScope(scope string) bool {
	switch scope {
	case ScopePartial, ScopePlatformDependent, ScopeDevelopmentOnly:
		return false
	default:
		return true
	}
}

// Document is the top-level docs/claims.yaml shape.
type Document struct {
	Version int     `yaml:"version"`
	Claims  []Claim `yaml:"claims"`
}

// Load reads and strictly decodes a claims YAML file.
func Load(path string) (Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Document{}, fmt.Errorf("read claims file: %w", err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var doc Document
	if err := decoder.Decode(&doc); err != nil {
		return Document{}, fmt.Errorf("decode claims file: %w", err)
	}
	seen := map[string]bool{}
	for _, c := range doc.Claims {
		if c.ID == "" {
			return Document{}, fmt.Errorf("claims file: entry with empty id")
		}
		if seen[c.ID] {
			return Document{}, fmt.Errorf("claims file: duplicate id %q", c.ID)
		}
		seen[c.ID] = true
		if _, ok := maturityRank[c.ClaimedMaturity]; !ok {
			return Document{}, fmt.Errorf("claims file: %s: claimed_maturity %q is not one of implemented/tested/accepted/shipped", c.ID, c.ClaimedMaturity)
		}
		if !validClaimScopes[c.ClaimScope] {
			return Document{}, fmt.Errorf("claims file: %s: claim_scope %q is not one of implemented/partial/platform-dependent/development-only/production-required", c.ID, c.ClaimScope)
		}
	}
	return doc, nil
}

// Result is one claim's re-derived, verified state.
type Result struct {
	ID               string
	Title            string
	ClaimedMaturity  string
	ComputedMaturity string
	Problems         []string
}

// OK is true when the claim's asserted maturity is fully backed by what
// Verify could re-derive from the repository — the condition CI gates on.
func (r Result) OK() bool {
	return maturityRank[r.ComputedMaturity] >= maturityRank[r.ClaimedMaturity]
}

// Verify re-derives every claim's computed maturity against repoRoot (the
// governator repository root) and returns one Result per claim, in the same
// order as doc.Claims.
func Verify(repoRoot string, doc Document) ([]Result, error) {
	return VerifyWithOptions(repoRoot, doc, VerifyOptions{})
}

func VerifyWithOptions(repoRoot string, doc Document, opts VerifyOptions) ([]Result, error) {
	results := make([]Result, 0, len(doc.Claims)+1)
	if opts.ArtifactPath != "" || opts.ManifestPath != "" {
		artifactResult := Result{
			ID:               "release-artifact",
			Title:            "release artifact provenance",
			ClaimedMaturity:  MaturityShipped,
			ComputedMaturity: MaturityShipped,
		}
		if ok, problems := verifyArtifactManifest(repoRoot, opts.ArtifactPath, opts.ManifestPath, opts.ClaimsPath); !ok {
			artifactResult.ComputedMaturity = MaturityAccepted
			artifactResult.Problems = problems
		}
		results = append(results, artifactResult)
	}
	for _, c := range doc.Claims {
		results = append(results, verifyOne(repoRoot, c, opts))
	}
	return results, nil
}

// verifyOne walks the maturity ladder implemented -> tested -> accepted ->
// shipped, stopping as soon as it reaches the claim's own claimed_maturity.
// It never probes (or reports problems for) a tier the claim doesn't assert
// it has reached — a claim that only claims "tested" is not penalized for
// lacking acceptance evidence it never promised.
func verifyOne(repoRoot string, c Claim, opts VerifyOptions) Result {
	res := Result{ID: c.ID, Title: c.Title, ClaimedMaturity: c.ClaimedMaturity, ComputedMaturity: MaturityUnimplemented}
	claimedRank := maturityRank[c.ClaimedMaturity]

	implemented, problems := verifyImplemented(repoRoot, c)
	res.Problems = append(res.Problems, problems...)
	if !implemented {
		return res
	}
	res.ComputedMaturity = MaturityImplemented
	if claimedRank <= maturityRank[MaturityImplemented] {
		return res
	}

	tested, problems := verifyTested(repoRoot, c)
	res.Problems = append(res.Problems, problems...)
	if !tested {
		return res
	}
	res.ComputedMaturity = MaturityTested
	if claimedRank <= maturityRank[MaturityTested] {
		return res
	}

	accepted, problems := verifyAccepted(repoRoot, c)
	res.Problems = append(res.Problems, problems...)
	if !accepted {
		return res
	}
	res.ComputedMaturity = MaturityAccepted
	if claimedRank <= maturityRank[MaturityAccepted] {
		return res
	}

	shipped, problems := verifyShipped(repoRoot, c, opts)
	res.Problems = append(res.Problems, problems...)
	if !shipped {
		return res
	}
	res.ComputedMaturity = MaturityShipped
	return res
}

// verifyImplemented checks every declared implementation symbol actually
// exists in the named file, and — if a CLI reference is declared — that its
// verb(s) are reachable dispatch targets under cmd/gov.
func verifyImplemented(repoRoot string, c Claim) (bool, []string) {
	var problems []string
	ok := true
	if len(c.Implementation) == 0 {
		return false, []string{"unwired: claim declares no implementation"}
	}
	for _, fs := range c.Implementation {
		full := filepath.Join(repoRoot, fs.File)
		names, err := symbolsInFile(full)
		if err != nil {
			ok = false
			problems = append(problems, fmt.Sprintf("unwired: %s: %v", fs.File, err))
			continue
		}
		for _, sym := range fs.Symbols {
			if !names[sym] {
				ok = false
				problems = append(problems, fmt.Sprintf("unwired: symbol %s not found in %s", sym, fs.File))
			}
		}
	}
	if c.CLI != nil {
		reachable, err := cliReachable(repoRoot, c.CLI.Command)
		if err != nil {
			ok = false
			problems = append(problems, fmt.Sprintf("unwired: CLI check for %q: %v", c.CLI.Command, err))
		} else if !reachable {
			ok = false
			problems = append(problems, fmt.Sprintf("unwired: %q is not reachable from any cmd/gov dispatch case", c.CLI.Command))
		}
	}
	if gapOK, gapProblems := verifyNoActiveGapMarkers(repoRoot, c); !gapOK {
		ok = false
		problems = append(problems, gapProblems...)
	}
	return ok, problems
}

// activeGapMarkers are the exact strings P1-7 (Sol10 rc4 Session 8) names:
// "the claims verifier must reject an absolute claim when an allowlisted
// gap marker... remains in an authority-bearing production path."
var activeGapMarkers = []string{"known_gap_pending_hardening", "known, accepted gap", "not fixed"}

// gapMarkerClosureRE matches the language this codebase's own convention
// uses to narrate a gap that WAS a marker but has since been resolved (see
// docs/security.md's "Closed ... Fixed:" entries) -- a marker string
// appearing only inside that kind of historical narration is not a live
// gap, and only docs/security.md-style prose (not source) should ever
// carry these strings post-closure anyway.
var gapMarkerClosureRE = regexp.MustCompile(`(?i)\b(closed|removed|was removed|no longer|fixed:)\b`)

// notFixedIdiomRE matches the tail of the ordinary code-comment idiom for
// the third activeGapMarkers entry (deliberately not spelled out verbatim
// in this comment, to avoid this very file re-triggering its own check) --
// "...here"/"...in this <noun>" following that phrase means "out of scope
// for this change," not a live security-gap status declaration.
var notFixedIdiomRE = regexp.MustCompile(`(?i)^\s+(here|in this)\b`)

// verifyNoActiveGapMarkers is P1-7: a claim whose ClaimScope is absolute
// (the default) must not have any of activeGapMarkers sitting, unclosed,
// in any file it names as its own implementation. A claim that legitimately
// has a known limitation should declare ClaimScope partial/
// platform-dependent/development-only instead of leaving an absolute claim
// standing next to the gap.
func verifyNoActiveGapMarkers(repoRoot string, c Claim) (bool, []string) {
	if !isAbsoluteClaimScope(c.ClaimScope) {
		return true, nil
	}
	var problems []string
	ok := true
	for _, fs := range c.Implementation {
		full := filepath.Join(repoRoot, fs.File)
		data, err := os.ReadFile(full)
		if err != nil {
			continue // verifyImplemented's own file-read check already reports this
		}
		text := string(data)
		for _, marker := range activeGapMarkers {
			searchFrom := 0
			for {
				pos := strings.Index(text[searchFrom:], marker)
				if pos == -1 {
					break
				}
				abs := searchFrom + pos
				searchFrom = abs + len(marker)
				// A marker sitting inside a quoted Go string literal (this
				// very function's own activeGapMarkers definition, sitting
				// in a file that legitimately implements a claim) is the
				// allowlist being DEFINED, not a live status being
				// DECLARED -- exclude an exact `"<marker>"` quoting.
				if abs > 0 && text[abs-1] == '"' && abs+len(marker) < len(text) && text[abs+len(marker)] == '"' {
					continue
				}
				// See notFixedIdiomRE's own comment: this third-marker
				// idiom (see internal/attest/attest.go,
				// internal/doctor/doctor.go: diagnostic-only Git/Bash
				// calls explicitly tracked elsewhere, never a governed
				// run's authority path) is "out of scope for this change,"
				// not a live security-gap status declaration -- only the
				// latter is what P1-7 means to catch.
				if marker == activeGapMarkers[2] && notFixedIdiomRE.MatchString(text[abs+len(marker):min(len(text), abs+len(marker)+16)]) {
					continue
				}
				start := abs - 300
				if start < 0 {
					start = 0
				}
				end := abs + len(marker) + 300
				if end > len(text) {
					end = len(text)
				}
				if !gapMarkerClosureRE.MatchString(text[start:end]) {
					ok = false
					problems = append(problems, fmt.Sprintf("unwired: %s contains active gap marker %q with no closure signal nearby -- an absolute claim (claim_scope=%s) may not stand next to an unresolved gap (P1-7); declare claim_scope: partial/platform-dependent/development-only if this is a known limitation", fs.File, marker, firstNonEmpty(c.ClaimScope, ScopeProductionRequired)))
				}
			}
		}
	}
	return ok, problems
}

// verifyTested checks every declared unit and integration test function
// exists in its named file, and that any declared build tag is present.
func verifyTested(repoRoot string, c Claim) (bool, []string) {
	var problems []string
	ok := true
	if len(c.Tests) == 0 {
		return false, []string{"untested: claim declares no tests"}
	}
	for _, ff := range c.Tests {
		if fileOK, probs := verifyFileFuncs(repoRoot, ff, "untested"); !fileOK {
			ok = false
			problems = append(problems, probs...)
		}
	}
	for _, ff := range c.IntegrationTests {
		if fileOK, probs := verifyFileFuncs(repoRoot, ff, "untested (integration)"); !fileOK {
			ok = false
			problems = append(problems, probs...)
		}
	}
	return ok, problems
}

func verifyFileFuncs(repoRoot string, ff FileFuncs, label string) (bool, []string) {
	var problems []string
	ok := true
	full := filepath.Join(repoRoot, ff.File)
	content, err := os.ReadFile(full)
	if err != nil {
		return false, []string{fmt.Sprintf("%s: %s: %v", label, ff.File, err)}
	}
	text := string(content)
	for _, fn := range ff.Funcs {
		re := regexp.MustCompile(`(?m)^func\s+` + regexp.QuoteMeta(fn) + `\s*\(`)
		if !re.MatchString(text) {
			ok = false
			problems = append(problems, fmt.Sprintf("%s: func %s not found in %s", label, fn, ff.File))
		}
	}
	if ff.BuildTag != "" {
		want := "//go:build " + ff.BuildTag
		if !strings.Contains(text, want) {
			ok = false
			problems = append(problems, fmt.Sprintf("%s: %s missing required %q build constraint", label, ff.File, want))
		}
	}
	return ok, problems
}

// verifyAccepted checks every declared acceptance artifact file exists, and
// if it declares a JSON pointer, that the pointer resolves against a real
// key in that file.
func verifyAccepted(repoRoot string, c Claim) (bool, []string) {
	var problems []string
	ok := true
	if len(c.AcceptanceArtifacts) == 0 {
		return false, []string{"stale: claim declares no acceptance artifacts"}
	}
	for _, a := range c.AcceptanceArtifacts {
		full := filepath.Join(repoRoot, a.Path)
		data, err := os.ReadFile(full)
		if err != nil {
			ok = false
			problems = append(problems, fmt.Sprintf("stale: acceptance artifact %s: %v", a.Path, err))
			continue
		}
		if a.Pointer == "" {
			continue
		}
		var parsed any
		if err := json.Unmarshal(data, &parsed); err != nil {
			ok = false
			problems = append(problems, fmt.Sprintf("stale: acceptance artifact %s is not valid JSON: %v", a.Path, err))
			continue
		}
		if !resolvePointer(parsed, a.Pointer) {
			ok = false
			problems = append(problems, fmt.Sprintf("stale: acceptance artifact %s has no key at %q", a.Path, a.Pointer))
		}
	}
	return ok, problems
}

func resolvePointer(data any, dotPath string) bool {
	cur := data
	for _, part := range strings.Split(dotPath, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return false
		}
		v, ok := m[part]
		if !ok {
			return false
		}
		cur = v
	}
	return true
}

// verifyShipped checks that the claim's binary build evidence names a commit
// that (a) actually exists and is an ancestor of (or equal to) HEAD, (b) is
// recorded in the named evidence file alongside a real binary hash, and (c)
// contained every declared implementation symbol at that historical commit
// — i.e. the symbol was actually present in the code the evidence's binary
// was built from, not added afterward.
func verifyShipped(repoRoot string, c Claim, opts VerifyOptions) (bool, []string) {
	if c.BinaryBuildEvidence == nil {
		return false, []string{"absent from shipped binary: claim declares no binary_build_evidence"}
	}
	be := c.BinaryBuildEvidence
	var problems []string
	ok := true

	if err := gitCheck(repoRoot, opts.PortableVerifier, "cat-file", "-e", be.Commit+"^{commit}"); err != nil {
		return false, []string{fmt.Sprintf("absent from shipped binary: commit %s not found: %v", be.Commit, err)}
	}
	if err := gitCheck(repoRoot, opts.PortableVerifier, "merge-base", "--is-ancestor", be.Commit, "HEAD"); err != nil {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: commit %s is not an ancestor of HEAD", be.Commit))
	}

	if be.ManifestPath != "" || be.ArtifactPath != "" {
		artifactOK, artifactProblems := verifyReleaseArtifact(repoRoot, c, opts)
		if !artifactOK {
			ok = false
			problems = append(problems, artifactProblems...)
		}
	}

	evPath := filepath.Join(repoRoot, be.EvidenceFile)
	data, err := os.ReadFile(evPath)
	if err != nil {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: evidence file %s: %v", be.EvidenceFile, err))
	} else {
		var parsed map[string]any
		if err := json.Unmarshal(data, &parsed); err != nil {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: evidence file %s is not valid JSON: %v", be.EvidenceFile, err))
		} else {
			if !evidenceRecordsCommit(parsed, be.Commit, be.Platform) {
				ok = false
				problems = append(problems, fmt.Sprintf("absent from shipped binary: evidence file %s does not record commit %s with a binary hash", be.EvidenceFile, be.Commit))
			}
			if gateOK, gateProblems := verifyReleaseGateEvidence(repoRoot, parsed, be.Commit, opts.PortableVerifier); !gateOK {
				ok = false
				problems = append(problems, gateProblems...)
			}
			if len(c.RedteamCases) > 0 {
				if casesOK, caseProblems := verifyClaimedRedteamCases(repoRoot, c.RedteamCases, parsed); !casesOK {
					ok = false
					problems = append(problems, caseProblems...)
				}
			}
		}
	}

	if be.Version != "" {
		if versionOK, versionProblems := verifyVersionTagProvenance(repoRoot, be.Commit, be.Version, opts.PortableVerifier); !versionOK {
			ok = false
			problems = append(problems, versionProblems...)
		}
	}

	for _, fs := range c.Implementation {
		blob, err := gitShow(repoRoot, opts.PortableVerifier, be.Commit, fs.File)
		if err != nil {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: %s did not exist at %s: %v", fs.File, be.Commit, err))
			continue
		}
		for _, sym := range fs.Symbols {
			re := regexp.MustCompile(`\b` + regexp.QuoteMeta(sym) + `\b`)
			if !re.Match(blob) {
				ok = false
				problems = append(problems, fmt.Sprintf("absent from shipped binary: symbol %s not present in %s at %s", sym, fs.File, be.Commit))
			}
		}
	}
	return ok, problems
}

// minRedteamTestCount is a defense-in-depth floor, not the primary release
// gate: even if the identity gate's manifest were somehow tampered down to
// fewer entries, a redteam suite discovering fewer than the full 41-case
// mandatory final attack corpus (including the currently enrolled v8 cases)
// cannot be a real release. The identity check below (an exact,
// name-by-name comparison against internal/redteam/manifest.yaml via `gov
// redteam-gate verify`) is what actually replaces the old count-only gate
// (Sol v7 S7, HS4) — see identity_gate below.
const minRedteamTestCount = 58

// verifyClaimedRedteamCases checks that every redteam manifest case number a
// claim declares (Claim.RedteamCases) is neither missing, name-drifted,
// failed, nor an unauthorized skip in the shipped binary's redteam evidence
// — Sol v7 S7 secondary finding 5 ("claims verification ... fails when a
// claim exceeds executable enforcement"). Resolves case numbers to exact
// test names via internal/redteam/manifest.yaml, so a claim can assert
// "cases 13-16 are enforced" without hardcoding function names that could
// drift out from under it.
func verifyClaimedRedteamCases(repoRoot string, cases []int, evidence map[string]any) (bool, []string) {
	manifestPath := filepath.Join(repoRoot, "internal", "redteam", "manifest.yaml")
	manifest, err := redteamgate.LoadManifest(manifestPath)
	if err != nil {
		return false, []string{fmt.Sprintf("absent from shipped binary: redteam_cases declared but manifest unreadable: %v", err)}
	}
	byCase := make(map[int]string, len(manifest.Cases))
	for _, c := range manifest.Cases {
		byCase[c.Case] = c.Name
	}
	suite, found := findNamedMap(evidence, "redteam")
	if !found {
		return false, []string{"absent from shipped binary: redteam_cases declared but evidence has no redteam suite"}
	}
	gate, found := findNamedMap(suite, "identity_gate")
	if !found {
		return false, []string{"absent from shipped binary: redteam_cases declared but redteam suite has no identity_gate evidence"}
	}
	blocked := make(map[string]bool)
	for _, field := range []string{"missing_tests", "unexpected_tests", "unexpected_skips", "failed_tests"} {
		for _, name := range stringsAt(gate, field) {
			blocked[name] = true
		}
	}
	var problems []string
	for _, num := range cases {
		name, known := byCase[num]
		if !known {
			problems = append(problems, fmt.Sprintf("absent from shipped binary: redteam_cases declares case %d, not present in manifest.yaml", num))
			continue
		}
		if blocked[name] {
			problems = append(problems, fmt.Sprintf("absent from shipped binary: redteam case %d (%s) is missing, failed, drifted, or an unauthorized skip in the shipped evidence", num, name))
		}
	}
	return len(problems) == 0, problems
}

func verifyReleaseGateEvidence(repoRoot string, evidence map[string]any, commit string, portable bool) (bool, []string) {
	var problems []string
	ok := true
	if strings.TrimSpace(commit) == "" {
		ok = false
		problems = append(problems, "absent from shipped binary: release evidence has empty source commit")
	}
	if suite, found := findNamedMap(evidence, "redteam"); found {
		if suiteOK, suiteProblems := verifyRedteamSuite(suite, commit); !suiteOK {
			ok = false
			problems = append(problems, suiteProblems...)
		}
	}
	if version, _ := stringAt(evidence, "version"); version != "" {
		if versionOK, versionProblems := verifyVersionTagProvenance(repoRoot, commit, version, portable); !versionOK {
			ok = false
			problems = append(problems, versionProblems...)
		}
	}
	return ok, problems
}

func verifyTestSummary(repoRoot, summaryPath, commit string) (bool, []string) {
	full := absOrRepo(repoRoot, summaryPath)
	data, err := os.ReadFile(full)
	if err != nil {
		return false, []string{fmt.Sprintf("absent from shipped binary: test summary %s: %v", summaryPath, err)}
	}
	var parsed map[string]any
	if err := json.Unmarshal(data, &parsed); err != nil {
		return false, []string{fmt.Sprintf("absent from shipped binary: test summary %s is not valid JSON: %v", summaryPath, err)}
	}
	var problems []string
	ok := true
	if got, _ := stringAt(parsed, "source_commit"); commit != "" && got != "" && got != commit {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: test summary source_commit %s does not match manifest %s", got, commit))
	}
	if suite, found := findNamedMap(parsed, "redteam"); found {
		if suiteOK, suiteProblems := verifyRedteamSuite(suite, commit); !suiteOK {
			ok = false
			problems = append(problems, suiteProblems...)
		}
	} else {
		ok = false
		problems = append(problems, "absent from shipped binary: test summary lacks mandatory redteam suite")
	}
	if _, found := findNamedMap(parsed, "environment_capabilities"); !found {
		ok = false
		problems = append(problems, "absent from shipped binary: test summary lacks environment_capabilities")
	}
	if evidenceOK, evidenceProblems := verifyEvidenceLogObjects(filepath.Dir(full), parsed); !evidenceOK {
		ok = false
		problems = append(problems, evidenceProblems...)
	}
	if matrixOK, matrixProblems := verifyAssayerMatrixPatchVersions(parsed); !matrixOK {
		ok = false
		problems = append(problems, matrixProblems...)
	}
	return ok, problems
}

// fullPatchVersionRE matches a complete X.Y.Z Python version (P1-1, Sol10
// rc4 Session 8: "the matrix should record full versions... rather than
// only 3.13" -- a bare minor version like "3.13" hides exactly which patch
// release the matrix actually ran, which is what let a shutdown regression
// specific to one patch (3.13.5) go unnoticed against release evidence
// that only ever said "3.13").
var fullPatchVersionRE = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)

func verifyAssayerMatrixPatchVersions(summary map[string]any) (bool, []string) {
	suites, _ := summary["suites"].(map[string]any)
	assayerMatrix, found := findNamedMap(suites, "assayer_matrix")
	if !found {
		return true, nil
	}
	versions, _ := assayerMatrix["versions"].([]any)
	var problems []string
	ok := true
	for _, v := range versions {
		entry, isMap := v.(map[string]any)
		if !isMap {
			continue
		}
		pv, _ := stringAt(entry, "python_version")
		if !fullPatchVersionRE.MatchString(pv) {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: assayer_matrix entry has non-patch python_version %q (must be X.Y.Z, e.g. 3.13.5)", pv))
		}
	}
	return ok, problems
}

// verifyEvidenceLogObjects is P1-4 (Sol10 rc4 Session 8): "a third party
// can see the claimed hashes but cannot retrieve and verify the objects
// those hashes identify." For every suite that declares a log_sha256, this
// requires a sibling log_path naming a real, gzip-compressed object in the
// same directory as test-summary.json, decompresses it, and checks its
// SHA-256 against the declared hash -- never trusting the summary's word
// alone. Runs for the six Go test tiers plus every Assayer per-interpreter
// matrix entry.
func verifyEvidenceLogObjects(evidenceDir string, summary map[string]any) (bool, []string) {
	var problems []string
	ok := true

	checkOne := func(label string, entry map[string]any) {
		declaredHash, hasHash := stringAt(entry, "log_sha256")
		if !hasHash || declaredHash == "" {
			return
		}
		logPath, hasPath := stringAt(entry, "log_path")
		if !hasPath || logPath == "" {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: %s declares log_sha256 %s but no log_path -- referenced test log absent", label, declaredHash))
			return
		}
		actualHash, err := decompressedSHA256(filepath.Join(evidenceDir, logPath))
		if err != nil {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: %s log object %s: %v", label, logPath, err))
			return
		}
		if !strings.EqualFold(actualHash, declaredHash) {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: %s log object %s sha256 mismatch: declared=%s actual=%s", label, logPath, declaredHash, actualHash))
		}
	}

	suites, _ := summary["suites"].(map[string]any)
	for _, name := range []string{"unit", "race", "integration", "black_box_corpus", "redteam", "redteam_race"} {
		entry, found := findNamedMap(suites, name)
		if !found {
			continue
		}
		checkOne("suite "+name, entry)
	}
	if assayerMatrix, found := findNamedMap(suites, "assayer_matrix"); found {
		if versions, ok2 := assayerMatrix["versions"].([]any); ok2 {
			for _, v := range versions {
				if entry, ok3 := v.(map[string]any); ok3 {
					pv, _ := stringAt(entry, "python_version")
					checkOne("assayer_matrix python "+pv, entry)
				}
			}
		}
	}
	return ok, problems
}

// decompressedSHA256 reads a gzip-compressed file and returns the SHA-256
// of its decompressed content.
func decompressedSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return "", fmt.Errorf("not a valid gzip object: %w", err)
	}
	defer gz.Close()
	h := sha256.New()
	if _, err := io.Copy(h, gz); err != nil {
		return "", fmt.Errorf("decompress: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func verifyRedteamSuite(suite map[string]any, commit string) (bool, []string) {
	var problems []string
	ok := true
	command, _ := stringAt(suite, "command")
	if !commandIncludesRedteam(command) {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: redteam suite command %q excludes -tags redteam", command))
	}
	if !strings.Contains(command, "-count=1") && !strings.Contains(command, "-count 1") {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: redteam suite command %q is not uncached (-count=1)", command))
	}
	result, _ := stringAt(suite, "result")
	if !passingResult(result) {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: redteam suite result %q is not passing", result))
	}
	if gotCommit, _ := stringAt(suite, "source_commit"); gotCommit != "" && commit != "" && gotCommit != commit {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: redteam suite source_commit %s does not match %s", gotCommit, commit))
	}
	if logHash, _ := stringAt(suite, "log_sha256"); logHash != "" && !isSHA256Hex(logHash) {
		ok = false
		problems = append(problems, "absent from shipped binary: redteam suite has invalid log_sha256")
	}
	discovered, hasDiscovered := intAt(suite, "tests_discovered", "number_discovered", "discovered", "test_count")
	if !hasDiscovered {
		ok = false
		problems = append(problems, "absent from shipped binary: redteam suite lacks tests_discovered")
	} else if discovered < minRedteamTestCount {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: redteam suite discovered %d below the full %d-case mandatory final attack corpus", discovered, minRedteamTestCount))
	}
	failed, hasFailed := intAt(suite, "tests_failed", "failed", "number_failed")
	if !hasFailed {
		ok = false
		problems = append(problems, "absent from shipped binary: redteam suite lacks tests_failed")
	} else if failed != 0 {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: redteam suite failed count is %d", failed))
	}

	// Sol v7 S7 (HS4): the old count-based unexpected-skip check
	// (unexpected_skipped == 0) is retired — it validated a total, not which
	// test skipped or why, so a wrong test skipping at the same total count
	// passed unnoticed. identity_gate is `gov redteam-gate verify`'s full
	// structured verdict against internal/redteam/manifest.yaml: exact
	// missing/unexpected/failed/unexpected-skip test *names*. A release
	// whose test-summary.json lacks this object entirely cannot be verified
	// as identity-checked and fails closed, the same posture every other
	// missing-evidence branch in this function already takes.
	gate, hasGate := findNamedMap(suite, "identity_gate")
	if !hasGate {
		ok = false
		problems = append(problems, "absent from shipped binary: redteam suite lacks identity_gate evidence (gov redteam-gate verify)")
		return ok, problems
	}
	if gateOK, _ := boolAt(gate, "ok"); !gateOK {
		ok = false
		problems = append(problems, "absent from shipped binary: redteam suite identity_gate reports ok=false (missing/unexpected/failed test or unauthorized skip)")
	}
	for _, field := range []string{"missing_tests", "unexpected_tests", "unexpected_skips"} {
		if names := stringsAt(gate, field); len(names) > 0 {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: redteam suite identity_gate.%s: %s", field, strings.Join(names, ", ")))
		}
	}
	return ok, problems
}

// VersionTagSourceForTesting is a TEST-ONLY seam (Sol14 rc7 Session 9a, P1-2).
// When non-nil, verifyVersionTagProvenance resolves a version's tag through it
// instead of `git rev-parse <tag>^{commit}` against repoRoot, so the
// version/tag provenance COMPARISON can be exercised deterministically on any
// checkout. It must return the commit the tag points at, or an error meaning
// "no such tag" (which this function treats as nothing to compare, exactly as
// a failing git rev-parse does).
//
// Before this seam, TestV6Case36UntaggedPostV1TagSourcePackagedAsV1IsRejected
// depended on the live checkout happening to have a reachable tag with HEAD
// several commits past it -- it skipped on a checkout sitting exactly at a tag,
// and on any clone fetched without tags. It was therefore carried as an OPEN
// GAP exclusion, which Sol14 P1-2 rejects as durable release policy.
//
// The seam replaces only the tag->commit LOOKUP. The provenance rule under test
// -- a version naming a tag whose commit differs from the evidence commit must
// be rejected -- still runs for real against the injected pair, so the assertion
// is the production one. Production code MUST NEVER set this; only _test.go
// code and the redteam corpus assign it (and defer restoring nil), mirroring
// containment.ExtinguishGateForTesting.
var VersionTagSourceForTesting func(repoRoot, tag string) (string, error)

func verifyVersionTagProvenance(repoRoot, commit, version string, portable bool) (bool, []string) {
	v := strings.TrimSpace(version)
	if v == "" || strings.Contains(v, "candidate") || strings.Contains(v, "+") {
		return true, nil
	}
	tag := v
	if !strings.HasPrefix(tag, "v") {
		tag = "v" + tag
	}
	var tagCommit string
	if resolve := VersionTagSourceForTesting; resolve != nil {
		resolved, err := resolve(repoRoot, tag)
		if err != nil {
			return true, nil
		}
		tagCommit = strings.TrimSpace(resolved)
	} else {
		out, err := gitOutput(repoRoot, portable, "rev-parse", tag+"^{commit}")
		if err != nil {
			return true, nil
		}
		tagCommit = strings.TrimSpace(string(out))
	}
	if tagCommit != "" && commit != "" && tagCommit != commit {
		return false, []string{fmt.Sprintf("absent from shipped binary: binary_build_evidence.version %s names tag %s at %s, but evidence commit is %s", version, tag, tagCommit, commit)}
	}
	return true, nil
}

func commandIncludesRedteam(command string) bool {
	fields := strings.Fields(command)
	for i, f := range fields {
		if strings.HasPrefix(f, "-tags=") || strings.HasPrefix(f, "--tags=") {
			for _, tag := range strings.Split(strings.TrimPrefix(strings.TrimPrefix(f, "--tags="), "-tags="), ",") {
				if tag == "redteam" {
					return true
				}
			}
		}
		if (f == "-tags" || f == "--tags") && i+1 < len(fields) {
			for _, tag := range strings.Split(fields[i+1], ",") {
				if tag == "redteam" {
					return true
				}
			}
		}
	}
	return false
}

func findNamedMap(v any, name string) (map[string]any, bool) {
	switch t := v.(type) {
	case map[string]any:
		if child, ok := t[name].(map[string]any); ok {
			return child, true
		}
		for _, child := range t {
			if found, ok := findNamedMap(child, name); ok {
				return found, true
			}
		}
	case []any:
		for _, child := range t {
			if found, ok := findNamedMap(child, name); ok {
				return found, true
			}
		}
	}
	return nil, false
}

func stringAt(m map[string]any, key string) (string, bool) {
	v, ok := m[key]
	if !ok {
		return "", false
	}
	s, ok := v.(string)
	return strings.TrimSpace(s), ok
}

func boolAt(m map[string]any, key string) (bool, bool) {
	v, ok := m[key]
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// stringsAt reads a JSON array of strings at key, tolerating absence (nil,
// not an error) — used for identity_gate's missing_tests/unexpected_tests/
// unexpected_skips fields, which are omitted entirely when empty.
func stringsAt(m map[string]any, key string) []string {
	raw, ok := m[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func intAt(m map[string]any, keys ...string) (int, bool) {
	for _, key := range keys {
		v, ok := m[key]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case float64:
			return int(t), true
		case int:
			return t, true
		case json.Number:
			i, err := t.Int64()
			return int(i), err == nil
		case []any:
			return len(t), true
		}
	}
	return 0, false
}

func isSHA256Hex(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func verifyReleaseArtifact(repoRoot string, c Claim, opts VerifyOptions) (bool, []string) {
	be := c.BinaryBuildEvidence
	if be == nil {
		return false, []string{"absent from shipped binary: claim declares no binary_build_evidence"}
	}
	manifestPath := firstNonEmpty(opts.ManifestPath, be.ManifestPath, be.EvidenceFile)
	artifactPath := firstNonEmpty(opts.ArtifactPath, be.ArtifactPath)
	ok, problems := verifyArtifactManifest(repoRoot, artifactPath, manifestPath, opts.ClaimsPath)
	if !ok {
		return ok, problems
	}
	manifest, _, artifactLabel, err := loadBuildManifest(repoRoot, artifactPath, manifestPath)
	if err != nil {
		return false, []string{err.Error()}
	}
	if manifest.SourceCommit != be.Commit {
		return false, []string{fmt.Sprintf("absent from shipped binary: manifest source_commit %s does not match claim commit %s", manifest.SourceCommit, be.Commit)}
	}
	expectedVersion := firstNonEmpty(be.Version, manifest.Version, c.FirstShippedVersion)
	if expectedVersion == "" {
		return false, []string{"absent from shipped binary: no expected version recorded"}
	}
	self, err := runArtifactVersionJSON(absOrRepo(repoRoot, artifactLabel))
	if err != nil {
		return false, []string{fmt.Sprintf("absent from shipped binary: artifact version --json failed: %v", err)}
	}
	if self.Version != expectedVersion {
		return false, []string{fmt.Sprintf("absent from shipped binary: artifact version %s does not match expected %s", self.Version, expectedVersion)}
	}
	return true, nil
}

func verifyArtifactManifest(repoRoot, artifactPath, manifestPath, claimsPath string) (bool, []string) {
	manifest, artifactFull, artifactLabel, err := loadBuildManifest(repoRoot, artifactPath, manifestPath)
	if err != nil {
		return false, []string{err.Error()}
	}
	var problems []string
	ok := true

	artifactHash, err := fileSHA256(artifactFull)
	if err != nil {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: artifact %s: %v", artifactLabel, err))
	} else if expected := manifest.expectedExtractedBinarySHA256(); !strings.EqualFold(artifactHash, expected) {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: artifact sha256 mismatch: manifest=%s actual=%s", expected, artifactHash))
	}

	if !passingResult(manifest.TestResult) || strings.TrimSpace(manifest.TestRunID) == "" {
		ok = false
		problems = append(problems, "absent from shipped binary: manifest lacks a passing test_run_id/test_result")
	}
	if strings.TrimSpace(manifest.TestSummaryPath) == "" {
		ok = false
		problems = append(problems, "absent from shipped binary: manifest lacks required test_summary_path")
	} else {
		// test_summary_path is a bare filename release.sh writes as a
		// sibling of build-manifest.json (both land in OUT_DIR, e.g.
		// dist/) -- never at repoRoot, and never inside the artifact
		// tarball itself (that ships only the gov binary). Resolve it
		// against the manifest's own directory, not repoRoot, or a real
		// release build fails its own artifact-provenance check.
		manifestDir := filepath.Dir(absOrRepo(repoRoot, manifestPath))
		if summaryOK, summaryProblems := verifyTestSummary(manifestDir, manifest.TestSummaryPath, manifest.SourceCommit); !summaryOK {
			ok = false
			problems = append(problems, summaryProblems...)
		}
	}
	if !passingResult(manifest.AcceptanceResult) || strings.TrimSpace(manifest.AcceptanceRunID) == "" {
		ok = false
		problems = append(problems, "absent from shipped binary: manifest lacks a passing acceptance_run_id/acceptance_result")
	}

	claimsLabel := firstNonEmpty(claimsPath, filepath.Join(repoRoot, "docs", "claims.yaml"))
	if actualClaimsHash, err := fileSHA256(absOrRepo(repoRoot, claimsLabel)); err != nil {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: claims file %s: %v", claimsLabel, err))
	} else if manifest.ClaimsHash != actualClaimsHash {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: manifest claims_hash %s does not match %s %s", manifest.ClaimsHash, claimsLabel, actualClaimsHash))
	}

	bi, err := buildinfo.ReadFile(artifactFull)
	if err != nil {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: cannot read Go buildinfo from %s: %v", artifactLabel, err))
	} else {
		if manifest.GoVersion != "" && bi.GoVersion != "" && manifest.GoVersion != bi.GoVersion {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: manifest go_version %s does not match artifact %s", manifest.GoVersion, bi.GoVersion))
		}
		settings := map[string]string{}
		for _, setting := range bi.Settings {
			settings[setting.Key] = setting.Value
		}
		if rev := firstNonEmpty(settings["vcs.revision"], manifest.BuildInfo["vcs_revision"]); rev != "" && rev != manifest.SourceCommit {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: artifact vcs revision %s does not match manifest source_commit %s", rev, manifest.SourceCommit))
		}
		if settings["vcs.modified"] == "true" {
			ok = false
			problems = append(problems, "absent from shipped binary: artifact build metadata reports vcs.modified=true")
		}
		if strings.Contains(strings.ToLower(strings.TrimSpace(bi.Main.Version)), "+dirty") {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: artifact module version %q contains +dirty", bi.Main.Version))
		}
	}

	self, err := runArtifactVersionJSON(artifactFull)
	if err != nil {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: artifact version --json failed: %v", err))
	} else {
		if self.Version != manifest.Version {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: artifact version %s does not match manifest %s", self.Version, manifest.Version))
		}
		if self.SourceCommit != manifest.SourceCommit {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: artifact source_commit %s does not match manifest %s", self.SourceCommit, manifest.SourceCommit))
		}
		if manifest.ClaimsHash != "" && self.ClaimsHash != manifest.ClaimsHash {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: artifact claims_hash %s does not match manifest %s", self.ClaimsHash, manifest.ClaimsHash))
		}
		if self.Dirty == nil {
			ok = false
			problems = append(problems, "absent from shipped binary: artifact version JSON missing dirty field")
		} else if *self.Dirty {
			ok = false
			problems = append(problems, "absent from shipped binary: artifact version JSON reports dirty=true")
		}
	}
	return ok, problems
}

func loadBuildManifest(repoRoot, artifactPath, manifestPath string) (BuildManifest, string, string, error) {
	var manifest BuildManifest
	if manifestPath == "" {
		return manifest, "", "", fmt.Errorf("absent from shipped binary: no build manifest path provided")
	}
	manifestFull := absOrRepo(repoRoot, manifestPath)
	data, err := os.ReadFile(manifestFull)
	if err != nil {
		return manifest, "", "", fmt.Errorf("absent from shipped binary: build manifest %s: %v", manifestPath, err)
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		return manifest, "", "", fmt.Errorf("absent from shipped binary: build manifest %s is not valid JSON: %v", manifestPath, err)
	}
	artifactLabel := firstNonEmpty(artifactPath, manifest.ArchivePath, manifest.ArtifactPath)
	if artifactLabel == "" {
		return manifest, "", "", fmt.Errorf("absent from shipped binary: no artifact path provided by CLI or manifest")
	}
	return manifest, absOrRepo(repoRoot, artifactLabel), artifactLabel, nil
}

type artifactVersion struct {
	Version                string `json:"version"`
	SourceCommit           string `json:"source_commit"`
	BuildTimestamp         string `json:"build_timestamp"`
	ClaimsHash             string `json:"claims_hash"`
	AdapterProtocolVersion string `json:"adapter_protocol_version"`
	Dirty                  *bool  `json:"dirty"`
}

func runArtifactVersionJSON(path string) (artifactVersion, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, path, "version", "--json") // govratchet:exec-allow(release_tooling)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return artifactVersion{}, fmt.Errorf("%w: %s", err, msg)
		}
		return artifactVersion{}, err
	}
	var v artifactVersion
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		return artifactVersion{}, err
	}
	return v, nil
}

func fileSHA256(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

func absOrRepo(repoRoot, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(repoRoot, path)
}

func passingResult(value string) bool {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "PASS", "PASSED", "OK", "SUCCESS":
		return true
	default:
		return false
	}
}

// evidenceRecordsCommit reports whether the parsed evidence JSON, anywhere in
// its tree, records commit under a "source_commit" or "vcs_revision" key
// AND — when platform is set — carries a non-empty "sha256" for that
// platform somewhere in the tree. The two facts are searched independently
// (not required to be siblings in the same object) because real evidence
// files record them under different parents (e.g. release.source_commit vs.
// binaries.targets[].sha256): this is one evidence report describing one
// build, so recording both facts anywhere in it is sufficient proof.
func evidenceRecordsCommit(v any, commit, platform string) bool {
	if !containsCommitValue(v, commit) {
		return false
	}
	if platform == "" {
		return true
	}
	return containsPlatformHash(v, platform)
}

func containsCommitValue(v any, commit string) bool {
	switch t := v.(type) {
	case map[string]any:
		for _, key := range []string{"source_commit", "vcs_revision"} {
			if s, ok := t[key].(string); ok && s == commit {
				return true
			}
		}
		for _, child := range t {
			if containsCommitValue(child, commit) {
				return true
			}
		}
	case []any:
		for _, item := range t {
			if containsCommitValue(item, commit) {
				return true
			}
		}
	}
	return false
}

func containsPlatformHash(v any, platform string) bool {
	switch t := v.(type) {
	case map[string]any:
		if p, _ := t["platform"].(string); p == platform {
			if sha, _ := t["sha256"].(string); strings.TrimSpace(sha) != "" {
				return true
			}
		}
		for _, child := range t {
			if containsPlatformHash(child, platform) {
				return true
			}
		}
	case []any:
		for _, item := range t {
			if containsPlatformHash(item, platform) {
				return true
			}
		}
	}
	return false
}

// resolveGitPath (and gitOutput below, its only caller) is claims-tooling's
// own offline reconciliation path -- verifying/regenerating claims.yaml
// against repo history, never a live governed run's authority path. Its
// exec.CommandContext(gitPath, ...) calls are out of Sol v9 P0-6's scope
// (sovereign Git execution inside a governed transaction). Swept 2026-07-19
// (rc3 Session 5); tracked for Session 8's exec.Command allowlist, not
// fixed here.
func resolveGitPath(portable bool) (string, error) {
	if !portable {
		gitPath, err := gitplumb.TrustedGitPath()
		if err != nil {
			return "", fmt.Errorf("resolve trusted git: %w", err)
		}
		return gitPath, nil
	}
	gitPath, err := exec.LookPath("git")
	if err != nil {
		return "", fmt.Errorf("resolve portable git: %w", err)
	}
	if canonical, cerr := filepath.EvalSymlinks(gitPath); cerr == nil {
		gitPath = canonical
	}
	return gitPath, nil
}

func gitOutput(repoRoot string, portable bool, args ...string) ([]byte, error) {
	gitPath, gerr := resolveGitPath(portable)
	if gerr != nil {
		return nil, gerr
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitPath, append([]string{"-C", repoRoot}, args...)...) // govratchet:exec-allow(release_tooling)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("%s", msg)
		}
		return nil, err
	}
	return out.Bytes(), nil
}

func gitCheck(repoRoot string, portable bool, args ...string) error {
	gitPath, gerr := resolveGitPath(portable)
	if gerr != nil {
		return gerr
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, gitPath, append([]string{"-C", repoRoot}, args...)...) // govratchet:exec-allow(release_tooling)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return fmt.Errorf("%s", msg)
		}
		return err
	}
	return nil
}

func gitShow(repoRoot string, portable bool, commit, path string) ([]byte, error) {
	gitPath, gerr := resolveGitPath(portable)
	if gerr != nil {
		return nil, gerr
	}
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	// Historical file paths are always repo-relative with forward slashes,
	// regardless of host OS path separators.
	ref := commit + ":" + filepath.ToSlash(path)
	cmd := exec.CommandContext(ctx, gitPath, "-C", repoRoot, "show", ref) // govratchet:exec-allow(release_tooling)
	var out, stderr bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg != "" {
			return nil, fmt.Errorf("%s", msg)
		}
		return nil, err
	}
	return out.Bytes(), nil
}

// symbolsInFile returns the set of top-level func/type/const/var names
// declared in a Go source file. Methods are indexed by name only, ignoring
// their receiver type, so `func (r *Runner) fallbackEligible(...)` matches
// the symbol name "fallbackEligible".
func symbolsInFile(path string) (map[string]bool, error) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		return nil, err
	}
	names := map[string]bool{}
	for _, decl := range f.Decls {
		switch d := decl.(type) {
		case *ast.FuncDecl:
			names[d.Name.Name] = true
		case *ast.GenDecl:
			for _, spec := range d.Specs {
				switch s := spec.(type) {
				case *ast.TypeSpec:
					names[s.Name.Name] = true
				case *ast.ValueSpec:
					for _, n := range s.Names {
						names[n.Name] = true
					}
				}
			}
		}
	}
	return names, nil
}

// caseLabelRE matches a single `case "a", "b", ...:` line and captures the
// full quoted-string list, which is then split out by quotedStringRE.
var caseLabelRE = regexp.MustCompile(`(?m)^\s*case\s+((?:"[^"]*"\s*,\s*)*"[^"]*")\s*:`)
var quotedStringRE = regexp.MustCompile(`"([^"]*)"`)

// cliReachable checks that every word of command after a leading "gov"
// appears as a `case "<word>":` label somewhere under cmd/gov. This proves
// the verb is a real dispatch target; it does not prove multi-word commands
// nest under each other exactly as written (a heuristic documented on
// CLIRef).
func cliReachable(repoRoot, command string) (bool, error) {
	words := strings.Fields(command)
	if len(words) == 0 {
		return false, fmt.Errorf("empty command")
	}
	if words[0] == "gov" {
		words = words[1:]
	}
	if len(words) == 0 {
		return false, fmt.Errorf("command has no verb after \"gov\"")
	}

	dir := filepath.Join(repoRoot, "cmd", "gov")
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false, err
	}
	labels := map[string]bool{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		content, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return false, err
		}
		for _, m := range caseLabelRE.FindAllStringSubmatch(string(content), -1) {
			for _, q := range quotedStringRE.FindAllStringSubmatch(m[1], -1) {
				labels[q[1]] = true
			}
		}
	}
	for _, w := range words {
		if !labels[w] {
			return false, nil
		}
	}
	return true, nil
}

// Report renders results as a doctor-style checklist, one line per claim,
// most-severe (lowest computed vs. claimed) first, and returns the process
// exit code CI should use.
func Report(results []Result) (string, int) {
	sorted := make([]Result, len(results))
	copy(sorted, results)
	sort.SliceStable(sorted, func(i, j int) bool {
		return sorted[i].ID < sorted[j].ID
	})

	var b strings.Builder
	exit := 0
	for _, r := range sorted {
		label := "OK"
		if !r.OK() {
			label = "FAIL"
			exit = 1
		}
		fmt.Fprintf(&b, "[%s] %-40s claimed=%-11s computed=%-11s\n", label, r.ID, r.ClaimedMaturity, r.ComputedMaturity)
		for _, p := range r.Problems {
			fmt.Fprintf(&b, "       - %s\n", p)
		}
	}
	if exit == 0 {
		fmt.Fprintf(&b, "claims: OK (%d claim(s) verified)\n", len(sorted))
	} else {
		fmt.Fprintln(&b, "claims: FAILED")
	}
	return b.String(), exit
}
