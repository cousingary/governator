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
	"context"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

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
}

// Claim is one docs/claims.yaml entry.
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
	results := make([]Result, 0, len(doc.Claims))
	for _, c := range doc.Claims {
		results = append(results, verifyOne(repoRoot, c))
	}
	return results, nil
}

// verifyOne walks the maturity ladder implemented -> tested -> accepted ->
// shipped, stopping as soon as it reaches the claim's own claimed_maturity.
// It never probes (or reports problems for) a tier the claim doesn't assert
// it has reached — a claim that only claims "tested" is not penalized for
// lacking acceptance evidence it never promised.
func verifyOne(repoRoot string, c Claim) Result {
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

	shipped, problems := verifyShipped(repoRoot, c)
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
func verifyShipped(repoRoot string, c Claim) (bool, []string) {
	if c.BinaryBuildEvidence == nil {
		return false, []string{"absent from shipped binary: claim declares no binary_build_evidence"}
	}
	be := c.BinaryBuildEvidence
	var problems []string
	ok := true

	if err := gitCheck(repoRoot, "cat-file", "-e", be.Commit+"^{commit}"); err != nil {
		return false, []string{fmt.Sprintf("absent from shipped binary: commit %s not found: %v", be.Commit, err)}
	}
	if err := gitCheck(repoRoot, "merge-base", "--is-ancestor", be.Commit, "HEAD"); err != nil {
		ok = false
		problems = append(problems, fmt.Sprintf("absent from shipped binary: commit %s is not an ancestor of HEAD", be.Commit))
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
		} else if !evidenceRecordsCommit(parsed, be.Commit, be.Platform) {
			ok = false
			problems = append(problems, fmt.Sprintf("absent from shipped binary: evidence file %s does not record commit %s with a binary hash", be.EvidenceFile, be.Commit))
		}
	}

	for _, fs := range c.Implementation {
		blob, err := gitShow(repoRoot, be.Commit, fs.File)
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

func gitCheck(repoRoot string, args ...string) error {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", append([]string{"-C", repoRoot}, args...)...)
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

func gitShow(repoRoot, commit, path string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	defer cancel()
	// Historical file paths are always repo-relative with forward slashes,
	// regardless of host OS path separators.
	ref := commit + ":" + filepath.ToSlash(path)
	cmd := exec.CommandContext(ctx, "git", "-C", repoRoot, "show", ref)
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
