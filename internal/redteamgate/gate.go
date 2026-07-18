// Package redteamgate implements the identity-based release gate that
// Session 7 (agents/governator-sol-upgrade7-plan.md, HS4) replaces the old
// count-based gate with: MIN_REDTEAM_TESTS/EXPECTED_REDTEAM_SKIPS validated
// how many tests ran and how many skipped, never which ones — so the wrong
// test skipping at the same total count passed the gate. This package
// checks exact test identity instead: every manifest-required case present,
// passing, and not-drifted; every skip individually authorized by name.
package redteamgate

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is internal/redteam/manifest.yaml: the single source of truth for
// the mandatory final attack corpus.
type Manifest struct {
	Version int         `yaml:"version"`
	Cases   []CaseEntry `yaml:"cases"`
}

// CaseEntry describes one corpus case's identity and release-gating policy.
// See manifest.yaml's header comment for the full field contract.
type CaseEntry struct {
	Case        int          `yaml:"case"`
	Name        string       `yaml:"name"`
	Session     string       `yaml:"session"`
	Required    bool         `yaml:"required"`
	Conditional bool         `yaml:"conditional"`
	AllowedSkip *AllowedSkip `yaml:"allowed_skip,omitempty"`
	Status      string       `yaml:"status,omitempty"`
}

// AllowedSkip is the only sanctioned way a required case may be absent from
// a passing run: an environment-capability predicate plus the exact skip
// reason the gate expects at that name.
type AllowedSkip struct {
	Predicate string `yaml:"predicate"`
	Reason    string `yaml:"reason"`
}

// LoadManifest reads and validates internal/redteam/manifest.yaml. It
// rejects a manifest with a blank or duplicated case name outright — those
// are exactly the drift conditions the gate exists to catch, so the
// manifest itself must not already contain them.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("redteamgate: read manifest: %w", err)
	}
	var m Manifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return Manifest{}, fmt.Errorf("redteamgate: parse manifest: %w", err)
	}
	seen := make(map[string]bool, len(m.Cases))
	for _, c := range m.Cases {
		if strings.TrimSpace(c.Name) == "" {
			return Manifest{}, fmt.Errorf("redteamgate: manifest case %d has no name", c.Case)
		}
		if seen[c.Name] {
			return Manifest{}, fmt.Errorf("redteamgate: manifest has duplicate case name %s", c.Name)
		}
		seen[c.Name] = true
	}
	return m, nil
}

// Outcome is one test's result as observed in a `go test -v` text log.
type Outcome struct {
	Name   string
	Result string // PASS, FAIL, SKIP
	Reason string // best-effort: buffered output emitted while the test ran, trimmed
}

var (
	resultLineRE = regexp.MustCompile(`^--- (PASS|FAIL|SKIP): (\S+) \(`)
	runLineRE    = regexp.MustCompile(`^=== RUN\s+(\S+)`)
	vCaseNameRE  = regexp.MustCompile(`^TestV\d+Case\d+`)
)

// ParseVerboseLog extracts one Outcome per test from `go test -v` output.
// Text, not -json: the existing release/CI tooling already captures text
// logs (scripts/release.sh's run_tier), so this reuses that evidence format
// rather than introducing a second, divergent one. Tracks nested/sequential
// "=== RUN" blocks via a stack so buffered log lines attach to whichever
// test most recently started and hasn't yet reported a result.
func ParseVerboseLog(log string) map[string]Outcome {
	outcomes := make(map[string]Outcome)
	var stack []string
	buffers := make(map[string]*strings.Builder)
	scanner := bufio.NewScanner(strings.NewReader(log))
	scanner.Buffer(make([]byte, 0, 64*1024), 10*1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if m := runLineRE.FindStringSubmatch(line); m != nil {
			name := m[1]
			stack = append(stack, name)
			buffers[name] = &strings.Builder{}
			continue
		}
		if m := resultLineRE.FindStringSubmatch(line); m != nil {
			result, name := m[1], m[2]
			reason := ""
			if b, ok := buffers[name]; ok {
				reason = strings.TrimSpace(b.String())
			}
			outcomes[name] = Outcome{Name: name, Result: result, Reason: reason}
			for i := len(stack) - 1; i >= 0; i-- {
				if stack[i] == name {
					stack = append(stack[:i], stack[i+1:]...)
					break
				}
			}
			continue
		}
		if len(stack) > 0 {
			top := stack[len(stack)-1]
			if b, ok := buffers[top]; ok {
				trimmed := strings.TrimSpace(line)
				if trimmed != "" {
					if b.Len() > 0 {
						b.WriteByte('\n')
					}
					b.WriteString(trimmed)
				}
			}
		}
	}
	return outcomes
}

// Result is the identity-based gate's verdict over one redteam run.
type Result struct {
	OK              bool     `json:"ok"`
	Discovered      int      `json:"discovered"`
	Run             int      `json:"run"`
	Skipped         int      `json:"skipped"`
	Failed          int      `json:"failed"`
	MissingTests    []string `json:"missing_tests,omitempty"`
	UnexpectedTests []string `json:"unexpected_tests,omitempty"`
	FailedTests     []string `json:"failed_tests,omitempty"`
	UnexpectedSkips []string `json:"unexpected_skips,omitempty"`
	Problems        []string `json:"problems,omitempty"`
}

// Evaluate checks a parsed `go test -v -tags redteam` log against the
// manifest:
//   - every manifest case must be present in the log (no MissingTests);
//   - every TestV*Case* test found in the log must be in the manifest (no
//     UnexpectedTests — this is the name-drift check);
//   - zero FailedTests anywhere in the suite;
//   - every SKIP must be individually authorized: the manifest entry must be
//     `conditional` with an `allowed_skip` whose predicate capability is
//     actually absent from the current environment and whose reason matches
//     the observed skip text (see skipAllowed). Anything else is an
//     UnexpectedSkip and blocks the release — this is the exact HS4 defect
//     ("the wrong test skipping while the count stays the same") this gate
//     replaces the old count-based check to close.
func Evaluate(manifest Manifest, log string, capabilities map[string]bool) Result {
	outcomes := ParseVerboseLog(log)
	var res Result
	byName := make(map[string]CaseEntry, len(manifest.Cases))
	for _, c := range manifest.Cases {
		byName[c.Name] = c
	}

	for name, o := range outcomes {
		c, known := byName[name]
		// A name outside the manifest is only in scope here if it *claims*
		// to be part of this corpus (TestV*Case* prefix) — that is the
		// name-drift signal (UnexpectedTests). An unrelated package test
		// (a helper, a v6 TestAttackN/TestV6CaseN case, anything not
		// claiming manifest membership) is not this gate's concern and must
		// not be silently absorbed into pass/fail/skip counts that are
		// supposed to describe the manifest-defined corpus specifically. A name that
		// *is* in the manifest is always processed, regardless of its
		// literal prefix — manifest membership, not string shape, is the
		// source of truth for "is this a corpus case."
		if !known && !vCaseNameRE.MatchString(name) {
			continue
		}
		res.Discovered++
		switch o.Result {
		case "PASS":
			res.Run++
		case "FAIL":
			res.Run++
			res.Failed++
			res.FailedTests = append(res.FailedTests, name)
		case "SKIP":
			res.Skipped++
		}
		if !known {
			res.UnexpectedTests = append(res.UnexpectedTests, name)
			continue
		}
		if o.Result == "SKIP" && !skipAllowed(c, o.Reason, capabilities) {
			res.UnexpectedSkips = append(res.UnexpectedSkips, name)
		}
	}

	for _, c := range manifest.Cases {
		if _, found := outcomes[c.Name]; !found {
			res.MissingTests = append(res.MissingTests, c.Name)
		}
	}

	sort.Strings(res.UnexpectedTests)
	sort.Strings(res.FailedTests)
	sort.Strings(res.UnexpectedSkips)
	sort.Strings(res.MissingTests)

	res.OK = len(res.MissingTests) == 0 &&
		len(res.UnexpectedTests) == 0 &&
		len(res.FailedTests) == 0 &&
		len(res.UnexpectedSkips) == 0

	if len(res.MissingTests) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("missing required corpus test(s): %s", strings.Join(res.MissingTests, ", ")))
	}
	if len(res.UnexpectedTests) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("unmanifested TestV*Case* test(s) found (name drift): %s", strings.Join(res.UnexpectedTests, ", ")))
	}
	if len(res.FailedTests) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("failed corpus test(s): %s", strings.Join(res.FailedTests, ", ")))
	}
	if len(res.UnexpectedSkips) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("unexpected skip(s) (not an authorized manifest conditional): %s", strings.Join(res.UnexpectedSkips, ", ")))
	}
	return res
}

// skipAllowed reports whether a case's SKIP is the one sanctioned exception
// to "every required case must pass": the manifest marks it conditional with
// an allowed_skip, the named capability is genuinely absent from this
// environment (present => the case should have run for real, so a skip is
// unexpected), and the observed reason contains the manifest's expected
// text. A capability key absent from the map is treated as "not present"
// (permissive) — recording every predicate a manifest references in
// test-summary.json's environment_capabilities is the release pipeline's
// responsibility, not this function's.
func skipAllowed(c CaseEntry, reason string, capabilities map[string]bool) bool {
	if !c.Conditional || c.AllowedSkip == nil {
		return false
	}
	if c.AllowedSkip.Predicate != "" && capabilities[c.AllowedSkip.Predicate] {
		return false
	}
	if c.AllowedSkip.Reason == "" {
		return true
	}
	return strings.Contains(reason, c.AllowedSkip.Reason)
}
