// Package redteamgate implements the identity-based release gate that
// Session 7 (agents/governator-sol-upgrade7-plan.md, HS4) replaces the old
// count-based gate with: MIN_REDTEAM_TESTS/EXPECTED_REDTEAM_SKIPS validated
// how many tests ran and how many skipped, never which ones — so the wrong
// test skipping at the same total count passed the gate. This package
// checks exact test identity instead: every manifest-required case present,
// passing, and not-drifted; every skip individually authorized by name.
//
// Sol12 rc5 Session 1 (agents/governator-sol-upgrade12-rc5-plan.md,
// P0-2/P0-3/P1-8) closes the release-truth defects in that model:
//
//   - P0-2: the gate no longer scopes "what is a corpus test" by a stale
//     TestV(7|8)Case regex. The authoritative inventory is supplied by the
//     caller (release.sh discovers it from //go:build redteam-tagged source),
//     and every inventory test must be either a manifest case or a documented
//     exclusion. A versioned-but-unmanifested security test (V9/V10/V11/...)
//     or any skipped security test outside the manifest now blocks the gate.
//   - P0-3: capability evidence is tri-state (present | absent | unknown).
//     Only explicitly proven absence authorizes a capability-conditioned
//     skip; a predicate the manifest references but the capability record
//     does not prove is CAPABILITY_EVIDENCE_INCOMPLETE and blocks the gate.
//   - P1-8: the manifest is decoded strictly (KnownFields, duplicate-key
//     rejection, status/case-number/name uniqueness, a known-predicate
//     registry, and conditional/allowed-skip consistency). The manifest is a
//     release security policy and parses as strictly as a contract.
package redteamgate

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Manifest is internal/redteam/manifest.yaml: the single source of truth for
// the mandatory final attack corpus plus the explicit non-production
// exclusions that let the gate account for every discovered security test.
type Manifest struct {
	Version    int              `yaml:"version"`
	Cases      []CaseEntry      `yaml:"cases"`
	Exclusions []ExclusionEntry `yaml:"exclusions,omitempty"`
}

// CaseEntry describes one corpus case's identity and release-gating policy.
// See manifest.yaml's header comment for the full field contract.
type CaseEntry struct {
	Case                int          `yaml:"case"`
	Name                string       `yaml:"name"`
	Session             string       `yaml:"session"`
	Required            bool         `yaml:"required"`
	Conditional         bool         `yaml:"conditional"`
	AllowedSkip         *AllowedSkip `yaml:"allowed_skip,omitempty"`
	AttestationCategory string       `yaml:"attestation_category,omitempty"`
	Status              string       `yaml:"status,omitempty"`
}

// AllowedSkip is the only sanctioned way a required case may be absent from
// a passing run: an environment-capability predicate plus the exact skip
// reason the gate expects at that name.
type AllowedSkip struct {
	Predicate string `yaml:"predicate"`
	Reason    string `yaml:"reason"`
}

// ExclusionEntry is P0-2's explicit classification for an inventoried test
// outside the corpus. Superseded exclusions name the exact passing replacement
// tests; non-production helpers may remain excluded with a documented reason.
type ExclusionEntry struct {
	Name             string   `yaml:"name"`
	Status           string   `yaml:"status,omitempty"`
	ReplacementTests []string `yaml:"replacement_tests,omitempty"`
	Reason           string   `yaml:"reason"`
}

// CapabilityState is the proven state of one environment capability. Only
// CapabilityPresent and CapabilityAbsent are "proven"; a predicate the
// manifest references but whose record is absent from the supplied
// capability map is CapabilityUnknown (the implicit third state), which is
// CAPABILITY_EVIDENCE_INCOMPLETE and may never authorize a skip (Sol12 P0-3).
type CapabilityState string

const (
	CapabilityPresent CapabilityState = "present"
	CapabilityAbsent  CapabilityState = "absent"
)

// CapabilityRecord is the tri-state evidence for one capability predicate
// (Sol12 P0-3). A record carries the probe identity, observed result, host
// and platform identity, timestamp, and an evidence hash so the record is
// self-describing evidence rather than a bare boolean. State must be
// CapabilityPresent or CapabilityAbsent; any other value is treated as
// unproven (CAPABILITY_EVIDENCE_INCOMPLETE).
type CapabilityRecord struct {
	State        CapabilityState `yaml:"state" json:"state"`
	Probe        string          `yaml:"probe" json:"probe"`
	Result       string          `yaml:"result" json:"result"`
	HostIdentity string          `yaml:"host_identity" json:"host_identity"`
	Platform     string          `yaml:"platform" json:"platform"`
	Timestamp    string          `yaml:"timestamp" json:"timestamp"`
	EvidenceHash string          `yaml:"evidence_hash" json:"evidence_hash"`
}

// KnownPredicates is the registry of capability predicate names a manifest's
// allowed_skip may reference (Sol12 P1-8: "a known-predicate registry").
// A manifest referencing a predicate not in this set fails load — that is
// the structural/typo rejection; a predicate that loads but is not proven in
// the supplied capability record fails the gate (P0-3). Extend this set when
// a new capability probe is added (Sessions 5/6 add Docker/Darwin hosts).
var KnownPredicates = map[string]bool{
	"has_systemd_user":                  true,
	"no_systemd_user":                   true,
	"has_second_uid":                    true,
	"has_kernel_landlock_full_abi":      true,
	"linux":                             true,
	"case8_hangfuse_extinction_fixture": true,
	"git_trusted":                       true,
	"proc1_fd_unreadable":               true,
	// has_docker_daemon: Session 5 (Sol12 P0-8/P2 "Docker tests need a real
	// release host"). True only when a `docker info` round trip against a
	// live daemon succeeds; case 31's real-daemon consumed-artifact-volume
	// acceptance test is authorized to skip only when this is proven absent.
	"has_docker_daemon": true,
	// has_darwin_native_host: Session 6 (Sol12 P1-1 "Darwin production
	// support is unproven"). True only when this host's own GOOS is
	// literally darwin -- cases 34/35's real native containment/Assayer
	// acceptance tests are authorized to skip only when this is proven
	// absent (every host this project runs on today).
	"has_darwin_native_host":  true,
	"fallback_path_exercised": true,
}

// allowedStatusValues enumerates the only status: values a manifest case may
// carry (P1-8: "allowed status enumeration").
var allowedStatusValues = map[string]bool{
	"implemented":         true,
	"not_yet_implemented": true,
}

var allowedAttestationCategories = map[string]bool{
	AttestationCategoryCore:           true,
	AttestationCategorySystemdEnabled: true,
	AttestationCategoryDockerEnabled:  true,
	AttestationCategoryFallbackHost:   true,
	AttestationCategoryDarwin:         true,
}

var allowedExclusionStatusValues = map[string]bool{
	"superseded":     true,
	"non-production": true,
}

// LoadManifest reads and strictly validates internal/redteam/manifest.yaml
// (Sol12 P1-8). Strictness: yaml.v3 KnownFields rejects unknown fields and
// duplicate YAML mapping keys; every case has a non-empty unique name and a
// unique case number; status (when set) is in the allowed enumeration; every
// conditional case carries a consistent allowed_skip whose predicate is in
// KnownPredicates; every exclusion has a non-empty unique name and a
// documented reason. The manifest is a release security policy and must
// parse as strictly as a contract — permissive decode is exactly the defect
// this closes.
func LoadManifest(path string) (Manifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Manifest{}, fmt.Errorf("redteamgate: read manifest: %w", err)
	}
	// KnownFields(true) rejects unknown fields; yaml.v3 also rejects
	// duplicate mapping keys during decode, so a duplicated YAML key (P1-8
	// case 11) fails here rather than silently last-wins.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("redteamgate: parse manifest: %w", err)
	}
	if err := validateManifest(m); err != nil {
		return Manifest{}, err
	}
	return m, nil
}

// validateManifest performs the semantic strictness checks that KnownFields
// alone cannot express.
func validateManifest(m Manifest) error {
	seenName := make(map[string]bool, len(m.Cases))
	seenCase := make(map[int]bool, len(m.Cases))
	for _, c := range m.Cases {
		if strings.TrimSpace(c.Name) == "" {
			return fmt.Errorf("redteamgate: manifest case %d has no name", c.Case)
		}
		if seenName[c.Name] {
			return fmt.Errorf("redteamgate: manifest has duplicate case name %s", c.Name)
		}
		seenName[c.Name] = true
		if seenCase[c.Case] {
			return fmt.Errorf("redteamgate: manifest has duplicate case number %d", c.Case)
		}
		seenCase[c.Case] = true
		if c.Status != "" && !allowedStatusValues[c.Status] {
			return fmt.Errorf("redteamgate: manifest case %d (%s) has unknown status %q", c.Case, c.Name, c.Status)
		}
		if c.AttestationCategory != "" && !allowedAttestationCategories[c.AttestationCategory] {
			return fmt.Errorf("redteamgate: manifest case %d (%s) has unknown attestation category %q", c.Case, c.Name, c.AttestationCategory)
		}
		if c.Conditional {
			if c.AllowedSkip == nil {
				return fmt.Errorf("redteamgate: manifest case %d (%s) is conditional without an allowed_skip", c.Case, c.Name)
			}
			pred := strings.TrimSpace(c.AllowedSkip.Predicate)
			if pred == "" {
				return fmt.Errorf("redteamgate: manifest case %d (%s) conditional allowed_skip has no predicate", c.Case, c.Name)
			}
			if !KnownPredicates[pred] {
				return fmt.Errorf("redteamgate: manifest case %d (%s) references unknown capability predicate %q", c.Case, c.Name, pred)
			}
		} else if c.AllowedSkip != nil {
			return fmt.Errorf("redteamgate: manifest case %d (%s) has allowed_skip but is not conditional", c.Case, c.Name)
		}
	}
	seenExcl := make(map[string]bool, len(m.Exclusions))
	for _, e := range m.Exclusions {
		if strings.TrimSpace(e.Name) == "" {
			return fmt.Errorf("redteamgate: manifest exclusion has no name")
		}
		if seenExcl[e.Name] {
			return fmt.Errorf("redteamgate: manifest has duplicate exclusion name %s", e.Name)
		}
		seenExcl[e.Name] = true
		if strings.TrimSpace(e.Reason) == "" {
			return fmt.Errorf("redteamgate: manifest exclusion %s has no documented reason", e.Name)
		}
		if e.Status != "" && !allowedExclusionStatusValues[e.Status] {
			return fmt.Errorf("redteamgate: manifest exclusion %s has unknown status %q", e.Name, e.Status)
		}
		if e.Status == "superseded" && len(e.ReplacementTests) == 0 {
			return fmt.Errorf("redteamgate: superseded exclusion %s has no replacement_tests", e.Name)
		}
		// An exclusion must not shadow a real corpus case — that would be a
		// way to silently retire an attack by reclassifying it as
		// non-production.
		if seenName[e.Name] {
			return fmt.Errorf("redteamgate: manifest exclusion %s is also a corpus case", e.Name)
		}
	}
	return nil
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
	OK                     bool     `json:"ok"`
	Discovered             int      `json:"discovered"`
	Run                    int      `json:"run"`
	Skipped                int      `json:"skipped"`
	Failed                 int      `json:"failed"`
	MissingTests           []string `json:"missing_tests,omitempty"`
	UnexpectedTests        []string `json:"unexpected_tests,omitempty"`
	FailedTests            []string `json:"failed_tests,omitempty"`
	UnexpectedSkips        []string `json:"unexpected_skips,omitempty"`
	IncompleteCapabilities []string `json:"incomplete_capabilities,omitempty"`
	RequireZeroSkips       bool     `json:"require_zero_skips"`
	InventorySupplied      bool     `json:"inventory_supplied"`
	Problems               []string `json:"problems,omitempty"`
}

// Evaluate checks a parsed `go test -v -tags redteam` log against the
// manifest with no extra options (ordinary development CI). It delegates to
// EvaluateWithOptions; production callers pass RequireZeroSkips and a
// DiscoveredTests inventory through Options.
func Evaluate(manifest Manifest, log string, capabilities map[string]CapabilityRecord) Result {
	return EvaluateWithOptions(manifest, log, capabilities, Options{})
}

// Options tunes Evaluate's policy for the caller's release mode.
type Options struct {
	// RequireZeroSkips is P1-3 (Sol10 rc4 Session 8): a production release
	// must not rely on a kernel-dependent conditional skip for a
	// security-sensitive invariant, no matter how well-authorized that
	// skip is by the manifest's normal allowed_skip mechanism. When set,
	// ANY skip -- authorized or not -- blocks the release; conditional
	// skips stay available only for ordinary development CI runs that
	// leave this unset.
	//
	// Sol13 Session 3: when Attestations are supplied, RequireZeroSkips
	// means "zero skips without a category-matched signed host pass". A
	// non-approving category or local evidence that a capability is absent
	// never substitutes for an execution on an appropriate host.
	RequireZeroSkips bool

	// DiscoveredTests is the authoritative inventory of every release-
	// relevant red-team test discovered from source (Sol12 P0-2): release.sh
	// enumerates the //go:build redteam-tagged test functions and passes
	// them here. When supplied, every inventory test that appears in the log
	// must be either a manifest corpus case or a documented exclusion, and
	// every inventory test must appear in the log. When empty the gate
	// operates in manifest-only mode (backward compatible with pre-Sol12
	// callers) but records InventorySupplied=false so production evidence
	// shows the inventory was not bound — release.sh always supplies it.
	DiscoveredTests []string

	// Attestations is the aggregated capability-host attestation set
	// (Session 9). When non-empty and RequireZeroSkips is set, a skip is
	// covered (not a gap) if SkipCoveredByAttestations reports true.
	Attestations *AggregationResult
}

// EvaluateWithOptions is the identity-based gate. Over one parsed redteam
// log it enforces:
//   - every manifest case is present in the log (no MissingTests);
//   - every supplied inventory test is present in the log and is either a
//     manifest case or a documented exclusion (no unmanifested drift, no
//     missing expected test) — P0-2;
//   - zero FailedTests among manifest cases or inventory tests;
//   - every SKIP is individually authorized: development CI requires a
//     conditional manifest entry whose predicate is explicitly proven ABSENT;
//     production requires an exact category-matched signed host pass; and
//     whose reason matches the observed skip text;
//   - every predicate any manifest case references is proven in the supplied
//     capability record (present or absent); a missing/unknown predicate is
//     CAPABILITY_EVIDENCE_INCOMPLETE and blocks the release — P0-3.
func EvaluateWithOptions(manifest Manifest, log string, capabilities map[string]CapabilityRecord, opts Options) Result {
	outcomes := ParseVerboseLog(log)
	var res Result
	res.RequireZeroSkips = opts.RequireZeroSkips
	res.InventorySupplied = len(opts.DiscoveredTests) > 0

	byName := make(map[string]CaseEntry, len(manifest.Cases))
	for _, c := range manifest.Cases {
		byName[c.Name] = c
	}
	excluded := make(map[string]ExclusionEntry, len(manifest.Exclusions))
	for _, e := range manifest.Exclusions {
		excluded[e.Name] = e
	}
	inventory := make(map[string]bool, len(opts.DiscoveredTests))
	for _, n := range opts.DiscoveredTests {
		inventory[n] = true
	}

	// P0-3: every predicate the manifest references must be proven in the
	// supplied capability record. Collect them first so an incomplete record
	// blocks regardless of whether the corresponding case actually skipped.
	manifestPredicates := make(map[string]bool)
	for _, c := range manifest.Cases {
		if c.Conditional && c.AllowedSkip != nil && c.AllowedSkip.Predicate != "" {
			manifestPredicates[c.AllowedSkip.Predicate] = true
		}
	}
	for pred := range manifestPredicates {
		rec, ok := capabilities[pred]
		if !ok {
			res.IncompleteCapabilities = append(res.IncompleteCapabilities, pred+" (missing from capability record)")
		} else if rec.State != CapabilityPresent && rec.State != CapabilityAbsent {
			res.IncompleteCapabilities = append(res.IncompleteCapabilities, pred+" (state not proven: "+string(rec.State)+")")
		}
	}

	// Classify every outcome in the log. A test is "in scope" for the gate
	// if it is a manifest case OR a member of the supplied inventory. An
	// unrelated package test (not manifest, not inventoried) is ignored, so
	// unit tests compiled under -tags redteam do not pollute the corpus
	// tallies.
	for name, o := range outcomes {
		c, knownCase := byName[name]
		inInv := inventory[name]
		if !knownCase && !inInv {
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
		if !knownCase {
			// In the inventory but not a corpus case: it must be a
			// documented exclusion, or it is unmanifested drift (P0-2).
			if _, isExcluded := excluded[name]; !isExcluded {
				res.UnexpectedTests = append(res.UnexpectedTests, name)
			}
			continue
		}
		if o.Result == "SKIP" {
			if opts.RequireZeroSkips {
				if opts.Attestations != nil && SkipCoveredByAttestations(name, *opts.Attestations, c) {
					// Session 9: skip is accounted for by the aggregated
					// attestation set — not a gap.
				} else {
					res.UnexpectedSkips = append(res.UnexpectedSkips, name)
				}
			} else if !skipAllowed(c, o.Reason, capabilities) {
				res.UnexpectedSkips = append(res.UnexpectedSkips, name)
			}
		}
	}

	// P0-2: every manifest case must appear in the log, and every supplied
	// inventory test must appear in the log (a discovered security test that
	// never ran is "a missing expected test").
	for _, c := range manifest.Cases {
		if _, found := outcomes[c.Name]; !found {
			res.MissingTests = append(res.MissingTests, c.Name)
		}
	}
	for _, n := range opts.DiscoveredTests {
		if _, found := outcomes[n]; !found {
			// Don't double-report a name already counted as a missing
			// manifest case (a manifest case can also be in the inventory).
			if _, isCase := byName[n]; !isCase {
				res.MissingTests = append(res.MissingTests, n)
			}
		}
	}
	for _, e := range manifest.Exclusions {
		for _, replacement := range e.ReplacementTests {
			outcome, inLog := outcomes[replacement]
			// Requiring inventory[replacement] unconditionally would break
			// the documented manifest-only backward-compat mode (no
			// DiscoveredTests supplied) the instant ANY exclusion carries
			// replacement_tests, regardless of what actually passed in the
			// log -- res.InventorySupplied already records whether the
			// stronger P0-2 membership guarantee applies; only enforce it
			// then. Manifest-only callers still get the real guarantee that
			// matters without an inventory: the replacement genuinely ran
			// and passed.
			if (res.InventorySupplied && !inventory[replacement]) || !inLog || outcome.Result != "PASS" {
				res.Problems = append(res.Problems, fmt.Sprintf("exclusion %s replacement %s is not an inventoried passing test", e.Name, replacement))
			}
		}
	}

	sort.Strings(res.UnexpectedTests)
	sort.Strings(res.FailedTests)
	sort.Strings(res.UnexpectedSkips)
	sort.Strings(res.MissingTests)
	sort.Strings(res.IncompleteCapabilities)

	res.OK = len(res.MissingTests) == 0 &&
		len(res.UnexpectedTests) == 0 &&
		len(res.FailedTests) == 0 &&
		len(res.UnexpectedSkips) == 0 &&
		len(res.IncompleteCapabilities) == 0 &&
		len(res.Problems) == 0

	if len(res.MissingTests) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("missing required corpus test(s): %s", strings.Join(res.MissingTests, ", ")))
	}
	if len(res.UnexpectedTests) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("unmanifested security test(s) found (not a corpus case and not a documented exclusion): %s", strings.Join(res.UnexpectedTests, ", ")))
	}
	if len(res.FailedTests) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("failed corpus test(s): %s", strings.Join(res.FailedTests, ", ")))
	}
	if len(res.IncompleteCapabilities) > 0 {
		res.Problems = append(res.Problems, fmt.Sprintf("CAPABILITY_EVIDENCE_INCOMPLETE (P0-3): predicate(s) not proven present/absent in the capability record: %s", strings.Join(res.IncompleteCapabilities, ", ")))
	}
	if len(res.UnexpectedSkips) > 0 {
		if opts.RequireZeroSkips {
			res.Problems = append(res.Problems, fmt.Sprintf("production mode requires zero red-team skips (P1-3): %s", strings.Join(res.UnexpectedSkips, ", ")))
		} else {
			res.Problems = append(res.Problems, fmt.Sprintf("unexpected skip(s) (capability not proven absent, or reason mismatch): %s", strings.Join(res.UnexpectedSkips, ", ")))
		}
	}
	return res
}

// skipAllowed reports whether a case's SKIP is the one sanctioned exception
// to "every required case must pass": the manifest marks it conditional with
// an allowed_skip, the named capability is explicitly proven ABSENT from
// this environment (present => the case should have run for real; unknown =>
// CAPABILITY_EVIDENCE_INCOMPLETE, handled above), and the observed reason
// contains the manifest's expected text. This is the tri-state correction
// (Sol12 P0-3): a predicate missing from the record no longer collapses to
// "absent" and authorize a skip.
func skipAllowed(c CaseEntry, reason string, capabilities map[string]CapabilityRecord) bool {
	if !c.Conditional || c.AllowedSkip == nil {
		return false
	}
	pred := c.AllowedSkip.Predicate
	if pred != "" {
		rec, ok := capabilities[pred]
		if !ok {
			return false // unknown — never authorizes a skip
		}
		if rec.State == CapabilityPresent {
			return false // capability present: the case should have run
		}
		if rec.State != CapabilityAbsent {
			return false // unproven state
		}
	}
	if c.AllowedSkip.Reason == "" {
		return true
	}
	return strings.Contains(reason, c.AllowedSkip.Reason)
}
