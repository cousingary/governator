package redteamgate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Attestation categories for the rc5 release (Sol12 P0-2/P0-3, Session 1
// W3). Each category names a differently-capable host whose environment a
// single core host cannot reproduce (live systemd vs. absent systemd; a
// functioning Docker daemon; a fallback-path fixture host; a Darwin native
// host if Darwin ships). The final release gate aggregates one signed
// attestation per required category, each bound to the same release
// identity, and accepts the release only when the aggregate covers every
// manifest case's required host (Session 9).
const (
	// AttestationCategoryCore is the primary release host: runs the locally
	// runnable red-team inventory (every case that does not require a host
	// capability this host lacks). Always required.
	AttestationCategoryCore = "core"
	// AttestationCategorySystemdEnabled covers cases requiring a live
	// systemd --user manager (has_systemd_user). Required when any case
	// whose sibling skips on a systemd-enabled host is enrolled.
	AttestationCategorySystemdEnabled = "systemd-enabled"
	// AttestationCategoryDockerEnabled covers the Docker red-team corpus
	// (Session 5): consumed artifacts, in-container identity, lifecycle and
	// extinction, network/hardening. Requires a functioning daemon.
	AttestationCategoryDockerEnabled = "docker-enabled"
	// AttestationCategoryFallbackHost covers the mutually-exclusive
	// "capability absent" path (e.g. no systemd --user) proved deterministically
	// off-host rather than by crippling the core host (Session 2).
	AttestationCategoryFallbackHost = "fallback-path"
	// AttestationCategoryDarwin covers Darwin native acceptance, or is
	// replaced by an explicit non-approving declaration if rc5 ships
	// Linux-only (Session 6).
	AttestationCategoryDarwin = "darwin"
)

// RequiredAttestationCategories is the set of host categories the rc5
// release aggregates (Session 9). Darwin is included; a non-approving
// declaration substitutes for it if rc5 is Linux-only (Session 6 decides).
var RequiredAttestationCategories = []string{
	AttestationCategoryCore,
	AttestationCategorySystemdEnabled,
	AttestationCategoryDockerEnabled,
	AttestationCategoryFallbackHost,
	AttestationCategoryDarwin,
}

// CapabilityAttestation is the signed evidence one capability host emits
// (Sol12 P0-2 binding + P0-3 record). The final gate may aggregate
// attestations from differently-capable hosts ONLY when every one is bound
// to the same release identity (Session 9 enforces via BindingConsistent).
// Sessions 5 and 6 produce real attestations against this schema; Session 9
// aggregates them. This type is the schema those sessions fill in.
type CapabilityAttestation struct {
	// Category is one of AttestationCategory*; identifies which host
	// capability this attestation covers.
	Category string `yaml:"category" json:"category"`

	// Binding: all attestations aggregated for one release must share these
	// six identities, or they describe different releases and may not be
	// combined (report P0-2 "the final release gate may aggregate these
	// attestations only when all are bound to").
	GovernatorCommit string `yaml:"governator_commit" json:"governator_commit"`
	AssayerCommit    string `yaml:"assayer_commit" json:"assayer_commit"`
	TestSourceHash   string `yaml:"test_source_hash" json:"test_source_hash"`
	// TestBinarySHA256 is the aggregate SHA-256 over the ordered compiled
	// red-team test-binary set. It prevents a source-selection or compiler
	// difference from being hidden behind a matching source hash.
	TestBinarySHA256 string `yaml:"test_binary_sha256" json:"test_binary_sha256"`
	ToolchainHash    string `yaml:"toolchain_hash" json:"toolchain_hash"`
	ReleaseVersion   string `yaml:"release_version" json:"release_version"`

	// Host identity: who/where this attestation was produced on.
	HostIdentity string `yaml:"host_identity" json:"host_identity"`
	Platform     string `yaml:"platform" json:"platform"`

	// Capabilities is the tri-state record (P0-3) this host proves: every
	// predicate the manifest references that this host is responsible for.
	Capabilities map[string]CapabilityRecord `yaml:"capabilities" json:"capabilities"`

	// CoveredTests names the manifest cases this attestation accounts for
	// on this host (ran and passed). The aggregate over all attestations
	// must cover every manifest case (Session 9).
	CoveredTests []string `yaml:"covered_tests,omitempty" json:"covered_tests,omitempty"`

	// NonApproving declares that this attestation's category does not claim
	// production approval for this release (Session 6: Darwin non-approving).
	// Tests covered exclusively by a non-approving category are not gaps —
	// the release simply does not claim that platform.
	NonApproving bool `yaml:"non_approving,omitempty" json:"non_approving,omitempty"`

	// Signature over the canonical (sorted-key) JSON of every field above
	// except Signature itself. Minisign (upgrade-11 Session 1) is the
	// release signature scheme; this field carries the detached signature.
	Signature string `yaml:"signature,omitempty" json:"signature,omitempty"`
	Timestamp string `yaml:"timestamp" json:"timestamp"`
}

// BindingConsistent reports whether every attestation in the set is bound to
// the same release identity (the same six binding fields), the prerequisite
// for aggregating differently-capable hosts into one release verdict. A
// mismatched binding means two attestations describe different releases and
// must not be combined (report P0-2).
func BindingConsistent(atts []CapabilityAttestation) (bool, string) {
	if len(atts) == 0 {
		return false, "no capability attestations supplied"
	}
	base := atts[0]
	for _, a := range atts[1:] {
		if a.GovernatorCommit != base.GovernatorCommit ||
			a.AssayerCommit != base.AssayerCommit ||
			a.TestSourceHash != base.TestSourceHash ||
			a.TestBinarySHA256 != base.TestBinarySHA256 ||
			a.ToolchainHash != base.ToolchainHash ||
			a.ReleaseVersion != base.ReleaseVersion {
			return false, fmt.Sprintf(
				"attestation %q binding differs from %q (governator/assayer/test-source/test-binary/toolchain/version must all match)",
				a.Category, base.Category)
		}
	}
	return true, ""
}

// AggregationResult is the outcome of verifying and aggregating a set of
// capability-host attestations for one release (Session 9).
type AggregationResult struct {
	OK       bool     `json:"ok"`
	Problems []string `json:"problems,omitempty"`

	// CoveredTests is the union of every test name that ran and passed
	// across all attestations.
	CoveredTests map[string]bool `json:"-"`

	// NonApprovingCategories are categories that explicitly do not claim
	// production approval (Darwin for rc5). Tests whose ONLY coverage is a
	// non-approving category are not gaps — the release does not claim that
	// platform.
	NonApprovingCategories map[string]bool `json:"-"`

	// CategoriesPresent lists which required categories have attestations.
	CategoriesPresent []string `json:"categories_present"`
}

// AggregateAndVerify checks a set of capability-host attestations against the
// required categories and binding consistency (Session 9). It returns the
// aggregated coverage set the gate uses to decide whether a skip under
// --require-zero-skips is accounted for.
func AggregateAndVerify(atts []CapabilityAttestation, requiredCategories []string) AggregationResult {
	var res AggregationResult
	res.CoveredTests = make(map[string]bool)
	res.NonApprovingCategories = make(map[string]bool)

	if len(atts) == 0 {
		res.Problems = append(res.Problems, "no capability attestations supplied")
		return res
	}

	if ok, msg := BindingConsistent(atts); !ok {
		res.Problems = append(res.Problems, msg)
		return res
	}

	present := make(map[string]bool)
	for _, a := range atts {
		present[a.Category] = true
		res.CategoriesPresent = append(res.CategoriesPresent, a.Category)
		if a.NonApproving {
			res.NonApprovingCategories[a.Category] = true
		}
		for _, t := range a.CoveredTests {
			res.CoveredTests[t] = true
		}
	}
	sort.Strings(res.CategoriesPresent)

	for _, cat := range requiredCategories {
		if !present[cat] {
			res.Problems = append(res.Problems, fmt.Sprintf("required attestation category %q is missing from the supplied set", cat))
		}
	}

	res.OK = len(res.Problems) == 0
	return res
}

// SkipCoveredByAttestations reports whether a skipped test is accounted for
// by the aggregated attestation set: the test ran and passed on another host,
// or its only coverage is a non-approving platform declaration, or its
// capability predicate is proven absent (the scenario is platform-inapplicable).
func SkipCoveredByAttestations(testName string, agg AggregationResult, capabilities map[string]CapabilityRecord, caseEntry CaseEntry) bool {
	if agg.CoveredTests[testName] {
		return true
	}
	if caseEntry.Conditional && caseEntry.AllowedSkip != nil && caseEntry.AllowedSkip.Predicate != "" {
		rec, ok := capabilities[caseEntry.AllowedSkip.Predicate]
		if ok && rec.State == CapabilityAbsent {
			return true
		}
	}
	return false
}

// LoadAttestations reads all .json attestation files from a directory and
// returns the parsed set (Session 9 aggregation input).
func LoadAttestations(dir string) ([]CapabilityAttestation, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("attestation dir: %w", err)
	}
	var atts []CapabilityAttestation
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("attestation %s: %w", e.Name(), err)
		}
		var a CapabilityAttestation
		if err := json.Unmarshal(data, &a); err != nil {
			return nil, fmt.Errorf("attestation %s: %w", e.Name(), err)
		}
		if a.Category == "" {
			return nil, fmt.Errorf("attestation %s: missing category", e.Name())
		}
		atts = append(atts, a)
	}
	return atts, nil
}
