package redteamgate

import (
	"bytes"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// ExactManifest is a name-inventoried security-test manifest that carries NO
// case numbers (Sol14 rc7 Session 9b). The numbered corpus (Manifest, in
// gate.go) remains the single source of truth for the mandatory final attack
// corpus. An ExactManifest groups security tests by the capability host they
// require -- red-team attacks, Governator<->Assayer integration, context-graph
// integration, Docker-capable integration, live-systemd integration -- so that
// Session 9d can enforce "every security-relevant test is either required and
// passed, or explicitly outside the claimed production platform" across the
// whole set, rather than only the numbered corpus plus the free-text
// exclusions list that P1-2 exists to drain.
//
// Why exact names instead of case numbers: the open-gap exclusions S9 drains
// (39 that "happened to pass" plus 2 that skipped) and the 8 raw-log security
// skips (5 Assayer-bridge, 3 context-graph) are coverage that moved *out* of
// the numbered corpus. Numbering them would re-introduce the count-vs-maximum
// drift that broke LoadManifest in S6 (see "Case numbering" in the rc7 plan).
// An exact manifest is name-inventoried only: every test name must be present
// exactly once across the whole set, but no ordinal is assigned or compared.
//
// required_capabilities reuses the existing KnownPredicates registry and the
// tri-state CapabilityRecord evidence (gate.go): a manifest declares which
// capability predicates the host it runs on must prove. S9d consumes this to
// classify a skip as "out of claimed production scope" (predicate proven
// absent) versus an unaccounted gap. S9b only loads and validates it.
type ExactManifest struct {
	// Name is the manifest's human identity (e.g. "red-team-attacks",
	// "assayer-integration"). It must be non-empty and unique across a
	// ManifestSet so release evidence can name which manifest a gap is in.
	Name string `yaml:"name"`
	// RequiredCapabilities is the set of KnownPredicates this manifest's host
	// must prove (present or absent). Each entry must be a registered
	// predicate; a typo fails load exactly as a manifest case's allowed_skip
	// predicate does (Sol12 P1-8). May be empty for a manifest whose tests
	// make no capability claim.
	RequiredCapabilities []string `yaml:"required_capabilities,omitempty"`
	// Tests is the exact-name inventory this manifest requires. Every name
	// must be a real //go:build-tagged test function; S9d proves that against
	// the authoritative inventory the release discovers from source, the same
	// way it does for the numbered corpus. Names must be unique within the
	// manifest and, across a ManifestSet, unique across all manifests and not
	// shadowed by a numbered corpus case.
	Tests []string `yaml:"tests"`
}

// LoadExactManifest reads and strictly validates one exact-manifest YAML file
// (Sol14 rc7 Session 9b). Strictness mirrors LoadManifest (gate.go):
// yaml.v3 KnownFields rejects unknown fields and duplicate mapping keys; the
// manifest has a non-empty unique name; every required_capabilities entry is a
// registered KnownPredicates value; the tests list is non-empty and every
// name is non-empty and unique within the file. An exact manifest is a release
// security policy and parses as strictly as a contract -- permissive decode is
// exactly the defect the numbered-corpus loader closed (P1-8) and is not
// re-opened here.
func LoadExactManifest(path string) (ExactManifest, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return ExactManifest{}, fmt.Errorf("redteamgate: read exact manifest %s: %w", path, err)
	}
	// KnownFields(true) rejects unknown fields; yaml.v3 also rejects duplicate
	// mapping keys during decode (the P1-8 duplicate-key defense), so a
	// mistyped or duplicated YAML key fails here rather than silently
	// last-wins.
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var em ExactManifest
	if err := dec.Decode(&em); err != nil {
		return ExactManifest{}, fmt.Errorf("redteamgate: parse exact manifest %s: %w", path, err)
	}
	if err := validateExactManifest(em); err != nil {
		return ExactManifest{}, fmt.Errorf("redteamgate: exact manifest %s: %w", path, err)
	}
	return em, nil
}

// validateExactManifest performs the semantic strictness checks that
// KnownFields alone cannot express. It mirrors validateManifest (gate.go) in
// shape: non-empty unique names, registered predicates, no duplicates.
func validateExactManifest(em ExactManifest) error {
	if strings.TrimSpace(em.Name) == "" {
		return fmt.Errorf("manifest has no name")
	}
	seenCap := make(map[string]bool, len(em.RequiredCapabilities))
	for _, pred := range em.RequiredCapabilities {
		pred = strings.TrimSpace(pred)
		if pred == "" {
			return fmt.Errorf("manifest %q has a blank required_capabilities entry", em.Name)
		}
		if seenCap[pred] {
			return fmt.Errorf("manifest %q declares required capability %q more than once", em.Name, pred)
		}
		seenCap[pred] = true
		if !KnownPredicates[pred] {
			return fmt.Errorf("manifest %q references unknown capability predicate %q", em.Name, pred)
		}
	}
	if len(em.Tests) == 0 {
		return fmt.Errorf("manifest %q lists no tests", em.Name)
	}
	seenTest := make(map[string]bool, len(em.Tests))
	for _, name := range em.Tests {
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("manifest %q has a blank test name", em.Name)
		}
		if seenTest[name] {
			return fmt.Errorf("manifest %q lists test %q more than once", em.Name, name)
		}
		seenTest[name] = true
	}
	return nil
}

// ManifestSet carries the numbered corpus (Manifest) plus N exact manifests.
// It is the container Session 9c populates (5 exact manifests) and Session 9d
// enforces zero unaccounted skips across. Session 9b ships it wired to zero
// exact manifests -- the numbered corpus alone -- so gate behavior is
// provably unchanged: a current-corpus release run loads a ManifestSet whose
// ExactManifests is empty, and no verdict differs from the pre-S9b gate.
type ManifestSet struct {
	Corpus         Manifest
	ExactManifests []ExactManifest
}

// LoadManifestSet loads the numbered corpus and zero or more exact manifests
// and validates the combined set. Cross-set validation is the structural
// defense against the silent-retirement attack P1-2 closes for the numbered
// corpus: a test must not appear in two exact manifests, and a test must not
// be both a numbered corpus case and an exact-manifest entry (that would let a
// case be "moved" out of the numbered corpus into an exact manifest that S9b
// does not yet enforce, hiding a coverage change). Manifest names must be
// unique across the set.
//
// exactPaths may be empty (the S9b wiring: zero exact manifests, byte-identical
// gate behavior). S9c supplies the five real manifest paths.
func LoadManifestSet(corpusPath string, exactPaths []string) (ManifestSet, error) {
	corpus, err := LoadManifest(corpusPath)
	if err != nil {
		return ManifestSet{}, err
	}
	set := ManifestSet{Corpus: corpus}
	if len(exactPaths) == 0 {
		return set, nil
	}
	// Pre-size the corpus case-name index once; every exact manifest is
	// checked against it so a case cannot be silently re-classified out of
	// the numbered corpus (the exclusion-shadow rule, generalized).
	corpusNames := make(map[string]bool, len(corpus.Cases))
	for _, c := range corpus.Cases {
		corpusNames[c.Name] = true
	}
	seenManifestName := make(map[string]bool, len(exactPaths))
	seenTestAcrossSet := make(map[string]string)
	for _, p := range exactPaths {
		em, err := LoadExactManifest(p)
		if err != nil {
			return ManifestSet{}, err
		}
		if seenManifestName[em.Name] {
			return ManifestSet{}, fmt.Errorf("redteamgate: exact manifest name %q appears more than once in the set", em.Name)
		}
		seenManifestName[em.Name] = true
		for _, name := range em.Tests {
			name = strings.TrimSpace(name)
			if priorManifest, dup := seenTestAcrossSet[name]; dup {
				return ManifestSet{}, fmt.Errorf("redteamgate: test %q appears in exact manifests %q and %q (a test belongs to exactly one manifest)", name, priorManifest, em.Name)
			}
			seenTestAcrossSet[name] = em.Name
			if corpusNames[name] {
				return ManifestSet{}, fmt.Errorf("redteamgate: test %q is both a numbered corpus case and an entry in exact manifest %q", name, em.Name)
			}
		}
		set.ExactManifests = append(set.ExactManifests, em)
	}
	return set, nil
}

// ExactManifestTestNames returns the deduplicated, sorted union of every test
// name across the set's exact manifests. Empty when the set carries no exact
// manifests (the S9b wiring). Provided so S9d and the release inventory can
// compare the exact-manifest coverage to the authoritative discovered
// inventory in one place.
func (s ManifestSet) ExactManifestTestNames() []string {
	if len(s.ExactManifests) == 0 {
		return nil
	}
	seen := make(map[string]bool)
	for _, em := range s.ExactManifests {
		for _, name := range em.Tests {
			seen[strings.TrimSpace(name)] = true
		}
	}
	out := make([]string, 0, len(seen))
	for name := range seen {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
