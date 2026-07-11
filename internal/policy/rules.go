package policy

import (
	"fmt"
	"regexp"
)

// RuleVerdict is what a fired temporal rule does to the run: deny records a
// blocking violation (same weight as any other audit violation, feeds
// ClassifyFailure/quarantine); flag is advisory-only — recorded for operator
// review but never changes the run's outcome, mirroring the assay bridge's
// advisory enforcement mode (internal/assay).
type RuleVerdict string

const (
	RuleDeny RuleVerdict = "deny"
	RuleFlag RuleVerdict = "flag"
)

// Starter rule names (Phase 6 §2 of the hardening plan). Kept as constants
// so ledger rows and tests reference a single spelling.
const (
	RuleSecretPrecedesNetwork       = "secret-read-precedes-network"
	RuleOutOfScopeReadPrecedesWrite = "out-of-scope-read-precedes-write"
	RuleInjectionPrecedesExec       = "suspected-injection-precedes-exec"
)

// RuleViolation is one temporal-rule hit: a Cause event that, once observed,
// makes a later Trigger event of the matching kind a violation.
type RuleViolation struct {
	Rule       string
	Verdict    RuleVerdict
	Detail     string
	CauseSeq   int
	TriggerSeq int
}

// injectionMarkerRE matches common prompt-injection phrasing seen in
// poisoned tool output (a fetched web page, a file the agent read) that
// tries to redirect the agent's own instructions. Narrow and literal by
// design — false negatives (missing a novel phrasing) are acceptable for an
// advisory flag; false positives on routine text are not.
var injectionMarkerRE = regexp.MustCompile(`(?i)ignore (all |any )?(previous|prior|above) instructions|disregard (the |all )?(system|previous) prompt|reveal (your|the) (system )?prompt|you are now (in )?(developer|admin|unrestricted) mode`)

// LooksLikeInjection reports whether text contains a recognized
// prompt-injection marker.
func LooksLikeInjection(text string) bool {
	return injectionMarkerRE.MatchString(text)
}

// EvaluateTemporalRules runs the Phase 6 starter rule set over one run's
// event graph, in event order (events must already be sorted by Sequence).
// secretPatterns are glob patterns a read's Subject is checked against for
// rule 1 (protected paths plus any operator-declared secrets globs);
// scopePatterns are the job contract's allowed.read patterns for rule 2 — a
// read whose Subject matches none of them is "outside declared scope". Empty
// scopePatterns disables rule 2 entirely (an unscoped contract has nothing to
// violate) rather than treating every read as out of scope.
func EvaluateTemporalRules(events []Event, secretPatterns, scopePatterns []string) []RuleViolation {
	var out []RuleViolation
	var secretRead, outOfScopeRead, lastInjection *Event

	for i := range events {
		e := events[i]
		switch e.Kind {
		case EventRead:
			if secretRead == nil && e.Subject != "" && MatchesAny(secretPatterns, e.Subject) {
				c := e
				secretRead = &c
			}
			if outOfScopeRead == nil && len(scopePatterns) > 0 && e.Subject != "" && !MatchesAny(scopePatterns, e.Subject) {
				c := e
				outOfScopeRead = &c
			}
		case EventNetwork:
			if secretRead != nil {
				out = append(out, RuleViolation{
					Rule: RuleSecretPrecedesNetwork, Verdict: RuleDeny,
					Detail:     fmt.Sprintf("read %q (seq %d) matching a protected/secret pattern precedes network request %q (seq %d)", secretRead.Subject, secretRead.Sequence, e.Subject, e.Sequence),
					CauseSeq:   secretRead.Sequence,
					TriggerSeq: e.Sequence,
				})
			}
		case EventWrite:
			if outOfScopeRead != nil {
				out = append(out, RuleViolation{
					Rule: RuleOutOfScopeReadPrecedesWrite, Verdict: RuleDeny,
					Detail:     fmt.Sprintf("read %q (seq %d) outside allowed.read scope precedes write %q (seq %d)", outOfScopeRead.Subject, outOfScopeRead.Sequence, e.Subject, e.Sequence),
					CauseSeq:   outOfScopeRead.Sequence,
					TriggerSeq: e.Sequence,
				})
			}
		case EventToolOutput:
			if LooksLikeInjection(e.Subject) {
				c := e
				lastInjection = &c
			}
		case EventExec:
			if lastInjection != nil {
				out = append(out, RuleViolation{
					Rule: RuleInjectionPrecedesExec, Verdict: RuleFlag,
					Detail:     fmt.Sprintf("tool output (seq %d) containing a suspected injection marker precedes shell command %q (seq %d)", lastInjection.Sequence, e.Subject, e.Sequence),
					CauseSeq:   lastInjection.Sequence,
					TriggerSeq: e.Sequence,
				})
				lastInjection = nil
			}
		}
	}
	return out
}
