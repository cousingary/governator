package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/cousingary/governator/internal/contracts"
)

type Risk string

const (
	RiskLow     Risk = "LOW"
	RiskMedium  Risk = "MED"
	RiskHigh    Risk = "HIGH"
	RiskBlocked Risk = "BLOCKED"
)

type PreflightReport struct {
	TargetFiles   []string       `json:"target_files"`
	MissingInputs []string       `json:"missing_inputs"`
	RiskFlags     []string       `json:"risk_flags"`
	Steps         []string       `json:"steps"`
	Mode          contracts.Mode `json:"mode"`
	Risk          Risk           `json:"risk"`
	// Decision carries the same information as RiskFlags with explicit
	// provenance: which policy layer (job contract vs. hardcoded org policy)
	// raised each flag, and a hash identifying the exact preflight policy
	// consulted. RiskFlags stays the primary field (existing callers match
	// against it); Decision is additive.
	Decision PolicyDecision `json:"decision"`
}

func Preflight(c contracts.Contract) (PreflightReport, error) {
	report := PreflightReport{
		Mode:  c.Mode,
		Risk:  RiskLow,
		Steps: []string{"compile scoped prompt", "create isolated workspace", "run selected adapter", "audit transcript and diff", "run deterministic validators", "apply merge gate"},
	}
	if err := c.Validate(); err != nil {
		return report, err
	}
	root, err := filepath.Abs(c.Workspace.Root)
	if err != nil {
		return report, err
	}
	if info, statErr := os.Stat(root); statErr != nil || !info.IsDir() {
		if statErr == nil {
			statErr = fmt.Errorf("not a directory")
		}
		return report, fmt.Errorf("workspace.root: %w", statErr)
	}

	var files []string
	if err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if rel == ".git" && entry.IsDir() {
			return filepath.SkipDir
		}
		if !entry.IsDir() && rel != "." {
			files = append(files, rel)
		}
		return nil
	}); err != nil {
		return report, err
	}

	var decisions []PolicyDecision
	for _, pattern := range c.Preflight.IntendedWrites {
		if !patternWithin(pattern, c.Allowed.Write) {
			report.Risk = RiskBlocked
			reason := "intended write exceeds allowed.write: " + pattern
			report.RiskFlags = append(report.RiskFlags, reason)
			decisions = append(decisions, Deny(SourceJobContract, reason))
		}
		for _, file := range files {
			if glob(pattern, file) {
				report.TargetFiles = append(report.TargetFiles, file)
			}
		}
	}
	for _, pattern := range c.Allowed.Read {
		found := pattern == "**"
		for _, file := range files {
			if glob(pattern, file) {
				found = true
				break
			}
		}
		if !found {
			report.MissingInputs = append(report.MissingInputs, pattern)
		}
	}

	for _, command := range c.Allowed.Execute {
		if class := ClassifyShellCommand(command, false); class != nil {
			report.Risk = RiskBlocked
			reason := fmt.Sprintf("destructive command allowed: %s %s", class.Verb, class.Resource)
			report.RiskFlags = append(report.RiskFlags, reason)
			decisions = append(decisions, Deny(SourceOrgPolicy, reason))
		}
	}
	if report.Risk != RiskBlocked {
		broad := false
		for _, pattern := range c.Preflight.IntendedWrites {
			prefix := staticPrefix(pattern)
			if prefix == "" || prefix == "." {
				broad = true
			}
		}
		switch {
		case broad || c.Budget.MaxFilesChanged > 50 || c.Budget.MaxLinesChanged > 2000 || c.Budget.MaxNewFiles > 30 || c.Budget.MaxDeleted > 0:
			report.Risk = RiskHigh
			reason := "large or destructive write envelope"
			report.RiskFlags = append(report.RiskFlags, reason)
			decisions = append(decisions, Deny(SourceJobContract, reason))
		case c.Mode == contracts.ModeBatchWorker || c.Budget.MaxFilesChanged > 10 || c.Budget.MaxLinesChanged > 500 || c.Budget.MaxNewFiles > 10:
			report.Risk = RiskMedium
			reason := "multi-file write envelope"
			report.RiskFlags = append(report.RiskFlags, reason)
			decisions = append(decisions, Deny(SourceJobContract, reason))
		}
	}
	if len(decisions) == 0 {
		report.Decision = Allow(SourceJobContract, SourceOrgPolicy)
	} else {
		report.Decision = Combine(decisions...)
	}
	sort.Strings(report.TargetFiles)
	report.TargetFiles = unique(report.TargetFiles)
	sort.Strings(report.MissingInputs)
	sort.Strings(report.RiskFlags)
	return report, nil
}

func Enforce(report PreflightReport, c contracts.Contract) error {
	if report.Risk == RiskBlocked {
		return fmt.Errorf("preflight BLOCKED: %s", strings.Join(report.RiskFlags, "; "))
	}
	if report.Risk == RiskHigh && !c.Preflight.ScoutCompleted && !c.Preflight.ApproveHighRisk {
		return fmt.Errorf("preflight HIGH requires scout_completed or approve_high_risk")
	}
	return nil
}

func MatchesAny(patterns []string, name string) bool {
	for _, pattern := range patterns {
		if glob(pattern, name) {
			return true
		}
	}
	return false
}

func patternWithin(pattern string, allowed []string) bool {
	prefix := staticPrefix(pattern)
	for _, candidate := range allowed {
		if candidate == "**" || candidate == pattern {
			return true
		}
		if !strings.ContainsAny(pattern, "*?[") && glob(candidate, pattern) {
			return true
		}
		if !strings.HasSuffix(candidate, "/**") {
			continue
		}
		allowedPrefix := strings.TrimSuffix(candidate, "/**")
		if prefix == allowedPrefix || strings.HasPrefix(prefix, strings.TrimSuffix(allowedPrefix, "/")+"/") {
			return true
		}
	}
	return false
}

func staticPrefix(pattern string) string {
	pattern = filepath.ToSlash(filepath.Clean(pattern))
	if i := strings.IndexAny(pattern, "*?["); i >= 0 {
		pattern = strings.TrimSuffix(pattern[:i], "/")
	}
	return pattern
}

func glob(pattern, name string) bool {
	pattern, name = filepath.ToSlash(pattern), filepath.ToSlash(name)
	var b strings.Builder
	b.WriteString("^")
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			if i+1 < len(pattern) && pattern[i+1] == '*' {
				b.WriteString(".*")
				i++
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			b.WriteString(regexp.QuoteMeta(string(pattern[i])))
		}
	}
	b.WriteString("$")
	ok, _ := regexp.MatchString(b.String(), name)
	return ok
}

func unique(values []string) []string {
	if len(values) == 0 {
		return values
	}
	out := values[:1]
	for _, value := range values[1:] {
		if value != out[len(out)-1] {
			out = append(out, value)
		}
	}
	return out
}
