package policy

import (
	"fmt"
	"strings"

	"github.com/cousingary/governator/internal/contracts"
)

// lintFormatKeywords are substrings that, found anywhere in a
// success.validators command (case-insensitive), already give a contract
// lint/format coverage without a dedicated cleanup block. Substring rather
// than word-boundary matching deliberately catches tool names like "gofmt"
// and "eslint" where the keyword isn't its own word.
var lintFormatKeywords = []string{
	"lint", "fmt", "format", "vet", "eslint", "black", "flake8", "ruff", "prettier",
}

func looksLikeLintOrFormat(cmd string) bool {
	lower := strings.ToLower(cmd)
	for _, kw := range lintFormatKeywords {
		if strings.Contains(lower, kw) {
			return true
		}
	}
	return false
}

// CleanupDoctrineApplies reports whether m is a code-writing mode the
// cleanup doctrine check governs. Scout/verifier/architect never write, and
// planner writes only a PLAN.yaml manifest (not code) inside its own output
// directory, so none of them are held to a cleanup/lint-format expectation.
func CleanupDoctrineApplies(m contracts.Mode) bool {
	return m == contracts.ModeSurgeon || m == contracts.ModeBatchWorker || m == contracts.ModeRepair
}

// CleanupDoctrineIssue reports the doctrine gap #5 finding for c: a
// code-writing contract with neither an explicit cleanup block nor a
// lint/format validator among success.validators. Returns "" when the
// doctrine doesn't apply to c's mode or when c already satisfies it. The
// caller (gov validate) decides whether this is a warning or, when
// config.Doctrine.RequireCleanup is set, a validation error — this function
// stays config-agnostic so it can be unit tested without a config fixture.
func CleanupDoctrineIssue(c contracts.Contract) string {
	if !CleanupDoctrineApplies(c.Mode) {
		return ""
	}
	if c.Cleanup != nil {
		return ""
	}
	for _, v := range c.Success.Validators {
		if looksLikeLintOrFormat(v) {
			return ""
		}
	}
	return fmt.Sprintf("job %s (mode %s) has neither a cleanup block nor a lint/format validator in success.validators", c.JobID, c.Mode)
}
