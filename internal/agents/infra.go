package agents

import (
	"errors"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// InfraFailure is the backend-facing classification of an infrastructure
// failure observed at run time. The values mirror observability.Infra* kinds
// but live here (next to the adapters) because each backend emits different
// rate-limit / auth strings; the matcher that turns a transcript tail into a
// kind is adapter-owned (plan Session 2). An empty string means "not infra" —
// the run is a quality failure or a success, and the breaker is never touched
// (rule 3: quality never opens a breaker).
type InfraFailure string

const (
	InfraNone              InfraFailure = ""
	InfraRateLimit         InfraFailure = "RATE_LIMIT"
	InfraQuotaExhausted    InfraFailure = "QUOTA_EXHAUSTED"
	InfraAuthExpired       InfraFailure = "AUTH_EXPIRED"
	InfraBinaryMissing     InfraFailure = "BINARY_MISSING"
	InfraFlagDrift         InfraFailure = "FLAG_DRIFT"
	InfraTransientUpstream InfraFailure = "TRANSIENT_UPSTREAM"
)

// infraMatcher maps a case-insensitive substring of the backend's stderr /
// transcript tail to an infra kind. Matchers are tried in order; the first hit
// wins. Order matters when one string could match two kinds (put the more
// specific kind first).
type infraMatcher struct {
	kind    InfraFailure
	pattern string
}

// ClassifyInfra inspects a backend run's exit code, launch error, and the tail
// of its merged transcript for infrastructure-failure signatures. It returns
// the infra kind, or InfraNone when the failure is not infra (a quality
// failure, an unrecognised nonzero exit, or a success).
//
// A binary that could not be launched is detected from the Go error
// (exec.ErrNotFound / ENOENT) and mapped to BINARY_MISSING regardless of the
// adapter. Every other kind comes from the adapter's stderr matchers, since
// Claude Code, Codex, and GLM emit different rate-limit / auth strings.
//
// The patterns are initial heuristics refined against observed backend output;
// the classification -> breaker mechanism is what is fully tested. An unknown
// nonzero exit with no infra signature is deliberately left as InfraNone so it
// stays a quality (AGENT_FAILURE) signal and never opens a breaker (rule 3).
func ClassifyInfra(agent string, exitCode int, launchErr error, transcriptTail string) InfraFailure {
	if kind, ok := classifyLaunchError(launchErr); ok {
		return kind
	}
	if exitCode == 0 {
		return InfraNone
	}
	hay := strings.ToLower(transcriptTail)
	for _, m := range infraMatchersFor(agent) {
		if strings.Contains(hay, m.pattern) {
			return m.kind
		}
	}
	return InfraNone
}

// classifyLaunchError maps a process-launch error to an infra kind. The only
// launch failure that is unambiguously infra is a missing executable: the
// backend binary the adapter depends on is not installed (or not on PATH).
// Every other launch error is left to the caller as non-infra.
func classifyLaunchError(launchErr error) (InfraFailure, bool) {
	if launchErr == nil {
		return InfraNone, false
	}
	if errors.Is(launchErr, exec.ErrNotFound) {
		return InfraBinaryMissing, true
	}
	// cmd.Start wraps ENOENT in a *fs.PathError whose message contains
	// "no such file or directory"; exec.ErrNotFound only covers the
	// resolved-path-absent case, so also match the kernel message for a
	// binary that resolved but cannot exec.
	msg := strings.ToLower(launchErr.Error())
	if strings.Contains(msg, "no such file or directory") || strings.Contains(msg, "executable file not found") {
		return InfraBinaryMissing, true
	}
	return InfraNone, false
}

// infraMatchersFor returns the backend-specific infrastructure-failure
// matchers. Claude Code, GLM (Claude-Code compatible), and Codex emit
// different rate-limit and auth strings; OpenCode and Pi use the generic web
// surface. Matchers are ordered most-specific first.
func infraMatchersFor(agent string) []infraMatcher {
	switch agent {
	case "claude-code", "glm":
		// glm-cli is Claude-Code compatible and shares the same stderr surface.
		return claudeCompatibleMatchers
	case "codex":
		return codexMatchers
	case "opencode", "pi":
		return genericMatchers
	default:
		return genericMatchers
	}
}

var claudeCompatibleMatchers = []infraMatcher{
	{InfraRateLimit, "rate limit"},
	{InfraRateLimit, "rate_limit"},
	{InfraRateLimit, "429"},
	{InfraRateLimit, "overloaded"},
	{InfraQuotaExhausted, "quota"},
	{InfraQuotaExhausted, "usage limit"},
	{InfraAuthExpired, "invalid api key"},
	{InfraAuthExpired, "authentication"},
	{InfraAuthExpired, "401"},
	{InfraTransientUpstream, "connection refused"},
	{InfraTransientUpstream, "connection reset"},
	{InfraTransientUpstream, "503"},
	{InfraTransientUpstream, "502"},
	{InfraTransientUpstream, "upstream"},
}

var codexMatchers = []infraMatcher{
	{InfraRateLimit, "rate_limit"},
	{InfraRateLimit, "rate limit"},
	{InfraRateLimit, "429"},
	{InfraQuotaExhausted, "usage limit"},
	{InfraQuotaExhausted, "quota"},
	{InfraAuthExpired, "unauthorized"},
	{InfraAuthExpired, "invalid api key"},
	{InfraAuthExpired, "401"},
	{InfraTransientUpstream, "connection refused"},
	{InfraTransientUpstream, "connection reset"},
	{InfraTransientUpstream, "503"},
	{InfraTransientUpstream, "502"},
}

var genericMatchers = []infraMatcher{
	{InfraRateLimit, "rate limit"},
	{InfraRateLimit, "rate_limit"},
	{InfraRateLimit, "429"},
	{InfraQuotaExhausted, "quota"},
	{InfraQuotaExhausted, "usage limit"},
	{InfraAuthExpired, "unauthorized"},
	{InfraAuthExpired, "invalid api key"},
	{InfraAuthExpired, "authentication"},
	{InfraAuthExpired, "401"},
	{InfraTransientUpstream, "connection refused"},
	{InfraTransientUpstream, "connection reset"},
	{InfraTransientUpstream, "503"},
	{InfraTransientUpstream, "502"},
	{InfraTransientUpstream, "upstream"},
}

var resetInPattern = regexp.MustCompile(`(?i)(?:retry|reset|try again)[^\n]*(?:in|after)\s+(\d+)\s*(seconds?|secs?|s|minutes?|mins?|m|hours?|hrs?|h)`)
var resetAtPattern = regexp.MustCompile(`(?i)(?:reset(?:s)? at|retry after|try again at)\s+([0-9]{4}-[0-9]{2}-[0-9]{2}(?:[tT ][0-9]{2}:[0-9]{2}(?::[0-9]{2})?(?:Z|[+-][0-9]{2}:?[0-9]{2})?)?)`)

// ResetHint extracts deterministic reset/cooldown hints from backend stderr or
// transcript tails. It is deliberately conservative: if no obvious absolute
// time or "in N units" phrase exists, callers keep their default breaker
// cooldown and quota window.
func ResetHint(transcriptTail string, now time.Time) (time.Time, bool) {
	text := strings.TrimSpace(transcriptTail)
	if text == "" {
		return time.Time{}, false
	}
	if m := resetInPattern.FindStringSubmatch(text); len(m) == 3 {
		n, err := strconv.Atoi(m[1])
		if err == nil && n > 0 {
			unit := strings.ToLower(m[2])
			d := time.Duration(n) * time.Second
			switch {
			case strings.HasPrefix(unit, "m"):
				d = time.Duration(n) * time.Minute
			case strings.HasPrefix(unit, "h"):
				d = time.Duration(n) * time.Hour
			}
			return now.UTC().Add(d), true
		}
	}
	if m := resetAtPattern.FindStringSubmatch(text); len(m) == 2 {
		raw := strings.ReplaceAll(m[1], " ", "T")
		layouts := []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02T15:04", "2006-01-02"}
		for _, layout := range layouts {
			if t, err := time.Parse(layout, raw); err == nil {
				return t.UTC(), true
			}
		}
	}
	return time.Time{}, false
}
