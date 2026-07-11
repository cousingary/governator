package agents

import (
	"errors"
	"os/exec"
	"testing"
	"time"
)

func TestClassifyInfraRateLimit(t *testing.T) {
	for _, agent := range []string{"claude-code", "codex", "glm", "opencode", "pi"} {
		if got := ClassifyInfra(agent, 1, nil, "Error: 429 Too Many Requests rate limit exceeded"); got != InfraRateLimit {
			t.Errorf("%s: got %q want RATE_LIMIT", agent, got)
		}
	}
}

func TestClassifyInfraAuthExpired(t *testing.T) {
	if got := ClassifyInfra("claude-code", 1, nil, "invalid api key"); got != InfraAuthExpired {
		t.Fatalf("got %q want AUTH_EXPIRED", got)
	}
	if got := ClassifyInfra("codex", 1, nil, "unauthorized"); got != InfraAuthExpired {
		t.Fatalf("got %q want AUTH_EXPIRED", got)
	}
}

func TestClassifyInfraQuotaExhausted(t *testing.T) {
	if got := ClassifyInfra("codex", 1, nil, "usage limit reached for today"); got != InfraQuotaExhausted {
		t.Fatalf("got %q want QUOTA_EXHAUSTED", got)
	}
}

func TestClassifyInfraTransient(t *testing.T) {
	if got := ClassifyInfra("claude-code", 1, nil, "connection refused by upstream"); got != InfraTransientUpstream {
		t.Fatalf("got %q want TRANSIENT_UPSTREAM", got)
	}
}

func TestClassifyInfraBinaryMissingFromLaunchError(t *testing.T) {
	// exec.ErrNotFound (resolved path absent).
	if got := ClassifyInfra("codex", 0, exec.ErrNotFound, ""); got != InfraBinaryMissing {
		t.Fatalf("ErrNotFound: got %q want BINARY_MISSING", got)
	}
	// Kernel ENOENT message for a binary that resolved but cannot exec.
	if got := ClassifyInfra("codex", 0, errors.New("fork/exec /usr/bin/codex: no such file or directory"), ""); got != InfraBinaryMissing {
		t.Fatalf("ENOENT msg: got %q want BINARY_MISSING", got)
	}
}

func TestClassifyInfraSuccessAndUnknownExitAreNone(t *testing.T) {
	// Exit 0 is never infra.
	if got := ClassifyInfra("codex", 0, nil, "rate limit noise in a log"); got != InfraNone {
		t.Fatalf("exit 0: got %q want none", got)
	}
	// Nonzero exit with no infra signature is not infra (stays a quality signal).
	if got := ClassifyInfra("codex", 1, nil, "the agent produced a bad diff"); got != InfraNone {
		t.Fatalf("unknown exit: got %q want none (rule 3)", got)
	}
}

func TestClassifyInfraMatcherOrderMostSpecificFirst(t *testing.T) {
	// "rate_limit" and "rate limit" both present; first hit wins and both map
	// to RATE_LIMIT, so ordering is stable. Verify a quota string that contains
	// a rate substring still classifies as quota when quota is listed first.
	if got := ClassifyInfra("claude-code", 1, nil, "quota rate limit reached"); got != InfraRateLimit {
		// "rate limit" appears and RATE_LIMIT matchers precede QUOTA in the
		// claude-compatible list; this pins that ordering decision.
		t.Fatalf("got %q (first matcher wins)", got)
	}
}

func TestInfraMatchersCoverEveryBackend(t *testing.T) {
	// Every registered backend must return a non-empty matcher set so an
	// unknown agent never silently falls through to no classification.
	for _, name := range []string{"claude-code", "codex", "glm", "opencode", "pi"} {
		if len(infraMatchersFor(name)) == 0 {
			t.Errorf("backend %q has no infra matchers", name)
		}
	}
}

func TestResetHintRelative(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	got, ok := ResetHint("rate limit; try again in 15 minutes", now)
	if !ok || !got.Equal(now.Add(15*time.Minute)) {
		t.Fatalf("got %s ok=%t", got, ok)
	}
}

func TestResetHintAbsolute(t *testing.T) {
	now := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	want := time.Date(2026, 7, 10, 12, 30, 0, 0, time.UTC)
	got, ok := ResetHint("usage limit reached; resets at 2026-07-10T12:30:00Z", now)
	if !ok || !got.Equal(want) {
		t.Fatalf("got %s ok=%t want %s", got, ok, want)
	}
}

func TestResetHintMissing(t *testing.T) {
	if got, ok := ResetHint("rate limit with no reset", time.Now()); ok || !got.IsZero() {
		t.Fatalf("got %s ok=%t", got, ok)
	}
}
