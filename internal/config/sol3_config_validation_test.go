package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestSol3LoadStrictRejectsMultipleYAMLDocuments reproduces corpus #13
// (Sol finding #9): a second `---`-separated YAML document in the config
// file used to be silently ignored — only the first document's values ever
// took effect, with no error and no indication a second document existed.
func TestSol3LoadStrictRejectsMultipleYAMLDocuments(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("spend: {daily_cap_usd: 5}\n---\nspend: {daily_cap_usd: 10}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStrict()
	if err == nil || !strings.Contains(err.Error(), "multiple YAML documents") {
		t.Fatalf("expected a multiple-documents error, got: %v", err)
	}
}

// TestSol3LoadStrictAcceptsSingleDocumentWithTrailingMarker proves the fix
// does not over-block: a single document followed by nothing (no second
// document body) must still load cleanly, including the common
// single-document `---` prefix some operators write out of habit.
func TestSol3LoadStrictAcceptsSingleDocumentWithTrailingMarker(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("---\nspend: {daily_cap_usd: 5}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadStrict()
	if err != nil {
		t.Fatalf("expected a single leading document marker to load cleanly, got: %v", err)
	}
	if cfg.Spend.DailyCapUSD != 5 {
		t.Fatalf("expected daily_cap_usd=5, got %v", cfg.Spend.DailyCapUSD)
	}
}

// TestSol3LoadStrictRejectsNaNAndInfSpendCap reproduces corpus #14 (Sol
// finding #9): `.nan`/`.inf` pass the old bare `< 0` check (NaN compares
// false to everything; +Inf is not < 0 either) and could otherwise poison
// Hash()'s JSON marshal or downstream spend-cap comparisons.
func TestSol3LoadStrictRejectsNaNAndInfSpendCap(t *testing.T) {
	cleanEnv(t)
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"nan", ".nan"},
		{"positive infinity", ".inf"},
		{"negative infinity", "-.inf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			t.Setenv("GOV_CONFIG", path)
			if err := os.WriteFile(path, []byte("spend: {daily_cap_usd: "+tc.value+"}\n"), 0644); err != nil {
				t.Fatal(err)
			}
			_, err := LoadStrict()
			if err == nil || !strings.Contains(err.Error(), "invalid spend.daily_cap_usd") {
				t.Fatalf("expected an invalid spend.daily_cap_usd error for %s, got: %v", tc.value, err)
			}
		})
	}
}

// TestSol3LoadStrictRejectsNaNAndInfQuotaFields extends the NaN/Inf
// rejection to the quota float fields named by the audit
// ("every numeric configuration ... field").
func TestSol3LoadStrictRejectsNaNAndInfQuotaFields(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("quotas: [{backend: codex, window_type: daily, estimated_limit: .nan, confidence: 0.5}]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStrict(); err == nil || !strings.Contains(err.Error(), "invalid quota estimated_limit") {
		t.Fatalf("expected an invalid quota estimated_limit error, got: %v", err)
	}

	path2 := filepath.Join(t.TempDir(), "config2.yaml")
	t.Setenv("GOV_CONFIG", path2)
	if err := os.WriteFile(path2, []byte("quotas: [{backend: codex, window_type: daily, estimated_limit: 100, confidence: .inf}]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStrict(); err == nil || !strings.Contains(err.Error(), "invalid quota confidence") {
		t.Fatalf("expected an invalid quota confidence error, got: %v", err)
	}
}

// TestSol3LoadStrictRejectsNegativeMaxMinutesInsteadOfDefaulting is the
// exact finding #9 reproduction: merge() only overwrites the built-in
// default when the supplied value is > 0, so a negative
// defaults.max_minutes used to be silently discarded and replaced by the
// default (30) rather than rejected — the operator's mistake vanished
// instead of failing to load.
func TestSol3LoadStrictRejectsNegativeMaxMinutesInsteadOfDefaulting(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("defaults: {max_minutes: -5}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStrict()
	if err == nil || !strings.Contains(err.Error(), "invalid defaults.max_minutes") {
		t.Fatalf("expected an invalid defaults.max_minutes error, got: %v", err)
	}
}

func TestSol3LoadStrictRejectsZeroMaxMinutes(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("defaults: {max_minutes: 0}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStrict()
	if err == nil || !strings.Contains(err.Error(), "invalid defaults.max_minutes") {
		t.Fatalf("expected a job to be unable to run with an explicit zero-minute budget, got: %v", err)
	}
}

// TestSol3LoadStrictRejectsNegativeAssayTimeoutSeconds mirrors the
// max_minutes case for assay.timeout_seconds, the second field the audit
// names explicitly.
func TestSol3LoadStrictRejectsNegativeAssayTimeoutSeconds(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("assay: {repo: /tmp/assayer, timeout_seconds: -30}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStrict()
	if err == nil || !strings.Contains(err.Error(), "invalid assay.timeout_seconds") {
		t.Fatalf("expected an invalid assay.timeout_seconds error, got: %v", err)
	}
}

// TestSol3LoadStrictRejectsNegativeBackendTokenLimits covers the third and
// fourth fields the audit names: a backend's context_tokens/output_tokens.
func TestSol3LoadStrictRejectsNegativeBackendTokenLimits(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("backends: {codex: {context_tokens: -1000}}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStrict(); err == nil || !strings.Contains(err.Error(), "invalid backends.codex.context_tokens") {
		t.Fatalf("expected an invalid backends.codex.context_tokens error, got: %v", err)
	}

	path2 := filepath.Join(t.TempDir(), "config2.yaml")
	t.Setenv("GOV_CONFIG", path2)
	if err := os.WriteFile(path2, []byte("backends: {codex: {output_tokens: -1}}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStrict(); err == nil || !strings.Contains(err.Error(), "invalid backends.codex.output_tokens") {
		t.Fatalf("expected an invalid backends.codex.output_tokens error, got: %v", err)
	}
}

// TestSol3LoadStrictAcceptsZeroBackendTokenLimits proves the fix does not
// over-block: zero is this codebase's pre-existing, intentional "not
// declared" state for context_tokens/output_tokens (see Backend's doc
// comment), unlike max_minutes/timeout_seconds where zero is nonsensical.
func TestSol3LoadStrictAcceptsZeroBackendTokenLimits(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("backends: {codex: {context_tokens: 0, output_tokens: 0, vision: true}}\n"), 0644); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadStrict()
	if err != nil {
		t.Fatalf("expected zero token limits to load cleanly, got: %v", err)
	}
	if !cfg.Backends["codex"].Vision {
		t.Fatalf("expected the sibling vision:true declaration to still merge, got %+v", cfg.Backends["codex"])
	}
}

// TestSol3LoadStrictRejectsMalformedQuotaTimestamp closes the "malformed
// time windows" gap from the audit's P1.2 summary: internal/quota's
// parseTimeOrZero silently substitutes the zero time for anything it can't
// parse, so a typo'd window_started_at/reset_at used to load without error
// and quietly reset the window's clock instead.
func TestSol3LoadStrictRejectsMalformedQuotaTimestamp(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("quotas: [{backend: codex, window_type: daily, estimated_limit: 100, confidence: 0.5, reset_at: \"not-a-timestamp\"}]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStrict()
	if err == nil || !strings.Contains(err.Error(), "invalid quota reset_at") {
		t.Fatalf("expected an invalid quota reset_at error, got: %v", err)
	}
}

func TestSol3LoadStrictAcceptsWellFormedQuotaTimestamp(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("quotas: [{backend: codex, window_type: daily, estimated_limit: 100, confidence: 0.5, reset_at: \"2026-07-13T00:00:00Z\"}]\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStrict(); err != nil {
		t.Fatalf("expected a well-formed RFC3339 reset_at to load cleanly, got: %v", err)
	}
}

// TestSol3LoadStrictAllowsDuplicateYAMLMapKeysIsAlreadyRejected documents
// (rather than fixes — no change was needed) that the audit's P1.2 "reject
// ambiguous duplicate keys" requirement is already satisfied: yaml.v3's
// KnownFields(true) strict decoder errors on a duplicate mapping key by
// itself. Locking this in as a regression guard so a future dependency
// bump or decoder change can't silently reintroduce last-write-wins
// duplicate-key behavior.
func TestSol3LoadStrictAllowsDuplicateYAMLMapKeysIsAlreadyRejected(t *testing.T) {
	cleanEnv(t)
	path := filepath.Join(t.TempDir(), "config.yaml")
	t.Setenv("GOV_CONFIG", path)
	if err := os.WriteFile(path, []byte("spend:\n  daily_cap_usd: 5\n  daily_cap_usd: 10\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadStrict()
	if err == nil || !strings.Contains(err.Error(), "already defined") {
		t.Fatalf("expected a duplicate-key decode error, got: %v", err)
	}
}

// attest.probe_timeout_seconds is merged only when positive, so — exactly like
// the P1.2 findings for max_minutes/assay.timeout_seconds — a supplied bad value
// would be silently replaced by the default unless raw validation rejects it.
func TestSol3LoadStrictRejectsInvalidAttestProbeTimeout(t *testing.T) {
	cleanEnv(t)
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"zero", "0"},
		{"negative", "-5"},
		{"nan", ".nan"},
		{"positive infinity", ".inf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			t.Setenv("GOV_CONFIG", path)
			if err := os.WriteFile(path, []byte("attest: {probe_timeout_seconds: "+tc.value+"}\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadStrict(); err == nil {
				t.Fatalf("expected %s probe_timeout_seconds to be rejected, got nil error", tc.name)
			}
		})
	}
}

// attest.total_deadline_seconds (Sol P1-17) gets the identical raw-validation
// treatment as its sibling probe_timeout_seconds above, for the same reason:
// merged only when positive, so a bad supplied value would otherwise be
// silently replaced by the default instead of rejected.
func TestSol3LoadStrictRejectsInvalidAttestTotalDeadline(t *testing.T) {
	cleanEnv(t)
	for _, tc := range []struct {
		name  string
		value string
	}{
		{"zero", "0"},
		{"negative", "-5"},
		{"nan", ".nan"},
		{"positive infinity", ".inf"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cleanEnv(t)
			path := filepath.Join(t.TempDir(), "config.yaml")
			t.Setenv("GOV_CONFIG", path)
			if err := os.WriteFile(path, []byte("attest: {total_deadline_seconds: "+tc.value+"}\n"), 0644); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadStrict(); err == nil {
				t.Fatalf("expected %s total_deadline_seconds to be rejected, got nil error", tc.name)
			}
		})
	}
}
