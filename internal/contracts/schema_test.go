package contracts

import (
	"sort"
	"testing"
)

func TestRepairEffectiveMaxAttemptsClampsAndDefaults(t *testing.T) {
	cases := []struct {
		name string
		r    *Repair
		want int
	}{
		{"nil repair block", nil, 0},
		{"unset defaults to 1", &Repair{Auto: true}, 1},
		{"explicit 1 stays 1", &Repair{Auto: true, MaxAttempts: 1}, 1},
		{"explicit 2 stays 2", &Repair{Auto: true, MaxAttempts: 2}, 2},
		{"3 or more clamps to 2", &Repair{Auto: true, MaxAttempts: 5}, 2},
		{"negative treated as unset", &Repair{Auto: true, MaxAttempts: -1}, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.EffectiveMaxAttempts(); got != c.want {
				t.Fatalf("EffectiveMaxAttempts() = %d, want %d", got, c.want)
			}
		})
	}
}

func TestModeReadOnly(t *testing.T) {
	readOnly := []Mode{ModeScout, ModeVerifier, ModeArchitect}
	writable := []Mode{ModeSurgeon, ModeBatchWorker, ModeRepair}
	for _, m := range readOnly {
		if !m.ReadOnly() {
			t.Fatalf("%s: expected ReadOnly() true", m)
		}
	}
	for _, m := range writable {
		if m.ReadOnly() {
			t.Fatalf("%s: expected ReadOnly() false", m)
		}
	}
}

func TestRoutingEffectiveObjectiveDefaults(t *testing.T) {
	cases := []struct {
		name string
		r    *Routing
		want string
	}{
		{"nil routing block", nil, "balanced"},
		{"empty objective", &Routing{}, "balanced"},
		{"explicit cheapest", &Routing{Objective: "cheapest"}, "cheapest"},
		{"explicit most_reliable", &Routing{Objective: "most_reliable"}, "most_reliable"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.EffectiveObjective(); got != c.want {
				t.Fatalf("EffectiveObjective() = %q, want %q", got, c.want)
			}
		})
	}
}

func TestRoutingEffectiveMaxAttemptsDefaults(t *testing.T) {
	cases := []struct {
		name string
		r    *Routing
		want int
	}{
		{"nil routing block", nil, 2},
		{"unset defaults to 2", &Routing{}, 2},
		{"explicit 1 stays 1", &Routing{MaxAttempts: 1}, 1},
		{"explicit 3 stays 3", &Routing{MaxAttempts: 3}, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.r.EffectiveMaxAttempts(); got != c.want {
				t.Fatalf("EffectiveMaxAttempts() = %d, want %d", got, c.want)
			}
		})
	}
}

// TestValidAgentsMatchesCanonicalBackends pins the validation set to the
// backends internal/agents.New actually launches. validAgents is a deliberate
// copy (contracts cannot import agents without a cycle), so this test catches
// accidental drift here; router_test.TestRegisteredAgentsMatchesAgentsNew
// catches drift on the agents side.
func TestValidAgentsMatchesCanonicalBackends(t *testing.T) {
	want := []string{"claude-code", "claude", "codex", "glm", "opencode", "pi"}
	got := make([]string, 0, len(validAgents))
	for name := range validAgents {
		got = append(got, name)
	}
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		t.Fatalf("validAgents drift: got %v want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("validAgents drift: got %v want %v", got, want)
		}
	}
}
