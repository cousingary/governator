package contracts

import "testing"

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
