package contracts

import (
	"sort"
	"strings"
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

// TestDockerIsHardened pins Session 3/6's definition of hardened containment:
// every one of the privilege-reducing controls must be set, and the image
// must carry a true digest. A nil config is never hardened, so a high-risk
// job with no docker block cannot sneak through IsHardened.
func TestDockerIsHardened(t *testing.T) {
	pinned := "ghcr.io/acme/agent@sha256:" + strings.Repeat("a", 64)
	cases := []struct {
		name string
		d    *DockerRunnerConfig
		want bool
	}{
		{"nil config", nil, false},
		{"bare image no controls", &DockerRunnerConfig{Image: "agent:latest"}, false},
		{"all controls but mutable tag", &DockerRunnerConfig{
			Image: "agent:latest", User: "65532:65532", ReadOnlyRootfs: true,
			CapDropAll: true, NoNewPrivileges: true,
		}, false},
		{"pinned image but missing one control", &DockerRunnerConfig{
			Image: pinned, User: "65532:65532", ReadOnlyRootfs: true,
			CapDropAll: true, // NoNewPrivileges missing
		}, false},
		{"pinned image all controls", &DockerRunnerConfig{
			Image: pinned, User: "65532:65532", ReadOnlyRootfs: true,
			CapDropAll: true, NoNewPrivileges: true,
		}, true},
		// Session 6 (Sol High 8): AllowMutableTag must NEVER yield hardened —
		// it is a logged exception (MutableTagException), not containment. A
		// high-risk job on a mutable tag must go through the signed operator
		// override in internal/containment instead.
		{"mutable tag with explicit exception all controls still not hardened", &DockerRunnerConfig{
			Image: "agent:latest", AllowMutableTag: true, User: "65532:65532",
			ReadOnlyRootfs: true, CapDropAll: true, NoNewPrivileges: true,
		}, false},
		// Session 6 (Sol High 8): a truncated/malformed digest must not pass —
		// the prior check was a bare strings.Contains(image, "@sha256:").
		{"short digest not a real 64-hex digest", &DockerRunnerConfig{
			Image: "agent@sha256:" + strings.Repeat("a", 10), User: "65532:65532",
			ReadOnlyRootfs: true, CapDropAll: true, NoNewPrivileges: true,
		}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.d.IsHardened(); got != c.want {
				t.Fatalf("IsHardened() = %v, want %v", got, c.want)
			}
		})
	}
}

// TestDockerHardenedRejectsRootUser is the direct regression test for Sol
// High 8's "root user accepted" reproduction: User values "root", "0", and
// "0:0" all previously satisfied `d.User != ""` and qualified as hardened.
func TestDockerHardenedRejectsRootUser(t *testing.T) {
	pinned := "ghcr.io/acme/agent@sha256:" + strings.Repeat("a", 64)
	base := func(user string) *DockerRunnerConfig {
		return &DockerRunnerConfig{
			Image: pinned, User: user, ReadOnlyRootfs: true,
			CapDropAll: true, NoNewPrivileges: true,
		}
	}
	for _, rootLike := range []string{"root", "0", "0:0", "ROOT", "root:root", "0:root"} {
		if base(rootLike).IsHardened() {
			t.Fatalf("User %q must not qualify as hardened", rootLike)
		}
	}
	// A syntactically invalid user (not root, just malformed) must also be
	// rejected: "validate user/group syntax" per the fix list.
	if base("not a valid user!!").IsHardened() {
		t.Fatal("syntactically invalid user must not qualify as hardened")
	}
	// The documented non-root form must still pass.
	if !base("65532:65532").IsHardened() {
		t.Fatal("65532:65532 is a valid non-root user and should be hardened (all else equal)")
	}
}

// TestMutableTagException pins the Session 6 replacement for the old
// AllowMutableTag containment escape hatch: it is now purely a logging
// signal (an explicit, documented exception), never a path to IsHardened.
func TestMutableTagException(t *testing.T) {
	if (&DockerRunnerConfig{Image: "agent:latest"}).MutableTagException() {
		t.Fatal("AllowMutableTag unset must never report an exception")
	}
	if !(&DockerRunnerConfig{Image: "agent:latest", AllowMutableTag: true}).MutableTagException() {
		t.Fatal("mutable tag with AllowMutableTag set must report the exception")
	}
	pinned := "ghcr.io/acme/agent@sha256:" + strings.Repeat("a", 64)
	if (&DockerRunnerConfig{Image: pinned, AllowMutableTag: true}).MutableTagException() {
		t.Fatal("a digest-pinned image is not a mutable-tag exception even with the flag set")
	}
}

// TestValidateContainmentOverrideBothOrNeither pins the fail-closed rule: an
// override reason and signature must appear together — a half-declared escape
// hatch is never silently accepted as either "no override" or "override
// granted." Calls validateContainment directly (the add closure) so the test
// isolates this one validator from every other Contract.Validate requirement.
func TestValidateContainmentOverrideBothOrNeither(t *testing.T) {
	cases := []struct {
		name        string
		cont        *Containment
		wantErrOn   string
		expectClean bool
	}{
		{"absent is fine", nil, "", true},
		{"empty is fine", &Containment{}, "", true},
		{"reason without signature", &Containment{OverrideReason: "trusted host"}, "containment.override_signature", false},
		{"signature without reason", &Containment{OverrideSignature: "deadbeef"}, "containment.override_reason", false},
		{"both present passes structurally", &Containment{OverrideReason: "ok", OverrideSignature: "abcd"}, "", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var errs ValidationErrors
			add := func(field, message string) { errs = append(errs, ValidationError{Field: field, Message: message}) }
			validateContainment(Contract{JobID: "j", Containment: c.cont}, add)
			if c.expectClean {
				if len(errs) != 0 {
					t.Fatalf("expected no validation error, got %+v", errs)
				}
				return
			}
			found := false
			for _, ve := range errs {
				if ve.Field == c.wantErrOn {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected field %q, got %+v", c.wantErrOn, errs)
			}
		})
	}
}

// TestValidateRunnerHardeningFieldsStructural calls validateRunner directly to
// isolate the Session 3 seccomp/tmpfs/egress structural checks from the rest
// of Contract.Validate.
func TestValidateRunnerHardeningFieldsStructural(t *testing.T) {
	cases := []struct {
		name   string
		docker DockerRunnerConfig
		field  string
	}{
		{"relative seccomp profile", DockerRunnerConfig{Image: "img:latest", SeccompProfile: "rel/seccomp.json"}, "docker.seccomp_profile"},
		{"blank tmpfs entry", DockerRunnerConfig{Image: "img:latest", Tmpfs: []string{"/tmp", "  "}}, "docker.tmpfs[1]"},
		// Any non-empty egress_allowlist is rejected outright (fail-closed):
		// the docker runner has no mechanism to enforce it, and an unenforced
		// allowlist reading as a restriction is a silently-broken control.
		{"egress allowlist rejected as unenforceable", DockerRunnerConfig{Image: "img:latest", EgressAllowlist: []string{"api.example.com:443"}}, "docker.egress_allowlist"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var errs ValidationErrors
			add := func(field, message string) { errs = append(errs, ValidationError{Field: field, Message: message}) }
			validateRunner(Contract{Runner: "docker", Docker: &c.docker}, add)
			found := false
			for _, ve := range errs {
				if ve.Field == c.field {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("expected field %q in errors, got %+v", c.field, errs)
			}
		})
	}
}

func TestIsHardenedRequiresNetworkDeny(t *testing.T) {
	// Unrestricted egress is a data-exfiltration path no filesystem or
	// capability control compensates for: a config with every other control
	// set but network: allow must NOT count as hardened. A high-risk job
	// that genuinely needs the network goes through the signed override.
	d := &DockerRunnerConfig{
		Image: "ghcr.io/acme/agent@sha256:" + strings.Repeat("a", 64),
		User:  "65532:65532", ReadOnlyRootfs: true, CapDropAll: true, NoNewPrivileges: true,
	}
	if !d.IsHardened() {
		t.Fatal("fully-hardened config with default (deny) network should be hardened")
	}
	d.Network = "allow"
	if d.IsHardened() {
		t.Fatal("network: allow must disqualify a config from hardened")
	}
	d.Network = "deny"
	if !d.IsHardened() {
		t.Fatal("explicit network: deny should be hardened")
	}
}
