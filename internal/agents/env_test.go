package agents

import (
	"strings"
	"testing"
)

func TestBuildAllowedEnvStripsUnlistedVariables(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("HOME", "/home/gov")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "shhh")
	t.Setenv("GITHUB_TOKEN", "shhh-too")
	t.Setenv("SSH_AUTH_SOCK", "/tmp/agent.sock")

	env := BuildAllowedEnv(nil)
	joined := strings.Join(env, "\n")
	for _, secret := range []string{"AWS_SECRET_ACCESS_KEY", "GITHUB_TOKEN", "SSH_AUTH_SOCK"} {
		if strings.Contains(joined, secret) {
			t.Fatalf("BuildAllowedEnv leaked %s into the filtered environment: %v", secret, env)
		}
	}
	if !strings.Contains(joined, "PATH=/usr/bin") {
		t.Fatalf("expected PATH to survive filtering: %v", env)
	}
	if !strings.Contains(joined, "HOME=/home/gov") {
		t.Fatalf("expected HOME to survive filtering: %v", env)
	}
}

func TestBuildAllowedEnvHonorsDeclaredExtra(t *testing.T) {
	t.Setenv("PATH", "/usr/bin")
	t.Setenv("MY_BACKEND_TOKEN", "declared")
	t.Setenv("OTHER_UNRELATED_SECRET", "not-declared")

	env := BuildAllowedEnv([]string{"MY_BACKEND_TOKEN"})
	joined := strings.Join(env, "\n")
	if !strings.Contains(joined, "MY_BACKEND_TOKEN=declared") {
		t.Fatalf("expected declared extra to survive filtering: %v", env)
	}
	if strings.Contains(joined, "OTHER_UNRELATED_SECRET") {
		t.Fatalf("undeclared variable leaked: %v", env)
	}
}

func TestEnvPolicyHashIgnoresValuesOnlyNames(t *testing.T) {
	t.Setenv("MY_BACKEND_TOKEN", "value-one")
	hashA := EnvPolicyHash([]string{"MY_BACKEND_TOKEN"})
	t.Setenv("MY_BACKEND_TOKEN", "a-completely-different-value")
	hashB := EnvPolicyHash([]string{"MY_BACKEND_TOKEN"})
	if hashA != hashB {
		t.Fatal("EnvPolicyHash must depend only on declared variable NAMES, never their values")
	}

	hashC := EnvPolicyHash([]string{"A_DIFFERENT_NAME"})
	if hashA == hashC {
		t.Fatal("EnvPolicyHash did not change when the declared variable name set changed")
	}
}

func TestEnvPolicyHashOrderIndependent(t *testing.T) {
	a := EnvPolicyHash([]string{"FOO", "BAR"})
	b := EnvPolicyHash([]string{"BAR", "FOO"})
	if a != b {
		t.Fatal("EnvPolicyHash must not depend on declaration order")
	}
}
