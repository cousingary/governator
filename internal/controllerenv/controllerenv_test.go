package controllerenv

import (
	"strings"
	"testing"
)

func TestFrozenEnvironmentIgnoresAmbientMutation(t *testing.T) {
	t.Setenv("PATH", "/controller/original")
	t.Setenv("HOME", "/controller/home")
	frozen := Freeze()

	t.Setenv("PATH", "/attacker/replacement")
	t.Setenv("HOME", "/attacker/home")
	derived := frozen.With(map[string]string{"LANG": "C"})

	path, ok := derived.Lookup("PATH")
	if !ok || path != "/controller/original" {
		t.Fatalf("derived PATH = %q, want frozen value", path)
	}
	home, ok := derived.Lookup("HOME")
	if !ok || home != "/controller/home" {
		t.Fatalf("derived HOME = %q, want frozen value", home)
	}
	if strings.Contains(strings.Join(derived.Values, "\n"), "/attacker/") {
		t.Fatalf("derived environment inherited post-freeze ambient values: %v", derived.Values)
	}
	if err := derived.Validate(); err != nil {
		t.Fatalf("derived frozen environment: %v", err)
	}
}

func TestFrozenEnvironmentHashDetectsMutation(t *testing.T) {
	frozen := Frozen{Values: []string{"PATH=/trusted"}}
	frozen.Hash = Hash(frozen.Values)
	frozen.Values[0] = "PATH=/replaced"
	if err := frozen.Validate(); err == nil {
		t.Fatal("mutated frozen values passed hash validation")
	}
}
