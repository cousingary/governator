package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBackendHelpArgs(t *testing.T) {
	tests := []struct {
		name string
		in   []string
		want string
	}{
		{name: "root help", want: "--help"},
		{name: "subcommand help", in: []string{"run"}, want: "run --help"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := backendHelpArgs(test.in)
			if strings.Join(got, " ") != test.want {
				t.Fatalf("backendHelpArgs(%q) = %q, want %q", test.in, got, test.want)
			}
			if len(test.in) > 0 && test.in[0] != "run" {
				t.Fatalf("backendHelpArgs mutated its input: %q", test.in)
			}
		})
	}
}

func TestBackendFlagDriftFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	fake := filepath.Join(t.TempDir(), "opencode")
	if err := os.WriteFile(fake, []byte("#!/bin/sh\nprintf '%s\\n' '--format'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_OPENCODE_BIN", fake)

	check := checkBackendFlags("opencode", "opencode", []string{"run"}, []string{"--format", "--dir"})
	if check.Status != StatusFail {
		t.Fatalf("status = %s, want %s: %s", check.Status, StatusFail, check.Detail)
	}
	if !strings.Contains(check.Detail, "--dir") {
		t.Fatalf("missing drift detail: %s", check.Detail)
	}
}
