package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cousingary/governator/internal/observability"
)

func captureHook(t *testing.T, script string) string {
	t.Helper()
	oldIn, oldOut := os.Stdin, os.Stdout
	inR, inW, _ := os.Pipe()
	outR, outW, _ := os.Pipe()
	_, _ = inW.WriteString(`{"tool_name":"Read","tool_input":{}}`)
	_ = inW.Close()
	os.Stdin, os.Stdout = inR, outW
	code := run([]string{"hook", "pre-tool-use", "--shadow", script})
	_ = outW.Close()
	os.Stdin, os.Stdout = oldIn, oldOut
	data, _ := io.ReadAll(outR)
	if code != 0 {
		t.Fatalf("hook exit=%d", code)
	}
	return string(data)
}

func TestShadowParityMatchMismatchUnavailable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)
	dir := t.TempDir()
	write := func(name, body string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(body), 0700); err != nil {
			t.Fatal(err)
		}
		return path
	}
	allow := write("allow.py", "import sys\nsys.stdin.read()\n")
	deny := write("deny.py", "import sys\nsys.stdin.read()\nsys.stdout.write('DENY')\n")
	crash := write("crash.py", "raise SystemExit(1)\n")

	if got := captureHook(t, allow); got != "" {
		t.Fatalf("allow output=%q", got)
	}
	if got := captureHook(t, deny); got != "DENY" {
		t.Fatalf("deny output=%q", got)
	}
	if got := captureHook(t, crash); got != "" {
		t.Fatalf("fallback output=%q", got)
	}

	report, err := observability.ParitySummary(home)
	if err != nil {
		t.Fatal(err)
	}
	if report.Total != 3 || report.Matches != 1 || report.Mismatches != 1 || report.Unavailable != 1 {
		t.Fatalf("report=%+v", report)
	}
}
