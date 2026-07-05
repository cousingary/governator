package tokenoptimizer

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveAutoMissing(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_RTK_MODE", "auto")
	t.Setenv("GOV_RTK_BIN", "rtk-not-present")
	t.Setenv("PATH", t.TempDir())
	status, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if status.Enabled {
		t.Fatalf("unexpected status: %+v", status)
	}
}

func TestRequiredMissingFails(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_RTK_MODE", "required")
	t.Setenv("GOV_RTK_BIN", "rtk-not-present")
	t.Setenv("PATH", t.TempDir())
	if _, err := Resolve(); err == nil || !strings.Contains(err.Error(), "required") {
		t.Fatalf("error=%v", err)
	}
}

func TestPromptAnnotationWhenAvailable(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(t.TempDir(), "rtk")
	if err := os.WriteFile(bin, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_RTK_MODE", "auto")
	t.Setenv("GOV_RTK_BIN", bin)
	annotation, err := PromptAnnotation()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(annotation, "RTK is available") || !strings.Contains(annotation, "not an authority bypass") {
		t.Fatalf("annotation=%q", annotation)
	}
}
