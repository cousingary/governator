package minimalism

import (
	"strings"
	"testing"
)

func TestResolveDefaultsToFull(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_MINIMALISM_MODE", "")
	status, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if status.Mode != "full" || !status.Enabled {
		t.Fatalf("status=%+v", status)
	}
}

func TestResolveOffDisables(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_MINIMALISM_MODE", "off")
	status, err := Resolve()
	if err != nil {
		t.Fatal(err)
	}
	if status.Enabled {
		t.Fatalf("status=%+v", status)
	}
}

func TestPromptAnnotationOffReturnsEmpty(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOV_CONFIG", "")
	t.Setenv("GOV_MINIMALISM_MODE", "off")
	annotation, err := PromptAnnotation()
	if err != nil {
		t.Fatal(err)
	}
	if annotation != "" {
		t.Fatalf("annotation=%q", annotation)
	}
}

func TestPromptAnnotationLiteVsFullVsUltra(t *testing.T) {
	cases := []struct {
		mode     string
		want     []string
		wantNots []string
	}{
		{mode: "lite", want: []string{"ponytail:"}, wantNots: []string{"1. Skip it", "Ultra mode"}},
		{mode: "full", want: []string{"1. Skip it", "ponytail:"}, wantNots: []string{"Ultra mode"}},
		{mode: "ultra", want: []string{"1. Skip it", "ponytail:", "Ultra mode"}},
	}
	for _, c := range cases {
		t.Run(c.mode, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			t.Setenv("GOV_CONFIG", "")
			t.Setenv("GOV_MINIMALISM_MODE", c.mode)
			annotation, err := PromptAnnotation()
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range c.want {
				if !strings.Contains(annotation, want) {
					t.Fatalf("mode=%s annotation missing %q: %q", c.mode, want, annotation)
				}
			}
			for _, wantNot := range c.wantNots {
				if strings.Contains(annotation, wantNot) {
					t.Fatalf("mode=%s annotation unexpectedly contains %q: %q", c.mode, wantNot, annotation)
				}
			}
		})
	}
}
