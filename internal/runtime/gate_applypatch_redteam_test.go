//go:build redteam

package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGateDecideApplyPatchMissingCommandDenies(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", manifest)

	d := GateDecideApplyPatch(t.TempDir(), "")
	if d.Allow {
		t.Fatalf("expected empty apply_patch command to deny, got %#v", d)
	}
	if d.Finding != "F2_APPLY_PATCH_PROTOCOL_ERROR" {
		t.Fatalf("expected protocol-error finding, got %s", d.Finding)
	}
}

func TestGateDecideApplyPatchMalformedEnvelopeDenies(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", manifest)

	d := GateDecideApplyPatch(t.TempDir(), "malformed patch body with no headers")
	if d.Allow {
		t.Fatalf("expected malformed apply_patch envelope to deny, got %#v", d)
	}
	if d.Finding != "F2_APPLY_PATCH_PROTOCOL_ERROR" {
		t.Fatalf("expected protocol-error finding, got %s", d.Finding)
	}
}
