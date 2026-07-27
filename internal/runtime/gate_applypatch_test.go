package runtime

import (
	"os"
	"path/filepath"
	"testing"
)

func TestExtractApplyPatchPaths(t *testing.T) {
	patch := `*** Begin Patch
*** Update File: src/main.go
@@ func main() {
-old
+new
*** Add File: src/new.go
+package main
*** Delete File: src/old.go
*** Update File: src/renamed_from.go
*** Move to: src/renamed_to.go
*** End Patch`

	got := ExtractApplyPatchPaths(patch)
	want := []string{"src/main.go", "src/new.go", "src/old.go", "src/renamed_from.go", "src/renamed_to.go"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestParseApplyPatchPathsRejectsMalformedEnvelope(t *testing.T) {
	if _, err := ParseApplyPatchPaths("not a patch at all"); err == nil {
		t.Fatal("expected malformed apply_patch envelope to fail")
	}
}

func TestGateDecideApplyPatchBlocksProtectedPath(t *testing.T) {
	protected := t.TempDir()
	protectedFile := filepath.Join(protected, "feed.xml")
	if err := os.WriteFile(protectedFile, []byte("finished\n"), 0600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(protectedFile+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", manifest)
	t.Setenv("HARNESS_UNLOCK", "")

	patch := "*** Begin Patch\n*** Update File: " + protectedFile + "\n@@\n-old\n+new\n*** End Patch"
	d := GateDecideApplyPatch(t.TempDir(), patch)
	if d.Allow {
		t.Fatalf("expected apply_patch touching a protected file to be blocked, got %#v", d)
	}
	if d.Finding != "F2" {
		t.Fatalf("expected F2 to decide, got %s (reason=%s)", d.Finding, d.Reason)
	}
}

func TestGateDecideApplyPatchAllowsScratchPath(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", manifest)

	scratch := filepath.Join(t.TempDir(), "scratch.go")
	patch := "*** Begin Patch\n*** Add File: " + scratch + "\n+package main\n*** End Patch"
	d := GateDecideApplyPatch(t.TempDir(), patch)
	if !d.Allow {
		t.Fatalf("expected apply_patch touching an unprotected scratch file to allow, got %#v", d)
	}
}

func TestGateDecideApplyPatchUnknownDirectiveDenies(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "protected_paths.txt")
	if err := os.WriteFile(manifest, []byte(""), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GOV_PROTECTED_PATHS", manifest)

	patch := "*** Begin Patch\n*** Rename File: scratch.go\n*** End Patch"
	d := GateDecideApplyPatch(t.TempDir(), patch)
	if d.Allow {
		t.Fatalf("expected unknown apply_patch directive to deny, got %#v", d)
	}
	if d.Finding != "F2_APPLY_PATCH_PROTOCOL_ERROR" {
		t.Fatalf("expected protocol-error finding, got %s", d.Finding)
	}
}
