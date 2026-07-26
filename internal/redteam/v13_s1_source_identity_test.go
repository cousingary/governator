//go:build redteam

package redteam

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/redteamgate"
)

type v13SourceIdentity struct {
	TestSourceHash   string   `json:"test_source_hash"`
	TestBinarySHA256 string   `json:"test_binary_sha256"`
	Inventory        []string `json:"inventory"`
	RedteamSources   []struct {
		Path string `json:"path"`
	} `json:"redteam_sources"`
}

func v13IdentityScript(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve red-team source identity test path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", "redteam_source_identity.py")
}

func v13WriteFile(t *testing.T, root, name, content string) string {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// v13IdentityFixture is intentionally a complete tiny Go module. The real
// identity script must use Go's tagged package selection and compile test
// binaries, so testing it against text fragments would miss its security
// boundary.
func v13IdentityFixture(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	script, err := os.ReadFile(v13IdentityScript(t))
	if err != nil {
		t.Fatal(err)
	}
	testNamesHelper, err := os.ReadFile(filepath.Join(filepath.Dir(v13IdentityScript(t)), "redteam_test_names.go"))
	if err != nil {
		t.Fatal(err)
	}
	v13WriteFile(t, root, "go.mod", "module example.com/redteam-identity\n\ngo 1.26.0\n")
	v13WriteFile(t, root, "go.sum", "")
	v13WriteFile(t, root, "scripts/redteam_source_identity.py", string(script))
	v13WriteFile(t, root, "scripts/redteam_capabilities.py", "print('{}')\n")
	v13WriteFile(t, root, "scripts/redteam_test_names.go", string(testNamesHelper))
	v13WriteFile(t, root, "scripts/redteam.sh", "#!/usr/bin/env bash\ngo test -tags redteam ./...\n")
	v13WriteFile(t, root, "internal/redteam/manifest.yaml", "version: 1\ncases: []\n")
	v13WriteFile(t, root, "internal/redteamgate/gate.go", "package redteamgate\n")
	v13WriteFile(t, root, "internal/redteam/fixtures/evidence.txt", "fixture\n")
	v13WriteFile(t, root, "internal/redteam/inside_test.go", `//go:build redteam

package redteam

import "testing"

func TestInside(t *testing.T) {}
`)
	v13WriteFile(t, root, "internal/assay/outside_test.go", `//go:build redteam

package assay

import "testing"

const outsideMarker = "outside-v1"

const embeddedTestText = "func TestEmbeddedTextMustNotEnterInventory(t *testing.T) {}"

func TestOutsideRedteam(t *testing.T) {
	if outsideMarker != "outside-v1" {
		t.Fatal(outsideMarker)
	}
}
`)
	return root
}

func v13Identity(t *testing.T, root string) v13SourceIdentity {
	t.Helper()
	out := filepath.Join(t.TempDir(), "identity.json")
	cmd := exec.Command("python3", v13IdentityScript(t), "--repo-root", root, "--out", out)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("redteam_source_identity.py: %v\n%s", err, output)
	}
	data, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	var identity v13SourceIdentity
	if err := json.Unmarshal(data, &identity); err != nil {
		t.Fatal(err)
	}
	return identity
}

func v13Replace(t *testing.T, path, old, replacement string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), old, replacement, 1)
	if updated == string(data) {
		t.Fatalf("%s did not contain %q", path, old)
	}
	if err := os.WriteFile(path, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestV13Case1RedteamTaggedTestOutsideRedteamDirChangesInvalidatesSourceHash
// proves that the source set follows Go's redteam build tag repository-wide,
// rather than a path containing /redteam/.
func TestV13Case1RedteamTaggedTestOutsideRedteamDirChangesInvalidatesSourceHash(t *testing.T) {
	root := v13IdentityFixture(t)
	before := v13Identity(t, root)
	v13Replace(t, filepath.Join(root, "internal/assay/outside_test.go"), "outside-v1", "outside-v2")
	after := v13Identity(t, root)
	if before.TestSourceHash == after.TestSourceHash {
		t.Fatal("a redteam-tagged test outside internal/redteam did not change test_source_hash")
	}
	if !contains(before.Inventory, "TestOutsideRedteam") {
		t.Fatalf("outside redteam-tagged test missing from inventory: %v", before.Inventory)
	}
	if contains(before.Inventory, "TestEmbeddedTextMustNotEnterInventory") {
		t.Fatalf("test-shaped text was mistaken for an inventory entry: %v", before.Inventory)
	}
	found := false
	for _, source := range before.RedteamSources {
		if source.Path == "internal/assay/outside_test.go" {
			found = true
		}
	}
	if !found {
		t.Fatalf("outside redteam-tagged test missing from source identity: %+v", before.RedteamSources)
	}
}

// TestV13Case2ManifestChangeInvalidatesAttestationBinding proves the exact
// release manifest is an input to the signed attestation source identity.
func TestV13Case2ManifestChangeInvalidatesAttestationBinding(t *testing.T) {
	root := v13IdentityFixture(t)
	before := v13Identity(t, root)
	v13Replace(t, filepath.Join(root, "internal/redteam/manifest.yaml"), "cases: []", "cases: []\n# changed")
	if after := v13Identity(t, root); before.TestSourceHash == after.TestSourceHash {
		t.Fatal("manifest change did not invalidate test_source_hash")
	}
}

// TestV13Case3CapabilityProbeChangeInvalidatesAttestationBinding proves the
// capability-probe implementation cannot be changed after host evidence was
// created without invalidating that evidence.
func TestV13Case3CapabilityProbeChangeInvalidatesAttestationBinding(t *testing.T) {
	root := v13IdentityFixture(t)
	before := v13Identity(t, root)
	v13Replace(t, filepath.Join(root, "scripts/redteam_capabilities.py"), "print('{}')", "print('{\\\"changed\\\": true}')")
	if after := v13Identity(t, root); before.TestSourceHash == after.TestSourceHash {
		t.Fatal("capability-probe change did not invalidate test_source_hash")
	}
}

// TestV13Case4CompiledRedteamTestBinaryChangeInvalidatesAttestationBinding
// proves the aggregate hash over per-package `go test -c` outputs changes
// when a tagged test's compiled behavior changes.
func TestV13Case4CompiledRedteamTestBinaryChangeInvalidatesAttestationBinding(t *testing.T) {
	root := v13IdentityFixture(t)
	before := v13Identity(t, root)
	v13Replace(t, filepath.Join(root, "internal/assay/outside_test.go"), "outside-v1", "outside-v2")
	after := v13Identity(t, root)
	if before.TestBinarySHA256 == after.TestBinarySHA256 {
		t.Fatal("compiled redteam test binary change did not invalidate test_binary_sha256")
	}
	attestations := []redteamgate.CapabilityAttestation{
		{
			GovernatorCommit: "governator-commit",
			AssayerCommit:    "assayer-commit",
			TestSourceHash:   before.TestSourceHash,
			TestBinarySHA256: before.TestBinarySHA256,
			ToolchainHash:    "toolchain",
			ReleaseVersion:   "v1.0.2-rc6",
		},
		{
			GovernatorCommit: "governator-commit",
			AssayerCommit:    "assayer-commit",
			TestSourceHash:   before.TestSourceHash,
			TestBinarySHA256: after.TestBinarySHA256,
			ToolchainHash:    "toolchain",
			ReleaseVersion:   "v1.0.2-rc6",
		},
	}
	if ok, message := redteamgate.BindingConsistent(attestations); ok {
		t.Fatalf("different compiled redteam test binaries remained binding-consistent: %s", message)
	}
}
