//go:build redteam && linux

// v12_s6_platform_linux_test.go implements Sol12 P1-1's corpus case 32
// ("Linux build with the memfd implementation") -- the positive companion
// to internal/redteam/v12_s6_platform_test.go's cases 33-36. Linux-only
// (like v10_s4_snapshot_immutability_test.go) because it exercises
// sealPackageMemfd/verifyPackageSeals/packageSeals directly, all defined
// only under `//go:build linux` (snapshot_linux.go) after this session's
// platform split.
package assay

import (
	"io"
	"testing"
)

// TestV12Case32LinuxSealedMemfdRoundTripSucceeds proves the platform split
// (snapshot_linux.go/snapshot_other.go) didn't change Linux's real
// behavior: sealPackageMemfd still creates a genuinely sealed, unlinked,
// unwritable memfd, and verifyPackageSeals still confirms it.
func TestV12Case32LinuxSealedMemfdRoundTripSucceeds(t *testing.T) {
	content := []byte("v12-case32-linux-memfd-round-trip")

	pkg, err := sealPackageMemfd(content)
	if err != nil {
		t.Fatalf("sealPackageMemfd: %v", err)
	}
	defer func() { _ = pkg.Close() }()

	if err := verifyPackageSeals(pkg); err != nil {
		t.Fatalf("verifyPackageSeals on a freshly sealed memfd: %v", err)
	}

	if _, err := pkg.WriteAt([]byte("x"), 0); err == nil {
		t.Fatal("expected a write against the sealed memfd to fail, got nil error")
	}

	if _, err := pkg.Seek(0, io.SeekStart); err != nil {
		t.Fatalf("rewind sealed memfd: %v", err)
	}
	got, rerr := io.ReadAll(pkg)
	if rerr != nil {
		t.Fatalf("read sealed memfd: %v", rerr)
	}
	if string(got) != string(content) {
		t.Fatalf("sealed memfd content = %q, want %q", got, content)
	}
}
