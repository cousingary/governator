//go:build linux

package assay

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// packageSeals is the exact seal set sealPackageMemfd applies to Package --
// content can never again be written, shrunk, grown, or have further seals
// added, for any process holding any descriptor to this memfd.
// memfd_create/F_ADD_SEALS are Linux-only syscalls -- split into this file
// (and its !linux counterpart) so internal/assay still cross-compiles for
// scripts/release.sh's darwin/amd64 and darwin/arm64 targets, even though
// BuildSnapshot already refuses to run at all on a non-Linux GOOS before
// reaching this code (see its runtime.GOOS guard). Mirrors
// internal/enforce/consumed_linux.go's own split.
const packageSeals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL

// sealPackageMemfd creates a sealed, unlinked memfd (never linkat'd into any
// directory) holding zipBytes, then immediately seals it with packageSeals:
// from that point on the kernel refuses every write/truncate/mmap-write
// against it, for every process holding any descriptor to it -- including
// this one. See Snapshot's doc comment (snapshot.go) for why this replaced
// the private-directory-copy approach.
func sealPackageMemfd(zipBytes []byte) (*os.File, error) {
	fd, merr := unix.MemfdCreate("governator-assayer-package", unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if merr != nil {
		return nil, fmt.Errorf("create sealed package memfd: %w", merr)
	}
	pkg := os.NewFile(uintptr(fd), "governator-assayer-package")
	ok := false
	defer func() {
		if !ok {
			_ = pkg.Close()
		}
	}()
	if _, werr := pkg.Write(zipBytes); werr != nil {
		return nil, fmt.Errorf("write sealed package memfd: %w", werr)
	}
	// Seal immediately after writing, before this snapshot is handed to any
	// caller: from this point on the kernel refuses every write/truncate/
	// mmap-write against this memfd, for every process holding any
	// descriptor to it (including this one) -- not merely a permission bit
	// a same-UID chmod could undo.
	if _, serr := unix.FcntlInt(pkg.Fd(), unix.F_ADD_SEALS, packageSeals); serr != nil {
		return nil, fmt.Errorf("seal package memfd: %w", serr)
	}
	if _, serr := pkg.Seek(0, io.SeekStart); serr != nil {
		return nil, fmt.Errorf("rewind sealed package memfd: %w", serr)
	}
	ok = true
	return pkg, nil
}

// verifyPackageSeals confirms pkg still carries exactly packageSeals -- see
// Snapshot.Verify's doc comment (snapshot.go) for why this is
// defense-in-depth rather than the load-bearing detection mechanism it once
// was.
func verifyPackageSeals(pkg *os.File) error {
	seals, err := unix.FcntlInt(pkg.Fd(), unix.F_GET_SEALS, 0)
	if err != nil {
		return fmt.Errorf("read package seal state: %w", err)
	}
	if seals&packageSeals != packageSeals {
		return fmt.Errorf("package seal state changed (want at least %#o, got %#o)", packageSeals, seals)
	}
	return nil
}
