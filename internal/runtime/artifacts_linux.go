//go:build linux

package runtime

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// consumedArtifactSeals matches assay.packageSeals exactly (Sol11 P0-6's
// precedent): once applied, the kernel refuses every write/truncate/
// mmap-write against the memfd, for every process holding any descriptor to
// it -- including this one -- never merely a permission bit a same-UID
// chmod could undo. memfd_create/F_ADD_SEALS are Linux-only syscalls --
// split into this file (and its !linux counterpart) so internal/runtime
// still cross-compiles for scripts/release.sh's darwin/amd64 and
// darwin/arm64 targets, mirroring internal/assay/snapshot_linux.go's own
// split.
const consumedArtifactSeals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL

// sealOneConsumedArtifact creates a sealed, unlinked memfd holding data,
// named for diagnostics only, then immediately seals it with
// consumedArtifactSeals. See sealConsumedArtifacts (artifacts.go) for the
// caller and sealedConsumedArtifact's doc comment for why no real host
// directory entry is ever created for it.
func sealOneConsumedArtifact(name string, data []byte) (*os.File, error) {
	fd, merr := unix.MemfdCreate("governator-consumed-"+name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
	if merr != nil {
		return nil, fmt.Errorf("create sealed consumed-artifact memfd %q: %w", name, merr)
	}
	f := os.NewFile(uintptr(fd), "governator-consumed-"+name)
	if _, werr := f.Write(data); werr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("write sealed consumed-artifact memfd %q: %w", name, werr)
	}
	// Seal immediately after writing, before this artifact is handed to any
	// launch: from this point on the kernel refuses every mutation against
	// this memfd, for every process holding any descriptor to it (Sol11
	// P0-7).
	if _, serr := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, consumedArtifactSeals); serr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("seal consumed-artifact memfd %q: %w", name, serr)
	}
	if _, serr := f.Seek(0, io.SeekStart); serr != nil {
		_ = f.Close()
		return nil, fmt.Errorf("rewind sealed consumed-artifact memfd %q: %w", name, serr)
	}
	return f, nil
}
