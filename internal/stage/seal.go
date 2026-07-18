package stage

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// SealReadonlyCopy copies path into a private temp directory and returns the
// sealed copy path plus a cleanup function. Callers use this for auxiliary
// launch inputs (for example, python scripts) that must not be re-opened from
// their original mutable pathname at execution time.
func SealReadonlyCopy(path string) (string, func(), error) {
	path = filepath.Clean(path)
	data, err := os.Open(path)
	if err != nil {
		return "", nil, fmt.Errorf("seal %s: open: %w", path, err)
	}
	defer data.Close()
	dir, err := os.MkdirTemp("", "governator-sealed-*")
	if err != nil {
		return "", nil, fmt.Errorf("seal %s: mkdir temp: %w", path, err)
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	sealed := filepath.Join(dir, filepath.Base(path))
	out, err := os.OpenFile(sealed, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		cleanup()
		return "", nil, fmt.Errorf("seal %s: create copy: %w", path, err)
	}
	_, copyErr := io.Copy(out, data)
	closeErr := out.Close()
	if copyErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("seal %s: copy: %w", path, copyErr)
	}
	if closeErr != nil {
		cleanup()
		return "", nil, fmt.Errorf("seal %s: close copy: %w", path, closeErr)
	}
	if err := os.Chmod(dir, 0500); err != nil {
		cleanup()
		return "", nil, fmt.Errorf("seal %s: chmod dir: %w", path, err)
	}
	return sealed, cleanup, nil
}
