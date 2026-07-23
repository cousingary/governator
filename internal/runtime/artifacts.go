package runtime

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/observability"
	"github.com/cousingary/governator/internal/pathsafe"
)

type stagedArtifact struct {
	Name   string
	Path   string
	SHA256 string
	Bytes  int64
	// data is the sealed content captured before replay lookup. It is never
	// serialized into identity; SHA256 and Bytes bind it there.
	data []byte
}

func consumedArtifactIdentities(db *sql.DB, home string, c contracts.Contract) ([]stagedArtifact, error) {
	if len(c.Consumes) == 0 {
		return nil, nil
	}
	if len(c.ArtifactSources) == 0 {
		return nil, fmt.Errorf("consumes declared but no artifact sources were resolved by plan validation")
	}
	artifactsRoot, err := filepath.Abs(filepath.Join(home, "artifacts"))
	if err != nil {
		return nil, err
	}
	out := make([]stagedArtifact, 0, len(c.Consumes))
	for _, name := range c.Consumes {
		producer := c.ArtifactSources[name]
		if producer == "" {
			return nil, fmt.Errorf("consumed artifact %q has no producing job_id", name)
		}
		var src, sha string
		var size int64
		err := db.QueryRow(`SELECT a.path,a.sha256,a.bytes FROM artifacts a JOIN runs r ON r.id=a.run_id WHERE a.name=? AND r.job_id=? AND r.status='APPROVED' ORDER BY r.created DESC LIMIT 1`, name, producer).Scan(&src, &sha, &size)
		if err != nil {
			if err == sql.ErrNoRows {
				return nil, fmt.Errorf("consumed artifact %q from job %q is not available in the ledger", name, producer)
			}
			return nil, err
		}
		if cleanSlash(name) != name || name == "." || strings.Contains(name, "/") || strings.Contains(name, `\`) {
			return nil, fmt.Errorf("consumed artifact %q is not a safe basename", name)
		}
		srcAbs, err := filepath.Abs(src)
		if err != nil {
			return nil, err
		}
		srcRel, err := filepath.Rel(artifactsRoot, srcAbs)
		if err != nil || srcRel == ".." || strings.HasPrefix(srcRel, ".."+string(os.PathSeparator)) {
			return nil, fmt.Errorf("consumed artifact %q ledger path escapes artifacts root: %s", name, src)
		}
		data, info, err := readRegularBeneath(artifactsRoot, filepath.ToSlash(srcRel))
		if err != nil {
			return nil, fmt.Errorf("identify consumed artifact %q beneath-root read: %w", name, err)
		}
		if size >= 0 && info.Size() != size {
			return nil, fmt.Errorf("identify consumed artifact %q size mismatch: ledger=%d actual=%d", name, size, info.Size())
		}
		actualSum := sha256.Sum256(data)
		actualSHA := hex.EncodeToString(actualSum[:])
		if sha != "" && actualSHA != sha {
			return nil, fmt.Errorf("identify consumed artifact %q sha256 mismatch", name)
		}
		out = append(out, stagedArtifact{Name: name, Path: filepath.ToSlash(filepath.Join(".governator", "consumed", name)), SHA256: actualSHA, Bytes: info.Size(), data: append([]byte(nil), data...)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func consumedArtifactsHash(artifacts []stagedArtifact) string {
	if len(artifacts) == 0 {
		return "none"
	}
	return hashJSON(artifacts)
}

// ConsumedArtifactMutated is the exact quarantine token Sol10 P0-1 requires:
// any consumed-artifact hash mismatch, at any of the four verification
// points (before backend launch, after backend extinction, before
// validation, after all validation), must report exactly this string --
// never a differently-worded message that happens to describe the same
// condition, so operators and the redteam corpus can grep for one fixed
// token.
const ConsumedArtifactMutated = "CONSUMED_ARTIFACT_MUTATED"

// consumedArtifactStoreDir is the private, controller-owned directory
// consumed artifacts are staged beneath for run runID (Sol10 P0-1): never
// inside the worktree. A same-UID backend process can always chmod its way
// past mode bits on a file inside its OWN writable workspace -- that is
// ordinary, privilege-free Unix file-ownership semantics, not a namespace
// escape, so 0400 inside <work> was never a real boundary regardless of
// --map-root-user.
//
// Sol11 P0-7: the read-only bind mount onto the workspace never made THIS
// directory itself immutable -- it only made the backend's *view* of it
// read-only, while the underlying directory entries remained ordinary,
// same-UID-writable files any other process running as Governator's own
// user could locate by this exact path and overwrite, then restore. runOnce
// no longer routes the local backend's own launch, or any validator launch
// (stage.Executor, regardless of runner kind), through this directory at
// all: they read consumed artifacts exclusively via sealConsumedArtifacts's
// sealed, kernel-write-sealed memfds, projected straight into a private
// tmpfs at launch time (enforce.Plan.WithConsumedArtifacts) with no host
// directory entry ever created for the landlock boundary.
//
// This directory is retained ONLY for the Docker-backend sub-case
// (Workspace.ConsumedDir's docker :ro mount): the Docker daemon is a wholly
// separate process, never a descendant of any private mount namespace
// Governator establishes, so it needs a real host path it can resolve a
// bind-mount source from -- and Governator has no privilege (no
// CAP_SYS_ADMIN in the host mount namespace, no CAP_LINUX_IMMUTABLE) to make
// that path itself immutable the way the memfd projection does for
// everything else. This remains an honestly-labelled, open residual: fully
// closing it needs either a root-owned dedicated-service-UID store or
// fs-verity enabled out of band, neither available at Governator's own
// runtime privilege level. Docker-backend runs still get the existing
// hash-reverification detection layer (verifyConsumedArtifacts) as their
// only boundary against this specific gap.
func consumedArtifactStoreDir(home, runID string) string {
	return filepath.Join(home, "consumed", runID)
}

// stageConsumedArtifacts writes every sealed artifact into dir (either
// consumedArtifactStoreDir's external private store, or -- only when local
// host containment is not active for this run, see runOnce -- the legacy
// <work>/.governator/consumed location) with mode 0400. Mode 0400 remains a
// courtesy against accidental same-process overwrite, never the actual
// immutability boundary; see consumedArtifactStoreDir's doc comment.
func stageConsumedArtifacts(dir string, artifacts []stagedArtifact) ([]stagedArtifact, error) {
	if len(artifacts) == 0 {
		return nil, nil
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("stage consumed artifacts: %w", err)
	}
	for _, artifact := range artifacts {
		sum := sha256.Sum256(artifact.data)
		if hex.EncodeToString(sum[:]) != artifact.SHA256 || int64(len(artifact.data)) != artifact.Bytes {
			return nil, fmt.Errorf("sealed consumed artifact %q identity mismatch", artifact.Name)
		}
		if err := writeNewBeneath(dir, artifact.Name, artifact.data, 0400); err != nil {
			return nil, fmt.Errorf("stage sealed consumed artifact %q: %w", artifact.Name, err)
		}
	}
	return append([]stagedArtifact(nil), artifacts...), nil
}

// verifyConsumedArtifacts re-reads every staged artifact beneath dir and
// hash-verifies it against the sealed identity captured before staging (Sol10
// P0-1's four verification points: before backend launch, after backend
// extinction, before validation, after all validation). Every lookup goes
// through readRegularBeneath (openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|
// RESOLVE_NO_MAGICLINKS), so a same-name symlink or hard-link swap fails the
// read itself rather than silently resolving to different bytes. Any
// mismatch -- unreadable, wrong size, wrong content -- is reported as exactly
// ConsumedArtifactMutated; callers never re-copy or skip past a mismatch.
func verifyConsumedArtifacts(dir string, artifacts []stagedArtifact) error {
	for _, artifact := range artifacts {
		data, info, err := readRegularBeneath(dir, artifact.Name)
		if err != nil {
			return fmt.Errorf("%s: consumed artifact %q unreadable beneath its sealed store: %w", ConsumedArtifactMutated, artifact.Name, err)
		}
		if info.Size() != artifact.Bytes {
			return fmt.Errorf("%s: consumed artifact %q size changed: staged=%d now=%d", ConsumedArtifactMutated, artifact.Name, artifact.Bytes, info.Size())
		}
		sum := sha256.Sum256(data)
		if actual := hex.EncodeToString(sum[:]); actual != artifact.SHA256 {
			return fmt.Errorf("%s: consumed artifact %q content changed", ConsumedArtifactMutated, artifact.Name)
		}
	}
	return nil
}

// consumedArtifactSeals matches assay.packageSeals exactly (Sol11 P0-6's
// precedent): once applied, the kernel refuses every write/truncate/
// mmap-write against the memfd, for every process holding any descriptor to
// it -- including this one -- never merely a permission bit a same-UID
// chmod could undo.
const consumedArtifactSeals = unix.F_SEAL_WRITE | unix.F_SEAL_SHRINK | unix.F_SEAL_GROW | unix.F_SEAL_SEAL

// sealedConsumedArtifact is one consumed artifact's content, held only as a
// sealed, unlinked memfd (Sol11 P0-7): unlike stageConsumedArtifacts, no
// real host directory entry is ever created for it, so no same-UID process
// -- inside or outside Governator's own private mount namespaces -- has any
// filesystem path through which to locate and mutate it. The controller
// retains file for the run's whole lifetime and threads it through
// enforce.Plan.WithConsumedArtifacts/stage.StageAuthority.ConsumedArtifacts
// for every launch (the local backend's own, and every validator's,
// regardless of runner kind) that must read it.
type sealedConsumedArtifact struct {
	Name   string
	SHA256 string
	Bytes  int64
	file   *os.File
}

// sealConsumedArtifacts seals every artifact's already-verified data (see
// consumedArtifactIdentities) into its own sealed, unlinked memfd. Returns
// nil, nil for no artifacts. On any error, every memfd created so far is
// closed before returning.
func sealConsumedArtifacts(artifacts []stagedArtifact) ([]sealedConsumedArtifact, error) {
	if len(artifacts) == 0 {
		return nil, nil
	}
	out := make([]sealedConsumedArtifact, 0, len(artifacts))
	ok := false
	defer func() {
		if !ok {
			closeSealedConsumedArtifacts(out)
		}
	}()
	for _, artifact := range artifacts {
		sum := sha256.Sum256(artifact.data)
		if hex.EncodeToString(sum[:]) != artifact.SHA256 || int64(len(artifact.data)) != artifact.Bytes {
			return nil, fmt.Errorf("sealed consumed artifact %q identity mismatch", artifact.Name)
		}
		fd, merr := unix.MemfdCreate("governator-consumed-"+artifact.Name, unix.MFD_CLOEXEC|unix.MFD_ALLOW_SEALING)
		if merr != nil {
			return nil, fmt.Errorf("create sealed consumed-artifact memfd %q: %w", artifact.Name, merr)
		}
		f := os.NewFile(uintptr(fd), "governator-consumed-"+artifact.Name)
		if _, werr := f.Write(artifact.data); werr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("write sealed consumed-artifact memfd %q: %w", artifact.Name, werr)
		}
		// Seal immediately after writing, before this artifact is handed to
		// any launch: from this point on the kernel refuses every mutation
		// against this memfd, for every process holding any descriptor to it
		// (Sol11 P0-7).
		if _, serr := unix.FcntlInt(f.Fd(), unix.F_ADD_SEALS, consumedArtifactSeals); serr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("seal consumed-artifact memfd %q: %w", artifact.Name, serr)
		}
		if _, serr := f.Seek(0, io.SeekStart); serr != nil {
			_ = f.Close()
			return nil, fmt.Errorf("rewind sealed consumed-artifact memfd %q: %w", artifact.Name, serr)
		}
		out = append(out, sealedConsumedArtifact{Name: artifact.Name, SHA256: artifact.SHA256, Bytes: artifact.Bytes, file: f})
	}
	ok = true
	return out, nil
}

// closeSealedConsumedArtifacts releases every retained memfd. Safe to call
// with a nil/empty slice.
func closeSealedConsumedArtifacts(sealed []sealedConsumedArtifact) {
	for _, a := range sealed {
		if a.file != nil {
			_ = a.file.Close()
		}
	}
}

// verifySealedConsumedArtifacts re-hashes every sealed artifact directly
// from its retained descriptor. F_SEAL_WRITE makes a real mismatch a
// structural impossibility rather than a race Governator might lose, but
// this stays in place as the same defense-in-depth re-check every other
// verification checkpoint performs -- a logic bug that skipped sealing, not
// a same-UID tamper, is what this would actually catch.
func verifySealedConsumedArtifacts(sealed []sealedConsumedArtifact) error {
	for _, a := range sealed {
		if _, err := a.file.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("%s: consumed artifact %q unreadable from its sealed memfd: %w", ConsumedArtifactMutated, a.Name, err)
		}
		sum := sha256.New()
		n, err := io.Copy(sum, a.file)
		if err != nil {
			return fmt.Errorf("%s: consumed artifact %q unreadable from its sealed memfd: %w", ConsumedArtifactMutated, a.Name, err)
		}
		if n != a.Bytes {
			return fmt.Errorf("%s: consumed artifact %q size changed: staged=%d now=%d", ConsumedArtifactMutated, a.Name, a.Bytes, n)
		}
		if actual := hex.EncodeToString(sum.Sum(nil)); actual != a.SHA256 {
			return fmt.Errorf("%s: consumed artifact %q content changed", ConsumedArtifactMutated, a.Name)
		}
	}
	return nil
}

// verifyConsumedArtifactsAll re-verifies every consumed-artifact identity
// this run staged, across every mechanism actually in play for this run's
// consumedBoundary (Sol11 P0-7): the plain host directory (Docker's own
// container mount, or the legacy in-workspace mode-bits-degraded path) when
// plainStaged is true, and the sealed memfd content whenever any was
// sealed. Called at all four Sol10 P0-1 checkpoints.
func verifyConsumedArtifactsAll(stageDir string, plainStaged bool, sealed []sealedConsumedArtifact, artifacts []stagedArtifact) error {
	if plainStaged {
		if err := verifyConsumedArtifacts(stageDir, artifacts); err != nil {
			return err
		}
	}
	return verifySealedConsumedArtifacts(sealed)
}

// consumedArtifactFDs converts sealed artifacts into the form
// enforce.Plan.WithConsumedArtifacts/stage.StageAuthority.ConsumedArtifacts
// take.
func consumedArtifactFDs(sealed []sealedConsumedArtifact) []enforce.ConsumedArtifactFD {
	if len(sealed) == 0 {
		return nil
	}
	out := make([]enforce.ConsumedArtifactFD, len(sealed))
	for i, a := range sealed {
		out[i] = enforce.ConsumedArtifactFD{Name: a.Name, File: a.file}
	}
	return out
}

func artifactPromptAnnotation(staged []stagedArtifact, produced []contracts.ArtifactSpec) string {
	if len(staged) == 0 && len(produced) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("\nGovernator typed handoff artifacts:\n")
	if len(staged) > 0 {
		b.WriteString("Consumed artifacts are staged read-only at these paths:\n")
		for _, artifact := range staged {
			fmt.Fprintf(&b, "- %s: %s (sha256=%s bytes=%d)\n", artifact.Name, artifact.Path, artifact.SHA256, artifact.Bytes)
		}
	}
	if len(produced) > 0 {
		b.WriteString("Produced artifacts must be written exactly under .governator/artifacts/ and are not source changes:\n")
		for _, artifact := range produced {
			line := fmt.Sprintf("- %s: %s max_bytes=%d", artifact.Name, artifact.Path, artifact.MaxBytes)
			if artifact.Schema != "" {
				line += " schema=" + artifact.Schema
			}
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func collectProducedArtifacts(home, work, runID string, specs []contracts.ArtifactSpec) ([]observability.ArtifactRecord, []string) {
	if len(specs) == 0 {
		return nil, nil
	}
	var records []observability.ArtifactRecord
	var violations []string
	artifactsRoot := filepath.Join(home, "artifacts")
	for _, spec := range specs {
		rel, err := safeWorkspaceRel(spec.Path)
		if err != nil {
			violations = append(violations, "artifact path invalid: "+spec.Name+": "+err.Error())
			continue
		}
		data, info, err := readRegularBeneath(work, rel)
		if err != nil {
			if os.IsNotExist(err) {
				violations = append(violations, "artifact missing: "+spec.Name+" at "+rel)
			} else {
				violations = append(violations, "artifact beneath-root read: "+spec.Name+": "+err.Error())
			}
			continue
		}
		if info.Size() > spec.MaxBytes {
			violations = append(violations, fmt.Sprintf("artifact oversized: %s %d > %d", spec.Name, info.Size(), spec.MaxBytes))
			continue
		}
		sum := sha256.Sum256(data)
		sha := hex.EncodeToString(sum[:])
		schemaOK := true
		if spec.Schema != "" {
			schemaRel, err := safeWorkspaceRel(spec.Schema)
			if err != nil {
				schemaOK = false
				violations = append(violations, "artifact schema invalid: "+spec.Name+": "+err.Error())
			} else if schemaData, _, err := readRegularBeneath(work, schemaRel); err != nil {
				schemaOK = false
				violations = append(violations, "artifact schema invalid: "+spec.Name+": beneath-root read: "+err.Error())
			} else if err := validateJSONSchemaData(schemaData, data); err != nil {
				schemaOK = false
				violations = append(violations, "artifact schema invalid: "+spec.Name+": "+err.Error())
			}
		}
		dstRel := filepath.Join(runID, filepath.FromSlash(rel))
		dst := filepath.Join(artifactsRoot, dstRel)
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			violations = append(violations, "artifact store mkdir: "+spec.Name+": "+err.Error())
			continue
		}
		if err := writeOverwriteBeneath(artifactsRoot, dstRel, data, 0600); err != nil {
			violations = append(violations, "artifact store beneath-root write: "+spec.Name+": "+err.Error())
			continue
		}
		records = append(records, observability.ArtifactRecord{
			RunID: runID, Name: spec.Name, Path: dst, SHA256: sha, Bytes: info.Size(), SchemaOK: schemaOK,
			DeclaredPath: rel, Language: spec.Language, MediaType: spec.MediaType,
		})
	}
	sort.Slice(records, func(i, j int) bool { return records[i].Name < records[j].Name })
	return records, violations
}

func filterSourceChanges(changed, deleted []string) ([]string, []string) {
	return filterSourcePaths(changed), filterSourcePaths(deleted)
}

func filterSourcePaths(paths []string) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		if isGovernatorInternalPath(p) {
			continue
		}
		out = append(out, p)
	}
	return out
}

func isGovernatorInternalPath(p string) bool {
	cleaned := cleanSlash(p)
	return cleaned == ".governator" || strings.HasPrefix(cleaned, ".governator/")
}

func cleanSlash(p string) string {
	return path.Clean(strings.ReplaceAll(p, `\`, "/"))
}

func safeWorkspaceRel(raw string) (string, error) {
	cleaned := cleanSlash(raw)
	if cleaned == "." || cleaned == ".." || strings.HasPrefix(cleaned, "../") || path.IsAbs(cleaned) {
		return "", fmt.Errorf("path escapes workspace: %s", raw)
	}
	return cleaned, nil
}

// readRegularBeneath, writeNewBeneath and writeOverwriteBeneath (below) are
// Sol P1-7's replacement for this file's old *NoFollow helpers, which opened
// an already-joined absolute path with a bare O_NOFOLLOW -- protecting only
// the final path component against a symlink swap, never a parent directory
// component (report §9 attack 22). Each now resolves relPath beneath baseDir
// via openBeneath (openat2 RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|
// RESOLVE_NO_MAGICLINKS, openbeneath.go), which makes the kernel validate
// every component of the path as one atomic operation -- there is no
// separate "check" step for a race to land between.

func readRegularBeneath(baseDir, relPath string) ([]byte, os.FileInfo, error) {
	f, err := pathsafe.OpenBeneath(baseDir, relPath, os.O_RDONLY, 0)
	if err != nil {
		return nil, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("non-regular artifact refused: %s beneath %s", relPath, baseDir)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	return data, info, nil
}

func writeNewBeneath(baseDir, relPath string, data []byte, perm os.FileMode) error {
	f, err := pathsafe.OpenBeneath(baseDir, relPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Chmod(perm)
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func writeOverwriteBeneath(baseDir, relPath string, data []byte, perm os.FileMode) error {
	flags := os.O_WRONLY | os.O_CREATE | os.O_EXCL
	openMode := perm
	abs := filepath.Join(baseDir, filepath.FromSlash(relPath))
	if info, err := os.Lstat(abs); err == nil {
		// Advisory only: openBeneath's RESOLVE_NO_SYMLINKS re-resolves every
		// component fresh inside the actual open call below regardless of
		// what this Lstat sees, so a swap landing between this check and
		// that call is refused there, not here. This Lstat exists only to
		// pick O_TRUNC vs O_EXCL -- picking the wrong one just produces an
		// ordinary "file exists"/"no such file" error, never an unsafe open.
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("existing destination is not a regular file: %s", abs)
		}
		flags = os.O_WRONLY | os.O_TRUNC
		// No O_CREATE on this branch, so openBeneath's mode argument must be
		// 0 (openat2 rejects a nonzero mode without O_CREATE/O_TMPFILE with
		// EINVAL, unlike legacy open()). f.Chmod(perm) below still forces the
		// exact permission bits after open, via the fd, so this loses nothing.
		openMode = 0
	} else if !os.IsNotExist(err) {
		return err
	}
	f, err := pathsafe.OpenBeneath(baseDir, relPath, flags, openMode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Chmod(perm)
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func validateJSONSchemaData(schemaData, data []byte) error {
	var schema any
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		return fmt.Errorf("parse schema: %w", err)
	}
	var value any
	if err := json.Unmarshal(data, &value); err != nil {
		return fmt.Errorf("parse artifact JSON: %w", err)
	}
	return validateSchemaValue(schema, value, "$")
}

func validateSchemaValue(schema, value any, at string) error {
	m, ok := schema.(map[string]any)
	if !ok {
		return nil
	}
	if enum, ok := m["enum"].([]any); ok {
		matched := false
		for _, item := range enum {
			if reflect.DeepEqual(item, value) {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("%s is not one of the allowed enum values", at)
		}
	}
	if typ, ok := m["type"]; ok && !schemaTypeMatches(typ, value) {
		return fmt.Errorf("%s has wrong type", at)
	}
	props, _ := m["properties"].(map[string]any)
	if required, ok := m["required"].([]any); ok {
		obj, _ := value.(map[string]any)
		for _, raw := range required {
			name, _ := raw.(string)
			if name == "" {
				continue
			}
			if obj == nil {
				return fmt.Errorf("%s is not an object with required property %q", at, name)
			}
			if _, exists := obj[name]; !exists {
				return fmt.Errorf("%s missing required property %q", at, name)
			}
		}
	}
	if len(props) > 0 {
		obj, ok := value.(map[string]any)
		if !ok {
			return nil
		}
		keys := make([]string, 0, len(props))
		for k := range props {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if child, exists := obj[k]; exists {
				if err := validateSchemaValue(props[k], child, at+"."+k); err != nil {
					return err
				}
			}
		}
		if additional, ok := m["additionalProperties"].(bool); ok && !additional {
			for k := range obj {
				if _, allowed := props[k]; !allowed {
					return fmt.Errorf("%s has additional property %q", at, k)
				}
			}
		}
	}
	if items, ok := m["items"]; ok {
		arr, ok := value.([]any)
		if !ok {
			return nil
		}
		for i, item := range arr {
			if err := validateSchemaValue(items, item, fmt.Sprintf("%s[%d]", at, i)); err != nil {
				return err
			}
		}
	}
	return nil
}

func schemaTypeMatches(schemaType, value any) bool {
	switch typed := schemaType.(type) {
	case string:
		return oneSchemaTypeMatches(typed, value)
	case []any:
		for _, raw := range typed {
			if name, ok := raw.(string); ok && oneSchemaTypeMatches(name, value) {
				return true
			}
		}
	}
	return true
}

func oneSchemaTypeMatches(name string, value any) bool {
	switch name {
	case "object":
		_, ok := value.(map[string]any)
		return ok
	case "array":
		_, ok := value.([]any)
		return ok
	case "string":
		_, ok := value.(string)
		return ok
	case "number":
		_, ok := value.(float64)
		return ok
	case "integer":
		f, ok := value.(float64)
		return ok && math.Trunc(f) == f
	case "boolean":
		_, ok := value.(bool)
		return ok
	case "null":
		return value == nil
	default:
		return true
	}
}
