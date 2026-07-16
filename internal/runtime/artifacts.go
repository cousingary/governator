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

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
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

func stageConsumedArtifacts(work string, artifacts []stagedArtifact) ([]stagedArtifact, error) {
	if len(artifacts) == 0 {
		return nil, nil
	}
	dir := filepath.Join(work, ".governator", "consumed")
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
	f, err := openBeneath(baseDir, relPath, os.O_RDONLY, 0)
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
	f, err := openBeneath(baseDir, relPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, perm)
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
	f, err := openBeneath(baseDir, relPath, flags, openMode)
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
