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
	"syscall"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/observability"
)

type stagedArtifact struct {
	Name   string
	Path   string
	SHA256 string
	Bytes  int64
}

func stageConsumedArtifacts(db *sql.DB, work string, c contracts.Contract) ([]stagedArtifact, error) {
	if len(c.Consumes) == 0 {
		return nil, nil
	}
	if len(c.ArtifactSources) == 0 {
		return nil, fmt.Errorf("consumes declared but no artifact sources were resolved by plan validation")
	}
	dir := filepath.Join(work, ".governator", "consumed")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("stage consumed artifacts: %w", err)
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
		data, info, err := readRegularNoFollowAbsolute(src)
		if err != nil {
			return nil, fmt.Errorf("stage consumed artifact %q no-follow read: %w", name, err)
		}
		if size >= 0 && info.Size() != size {
			return nil, fmt.Errorf("stage consumed artifact %q size mismatch: ledger=%d actual=%d", name, size, info.Size())
		}
		actualSum := sha256.Sum256(data)
		actualSHA := hex.EncodeToString(actualSum[:])
		if sha != "" && actualSHA != sha {
			return nil, fmt.Errorf("stage consumed artifact %q sha256 mismatch", name)
		}
		dst := filepath.Join(dir, name)
		if err := writeNewNoFollow(dst, data, 0400); err != nil {
			return nil, fmt.Errorf("stage consumed artifact %q no-follow write: %w", name, err)
		}
		out = append(out, stagedArtifact{Name: name, Path: filepath.ToSlash(filepath.Join(".governator", "consumed", name)), SHA256: actualSHA, Bytes: info.Size()})
	}
	return out, nil
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
	for _, spec := range specs {
		rel, err := safeWorkspaceRel(spec.Path)
		if err != nil {
			violations = append(violations, "artifact path invalid: "+spec.Name+": "+err.Error())
			continue
		}
		data, info, err := readWorkspaceFileNoFollow(work, rel)
		if err != nil {
			if os.IsNotExist(err) {
				violations = append(violations, "artifact missing: "+spec.Name+" at "+rel)
			} else {
				violations = append(violations, "artifact no-follow read: "+spec.Name+": "+err.Error())
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
			} else if schemaData, _, err := readWorkspaceFileNoFollow(work, schemaRel); err != nil {
				schemaOK = false
				violations = append(violations, "artifact schema invalid: "+spec.Name+": no-follow read: "+err.Error())
			} else if err := validateJSONSchemaData(schemaData, data); err != nil {
				schemaOK = false
				violations = append(violations, "artifact schema invalid: "+spec.Name+": "+err.Error())
			}
		}
		dst := filepath.Join(home, "artifacts", runID, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			violations = append(violations, "artifact store mkdir: "+spec.Name+": "+err.Error())
			continue
		}
		if err := writeFileNoFollowOverwrite(dst, data, 0600); err != nil {
			violations = append(violations, "artifact store no-follow write: "+spec.Name+": "+err.Error())
			continue
		}
		records = append(records, observability.ArtifactRecord{RunID: runID, Name: spec.Name, Path: dst, SHA256: sha, Bytes: info.Size(), SchemaOK: schemaOK})
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

func readWorkspaceFileNoFollow(work, rel string) ([]byte, os.FileInfo, error) {
	cleanRel, err := safeWorkspaceRel(rel)
	if err != nil {
		return nil, nil, err
	}
	abs := filepath.Join(work, filepath.FromSlash(cleanRel))
	workAbs, err := filepath.Abs(work)
	if err != nil {
		return nil, nil, err
	}
	abs, err = filepath.Abs(abs)
	if err != nil {
		return nil, nil, err
	}
	relToWork, err := filepath.Rel(workAbs, abs)
	if err != nil {
		return nil, nil, err
	}
	if relToWork == ".." || strings.HasPrefix(relToWork, ".."+string(os.PathSeparator)) {
		return nil, nil, fmt.Errorf("path escapes workspace: %s", rel)
	}
	return readRegularNoFollowAbsolute(abs)
}

func readRegularNoFollowAbsolute(abs string) ([]byte, os.FileInfo, error) {
	info, err := os.Lstat(abs)
	if err != nil {
		return nil, nil, err
	}
	mode := info.Mode()
	if mode&os.ModeSymlink != 0 {
		return nil, nil, fmt.Errorf("symlink refused: %s", abs)
	}
	if !mode.IsRegular() {
		return nil, nil, fmt.Errorf("non-regular artifact refused: %s", abs)
	}
	fd, err := syscall.Open(abs, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, nil, err
	}
	f := os.NewFile(uintptr(fd), abs)
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, nil, err
	}
	if !openedInfo.Mode().IsRegular() {
		return nil, nil, fmt.Errorf("non-regular artifact refused after open: %s", abs)
	}
	if !sameFileIdentity(info, openedInfo) {
		return nil, nil, fmt.Errorf("artifact changed during no-follow open: %s", abs)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		return nil, nil, err
	}
	return data, openedInfo, nil
}

func writeNewNoFollow(abs string, data []byte, perm os.FileMode) error {
	fd, err := syscall.Open(abs, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW, uint32(perm))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), abs)
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(abs, perm)
}

func writeFileNoFollowOverwrite(abs string, data []byte, perm os.FileMode) error {
	flags := syscall.O_WRONLY | syscall.O_CREAT | syscall.O_EXCL | syscall.O_NOFOLLOW
	if info, err := os.Lstat(abs); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("existing destination is not a regular file: %s", abs)
		}
		flags = syscall.O_WRONLY | syscall.O_TRUNC | syscall.O_NOFOLLOW
	} else if !os.IsNotExist(err) {
		return err
	}
	fd, err := syscall.Open(abs, flags, uint32(perm))
	if err != nil {
		return err
	}
	f := os.NewFile(uintptr(fd), abs)
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Chmod(abs, perm)
}

func sameFileIdentity(a, b os.FileInfo) bool {
	as, okA := a.Sys().(*syscall.Stat_t)
	bs, okB := b.Sys().(*syscall.Stat_t)
	if !okA || !okB {
		return true
	}
	return as.Dev == bs.Dev && as.Ino == bs.Ino
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
