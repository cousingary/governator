package runtime

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
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
		dst := filepath.Join(dir, name)
		if err := copyFile(src, dst); err != nil {
			return nil, fmt.Errorf("stage consumed artifact %q: %w", name, err)
		}
		if err := os.Chmod(dst, 0400); err != nil {
			return nil, fmt.Errorf("make consumed artifact read-only: %w", err)
		}
		out = append(out, stagedArtifact{Name: name, Path: filepath.ToSlash(filepath.Join(".governator", "consumed", name)), SHA256: sha, Bytes: size})
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
		rel := cleanSlash(spec.Path)
		src := filepath.Join(work, filepath.FromSlash(rel))
		info, err := os.Stat(src)
		if err != nil {
			if os.IsNotExist(err) {
				violations = append(violations, "artifact missing: "+spec.Name+" at "+rel)
			} else {
				violations = append(violations, "artifact stat: "+spec.Name+": "+err.Error())
			}
			continue
		}
		if info.IsDir() {
			violations = append(violations, "artifact is directory: "+spec.Name+" at "+rel)
			continue
		}
		if info.Size() > spec.MaxBytes {
			violations = append(violations, fmt.Sprintf("artifact oversized: %s %d > %d", spec.Name, info.Size(), spec.MaxBytes))
			continue
		}
		data, err := os.ReadFile(src)
		if err != nil {
			violations = append(violations, "artifact read: "+spec.Name+": "+err.Error())
			continue
		}
		sum := sha256.Sum256(data)
		sha := hex.EncodeToString(sum[:])
		schemaOK := true
		if spec.Schema != "" {
			if err := validateJSONSchemaFile(filepath.Join(work, filepath.FromSlash(cleanSlash(spec.Schema))), data); err != nil {
				schemaOK = false
				violations = append(violations, "artifact schema invalid: "+spec.Name+": "+err.Error())
			}
		}
		dst := filepath.Join(home, "artifacts", runID, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(dst), 0700); err != nil {
			violations = append(violations, "artifact store mkdir: "+spec.Name+": "+err.Error())
			continue
		}
		if err := copyFile(src, dst); err != nil {
			violations = append(violations, "artifact store copy: "+spec.Name+": "+err.Error())
			continue
		}
		_ = os.Chmod(dst, 0600)
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

func validateJSONSchemaFile(schemaPath string, data []byte) error {
	schemaData, err := os.ReadFile(schemaPath)
	if err != nil {
		return fmt.Errorf("read schema: %w", err)
	}
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
