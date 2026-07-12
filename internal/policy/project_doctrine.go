package policy

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ProjectDoctrineFilename is the fixed filename LoadProjectDoctrine looks for
// at a job's workspace root: a per-project declarative policy_rules file an
// operator commits alongside the project (the "project doctrine" layer,
// distinct from the org-wide config.yaml policy_rules and from a job
// contract's own rules). Missing is not an error — an unconfigured project
// contributes no rules, the same additive-by-default posture as every other
// Session feature in this codebase (Assay.Repo, Containment.OverridePublicKey, ...).
const ProjectDoctrineFilename = ".governator-doctrine.yaml"

// projectDoctrineFile is the on-disk shape of a project doctrine file: just
// a policy_rules list, so it reads identically to the org config's own
// policy_rules block.
type projectDoctrineFile struct {
	PolicyRules []ConditionRule `yaml:"policy_rules"`
}

// LoadProjectDoctrine reads workspaceRoot/.governator-doctrine.yaml. A
// missing file returns (nil, nil) — no project doctrine configured is not
// an error. A present-but-invalid file (bad YAML, or a rule that fails
// Validate) is always an error: this engine is fail-closed by design, so a
// project doctrine file the operator can't actually parse must stop the run
// rather than silently contribute nothing.
func LoadProjectDoctrine(workspaceRoot string) ([]ConditionRule, error) {
	path := filepath.Join(workspaceRoot, ProjectDoctrineFilename)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read project doctrine %s: %w", path, err)
	}
	var file projectDoctrineFile
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return nil, fmt.Errorf("decode project doctrine %s: %w", path, err)
	}
	seen := map[string]bool{}
	for _, r := range file.PolicyRules {
		if seen[r.ID] {
			return nil, fmt.Errorf("project doctrine %s: duplicate rule id %q in project_doctrine namespace", path, r.ID)
		}
		seen[r.ID] = true
		if verr := r.Validate(); verr != nil {
			return nil, fmt.Errorf("project doctrine %s: %w", path, verr)
		}
	}
	return file.PolicyRules, nil
}
