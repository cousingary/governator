package contracts

import (
	"fmt"
)

func validatePanelSpec(spec PanelSpec, jobs []Contract) error {
	var errs ValidationErrors
	add := func(field, msg string) { errs = append(errs, ValidationError{Field: field, Message: msg}) }
	if spec.ID == "" {
		add("panel.id", "is required")
	} else if !jobIDPattern.MatchString(spec.ID) {
		add("panel.id", "must look like a job_id (alphanumeric, '.', '_', '-')")
	}
	if len(spec.Members) < 2 {
		add("panel.members", "must contain at least two member jobs")
	}
	if spec.ComparisonJob == "" {
		add("panel.comparison_job", "is required")
	}
	if spec.Judge == "" {
		add("panel.judge", "is required")
	}
	validatePanelQuorum(spec, add)

	byID := make(map[string]Contract, len(jobs))
	for _, job := range jobs {
		byID[job.JobID] = job
	}
	memberSet := map[string]bool{}
	memberArtifacts := map[string]string{}
	for i, id := range spec.Members {
		field := fmt.Sprintf("panel.members[%d]", i)
		if memberSet[id] {
			add(field, "duplicates another panel member")
			continue
		}
		memberSet[id] = true
		job, ok := byID[id]
		if !ok {
			add(field, "does not name a job in the plan")
			continue
		}
		if job.Mode != ModeScout && job.Mode != ModeArchitect && job.Mode != ModeVerifier {
			add(field+".mode", "panel members must use read-only modes only (scout, architect, verifier)")
		}
		if job.Workspace.Worktree != "auto" {
			add(field+".workspace.worktree", "panel members must use isolated auto worktrees; shared worktrees are forbidden")
		}
		if len(job.Produces) == 0 {
			add(field+".produces", "panel members must produce at least one schema'd artifact")
		}
		for j, artifact := range job.Produces {
			if artifact.Schema == "" {
				add(fmt.Sprintf("%s.produces[%d].schema", field, j), "panel member artifacts must declare a schema")
			}
			if artifact.Name != "" {
				if other, exists := memberArtifacts[artifact.Name]; exists {
					add(fmt.Sprintf("%s.produces[%d].name", field, j), "duplicates panel artifact produced by "+other)
				} else {
					memberArtifacts[artifact.Name] = id
				}
			}
		}
	}

	comparison, comparisonOK := byID[spec.ComparisonJob]
	var comparisonArtifacts []string
	if !comparisonOK {
		if spec.ComparisonJob != "" {
			add("panel.comparison_job", "does not name a job in the plan")
		}
	} else {
		if comparison.Mode != ModeVerifier {
			add("panel.comparison_job.mode", "must be verifier so the deterministic comparison artifact cannot edit source")
		}
		if comparison.Workspace.Worktree != "auto" {
			add("panel.comparison_job.workspace.worktree", "must use an isolated auto worktree")
		}
		for _, id := range spec.Members {
			if !containsString(comparison.DependsOn, id) {
				add("panel.comparison_job.depends_on", "must depend on every panel member")
			}
		}
		for name := range memberArtifacts {
			if !containsString(comparison.Consumes, name) {
				add("panel.comparison_job.consumes", "must consume member artifact "+name)
			}
		}
		if len(comparison.Produces) == 0 {
			add("panel.comparison_job.produces", "must produce the deterministic comparison artifact")
		}
		for i, artifact := range comparison.Produces {
			if artifact.Schema == "" {
				add(fmt.Sprintf("panel.comparison_job.produces[%d].schema", i), "comparison artifact must declare a schema")
			}
			if artifact.Name != "" {
				comparisonArtifacts = append(comparisonArtifacts, artifact.Name)
			}
		}
	}

	judge, judgeOK := byID[spec.Judge]
	if !judgeOK {
		if spec.Judge != "" {
			add("panel.judge", "does not name a job in the plan")
		}
	} else {
		if memberSet[spec.Judge] || spec.Judge == spec.ComparisonJob {
			add("panel.judge", "must be separate from panel members and the comparison job")
		}
		if judge.Mode != ModeArchitect {
			add("panel.judge.mode", "must be architect; panel verdicts are advisory and cannot auto-merge")
		}
		if judge.Workspace.Worktree != "auto" {
			add("panel.judge.workspace.worktree", "must use an isolated auto worktree")
		}
		for _, id := range spec.Members {
			if !containsString(judge.DependsOn, id) {
				add("panel.judge.depends_on", "must depend on every panel member")
			}
		}
		if comparisonOK && !containsString(judge.DependsOn, spec.ComparisonJob) {
			add("panel.judge.depends_on", "must depend on the deterministic comparison job")
		}
		for name := range memberArtifacts {
			if containsString(judge.Consumes, name) {
				add("panel.judge.consumes", "must not consume raw member artifact "+name+"; use the anonymized comparison artifact")
			}
		}
		for _, name := range comparisonArtifacts {
			if !containsString(judge.Consumes, name) {
				add("panel.judge.consumes", "must consume comparison artifact "+name)
			}
		}
		for i, artifact := range judge.Produces {
			if artifact.Schema == "" {
				add(fmt.Sprintf("panel.judge.produces[%d].schema", i), "judge artifacts must declare a schema")
			}
		}
	}

	if len(errs) > 0 {
		return errs.Sorted()
	}
	return nil
}

// validatePanelQuorum checks the optional min_success/timeouts/diversity
// block against the member count. len(spec.Members) may itself already be
// invalid (< 2, checked above by the caller) — every bound here compares
// against the raw count regardless, so a malformed panel reports every
// problem at once instead of hiding these behind the members error.
func validatePanelQuorum(spec PanelSpec, add func(string, string)) {
	n := len(spec.Members)
	if spec.MinSuccess != 0 {
		if spec.MinSuccess < 2 {
			add("panel.min_success", "must be at least 2 when set (the comparison job needs at least two artifacts)")
		} else if spec.MinSuccess > n {
			add("panel.min_success", fmt.Sprintf("must not exceed panel.members count (%d)", n))
		}
	}
	if spec.MemberTimeoutSeconds < 0 {
		add("panel.member_timeout_seconds", "must be zero or greater")
	}
	if spec.HardTimeoutSeconds < 0 {
		add("panel.hard_timeout_seconds", "must be zero or greater")
	}
	if spec.MemberTimeoutSeconds > 0 && spec.HardTimeoutSeconds > 0 && spec.HardTimeoutSeconds < spec.MemberTimeoutSeconds {
		add("panel.hard_timeout_seconds", "must be greater than or equal to panel.member_timeout_seconds when both are set")
	}
	if spec.Diversity == nil {
		return
	}
	d := spec.Diversity
	if d.GroupBy != "" && !panelDiversityKeys[d.GroupBy] {
		add("panel.diversity.group_by", "must be 'backend' or 'model_family' when set")
	}
	if d.FallbackGroupBy != "" {
		if !panelDiversityKeys[d.FallbackGroupBy] {
			add("panel.diversity.fallback_group_by", "must be 'backend' or 'model_family' when set")
		} else if d.FallbackGroupBy == d.GroupBy {
			add("panel.diversity.fallback_group_by", "must differ from panel.diversity.group_by")
		}
	}
	if d.MinUnique < 0 {
		add("panel.diversity.min_unique", "must be zero or greater")
	} else if d.MinUnique > n {
		add("panel.diversity.min_unique", fmt.Sprintf("must not exceed panel.members count (%d)", n))
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
