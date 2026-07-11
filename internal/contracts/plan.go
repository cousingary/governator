package contracts

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Plan is the manifest a governed planner job (mode: planner) writes:
// an ordered list of governed sub-contracts, each carrying its own
// depends_on/risk_class. A Plan is never executed directly — ValidatePlan
// gates it, then the caller (`gov plan`) explodes each job into its own
// runnable contract file for `gov batch run`.
type Plan struct {
	Panel *PanelSpec `yaml:"panel,omitempty" json:"panel,omitempty"`
	Jobs  []Contract `yaml:"jobs" json:"jobs"`
}

// PanelSpec is plan-level metadata for a cognition-only panel template. It is
// not a runtime primitive: the jobs remain ordinary contracts, while this
// block lets ValidatePlanManifest enforce panel-specific prohibitions and lets
// generated plans map anonymized panelist labels back to job ids.
//
// MinSuccess, the timeouts, and Diversity are quorum/diversity policy read by
// internal/runtime.RunPanel, not by ValidatePlan itself — a plan without a
// panel block (or an older panel plan predating these fields) keeps running
// exactly as before via plain RunBatchOrdered, since every field here is
// optional and its Effective* accessor defaults to the pre-Phase-2 behavior
// (wait for every member, no diversity requirement).
type PanelSpec struct {
	ID            string   `yaml:"id" json:"id"`
	Members       []string `yaml:"members" json:"members"`
	ComparisonJob string   `yaml:"comparison_job" json:"comparison_job"`
	Judge         string   `yaml:"judge" json:"judge"`

	// MinSuccess is how many members must complete before the comparison job
	// is allowed to run. 0 (unset) defaults to every member — the original
	// behavior. Comparison always needs at least 2 usable artifacts
	// (panel.CompareArtifacts), so an explicit value below 2 fails validation.
	MinSuccess int `yaml:"min_success,omitempty" json:"min_success,omitempty"`

	// MemberTimeoutSeconds bounds a single member's run; RunPanel applies it
	// as that member job's budget.max_minutes (rounded up), reusing the
	// existing per-job wall-clock gate rather than adding a second one. 0
	// defaults to 120s.
	MemberTimeoutSeconds int `yaml:"member_timeout_seconds,omitempty" json:"member_timeout_seconds,omitempty"`

	// HardTimeoutSeconds bounds the whole member level: once it elapses,
	// RunPanel stops waiting on stragglers and proceeds with whatever
	// quorum (MinSuccess) it has, or reports panel failure if it never
	// reached 2 successes. 0 defaults to 180s. Must be >= the effective
	// MemberTimeoutSeconds when both are set explicitly.
	HardTimeoutSeconds int `yaml:"hard_timeout_seconds,omitempty" json:"hard_timeout_seconds,omitempty"`

	// Diversity is the backend-plurality requirement across members. A nil
	// value defaults to key: backend, min_unique: len(members) — the
	// strictest reading ("every member on a different backend"), reported
	// (never silently relaxed) as degraded when the live candidate pool
	// can't satisfy it.
	Diversity *PanelDiversity `yaml:"diversity,omitempty" json:"diversity,omitempty"`
}

// PanelDiversity configures the backend-plurality check RunPanel enforces
// across a panel's members via router exclusion sets (Request.ExcludeAgents).
//
// Field names deliberately avoid the substring "key" in their YAML/JSON
// tags (GroupBy, not Key): contracts.ParsePlan's literal-secret scan flags
// any `<word>KEY: <8+ char value>` pattern in a manifest, case-insensitive,
// to catch an accidentally-committed API key — "key: model_family" would
// false-positive on that heuristic every time. GroupBy sidesteps it while
// meaning the same thing.
type PanelDiversity struct {
	// GroupBy groups candidates for exclusion purposes: "backend" (default,
	// the literal agent name) or "model_family" (a coarser grouping — see
	// internal/runtime.diversityGroup — for when distinct CLI wrappers front
	// the same underlying model).
	GroupBy string `yaml:"group_by,omitempty" json:"group_by,omitempty"`
	// MinUnique is how many distinct groups the assignment must achieve. 0
	// defaults to len(members).
	MinUnique int `yaml:"min_unique,omitempty" json:"min_unique,omitempty"`
	// FallbackGroupBy, if set, is tried once GroupBy's exclusion leaves no
	// candidate for a member — a coarser regrouping before RunPanel gives up
	// and reuses a backend (recording degraded either way).
	FallbackGroupBy string `yaml:"fallback_group_by,omitempty" json:"fallback_group_by,omitempty"`
}

var panelDiversityKeys = map[string]bool{"backend": true, "model_family": true}

// EffectiveMinSuccess defaults to every member — RunPanel waits for all of
// them, matching pre-Phase-2 behavior — when unset.
func (s PanelSpec) EffectiveMinSuccess() int {
	if s.MinSuccess > 0 {
		return s.MinSuccess
	}
	return len(s.Members)
}

// EffectiveMemberTimeoutSeconds defaults to 120s.
func (s PanelSpec) EffectiveMemberTimeoutSeconds() int {
	if s.MemberTimeoutSeconds > 0 {
		return s.MemberTimeoutSeconds
	}
	return 120
}

// EffectiveHardTimeoutSeconds defaults to 180s.
func (s PanelSpec) EffectiveHardTimeoutSeconds() int {
	if s.HardTimeoutSeconds > 0 {
		return s.HardTimeoutSeconds
	}
	return 180
}

// EffectiveDiversity defaults to group_by: backend, min_unique:
// len(members), no fallback — the strictest reading, applied whenever the
// panel omits the block entirely.
func (s PanelSpec) EffectiveDiversity() PanelDiversity {
	d := PanelDiversity{GroupBy: "backend", MinUnique: len(s.Members)}
	if s.Diversity == nil {
		return d
	}
	if s.Diversity.GroupBy != "" {
		d.GroupBy = s.Diversity.GroupBy
	}
	if s.Diversity.MinUnique > 0 {
		d.MinUnique = s.Diversity.MinUnique
	}
	d.FallbackGroupBy = s.Diversity.FallbackGroupBy
	return d
}

func ParsePlanFile(filename string) (*Plan, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("read plan: %w", err)
	}
	return ParsePlan(data)
}

func ValidatePlanManifest(plan *Plan, root string, envelope []string, maxTotalTokens int) ([][]Contract, error) {
	if plan == nil {
		return nil, ValidationErrors{{Field: "plan", Message: "is nil"}}
	}
	levels, err := ValidatePlan(plan.Jobs, root, envelope, maxTotalTokens)
	if err != nil {
		return nil, err
	}
	if plan.Panel != nil {
		if err := validatePanelSpec(*plan.Panel, plan.Jobs); err != nil {
			return nil, err
		}
	}
	return levels, nil
}

func ParsePlan(data []byte) (*Plan, error) {
	if name := literalSecretKind(string(data)); name != "" {
		return nil, ValidationErrors{{Field: "plan", Message: "contains a literal " + name + "; reference an environment variable instead"}}
	}

	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var plan Plan
	if err := decoder.Decode(&plan); err != nil {
		return nil, fmt.Errorf("decode plan: %w", err)
	}

	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("decode plan: multiple YAML documents are not allowed")
		}
		return nil, fmt.Errorf("decode plan: %w", err)
	}

	return &plan, nil
}

// ValidatePlan is the deterministic, pure-Go post-gate a `gov plan` run's
// PLAN.yaml manifest must pass before any sub-contract is written out or
// run. It never talks to a backend: every check here is static analysis of
// the manifest against the plan's declared workspace root, write envelope,
// and total token budget:
//
//   - every job independently passes Contract.Validate()
//   - job_id is unique within the plan
//   - every job's workspace.root matches the plan's root (no sub-job can
//     point a governed run at a different project)
//   - every job declares a risk_class and a positive budget.max_tokens
//   - the sum of budget.max_tokens does not exceed maxTotalTokens
//   - every job's allowed.write and preflight.intended_writes patterns stay
//     inside the declared envelope
//   - every depends_on reference names another job_id in the same plan,
//     with no self-reference and no cycle
//
// On success it returns the sub-contracts partitioned into topological
// levels (serial across a depends_on edge, parallel within a level) so both
// `gov plan --show` and `gov batch run --ordered` can reuse the same
// dependency graph without recomputing it differently.
func ValidatePlan(jobs []Contract, root string, envelope []string, maxTotalTokens int) ([][]Contract, error) {
	var errs ValidationErrors
	add := func(field, msg string) { errs = append(errs, ValidationError{Field: field, Message: msg}) }

	if len(jobs) == 0 {
		add("jobs", "plan must contain at least one job")
	}
	if maxTotalTokens <= 0 {
		add("max_total_tokens", "must be greater than zero")
	}
	if len(envelope) == 0 {
		add("envelope", "at least one declared write pattern is required")
	}

	seen := make(map[string]bool, len(jobs))
	totalTokens := 0
	for i, job := range jobs {
		field := fmt.Sprintf("jobs[%d]", i)
		if err := job.Validate(); err != nil {
			add(field, err.Error())
		}
		if job.JobID != "" {
			if seen[job.JobID] {
				add(field+".job_id", "duplicate job_id in plan: "+job.JobID)
			}
			seen[job.JobID] = true
		}
		if job.Workspace.Root != root {
			add(field+".workspace.root", fmt.Sprintf("must equal the plan root %q, got %q", root, job.Workspace.Root))
		}
		if strings.TrimSpace(job.RiskClass) == "" {
			add(field+".risk_class", "every planned job must declare a risk_class (low, medium, or high)")
		}
		if job.Budget.MaxTokens <= 0 {
			add(field+".budget.max_tokens", "every planned job must declare budget.max_tokens > 0 so the plan's total is bounded")
		} else {
			totalTokens += job.Budget.MaxTokens
		}
		for _, w := range job.Allowed.Write {
			if !envelopeCovers(envelope, w) {
				add(field+".allowed.write", fmt.Sprintf("%q escapes the declared envelope %v", w, envelope))
			}
		}
		for _, w := range job.Preflight.IntendedWrites {
			if !envelopeCovers(envelope, w) {
				add(field+".preflight.intended_writes", fmt.Sprintf("%q escapes the declared envelope %v", w, envelope))
			}
		}
	}
	if maxTotalTokens > 0 && totalTokens > maxTotalTokens {
		add("jobs", fmt.Sprintf("sum of budget.max_tokens (%d) exceeds --max-total-tokens (%d)", totalTokens, maxTotalTokens))
	}

	for i, job := range jobs {
		field := fmt.Sprintf("jobs[%d].depends_on", i)
		for _, dep := range job.DependsOn {
			if dep == job.JobID {
				add(field, "job cannot depend on itself: "+dep)
			} else if !seen[dep] {
				add(field, "depends on unknown job_id: "+dep)
			}
		}
	}

	errs = append(errs, ResolveArtifactSources(jobs)...)

	if len(errs) > 0 {
		return nil, errs.Sorted()
	}

	levels, err := TopologicalLevels(jobs)
	if err != nil {
		return nil, ValidationErrors{{Field: "jobs", Message: err.Error()}}
	}
	return levels, nil
}

// TopologicalLevels partitions jobs into dependency levels via Kahn's
// algorithm: level 0 is every job with no unresolved depends_on, level 1
// depends only on level 0, and so on — serial across levels, parallel within
// one. It assumes job_id is unique and every depends_on reference resolves
// within the set (ValidatePlan checks both before calling this); called
// directly (e.g. from `gov plan --show`) it still fails safely on a cycle,
// but a dangling reference is silently ignored rather than reported.
func TopologicalLevels(jobs []Contract) ([][]Contract, error) {
	byID := make(map[string]Contract, len(jobs))
	indegree := make(map[string]int, len(jobs))
	for _, j := range jobs {
		byID[j.JobID] = j
		if _, ok := indegree[j.JobID]; !ok {
			indegree[j.JobID] = 0
		}
	}
	dependents := make(map[string][]string)
	for _, j := range jobs {
		for _, dep := range j.DependsOn {
			if _, ok := byID[dep]; !ok {
				continue // dangling reference: ValidatePlan already reports this
			}
			indegree[j.JobID]++
			dependents[dep] = append(dependents[dep], j.JobID)
		}
	}

	current := map[string]bool{}
	for id, deg := range indegree {
		if deg == 0 {
			current[id] = true
		}
	}

	var levels [][]Contract
	remaining := len(jobs)
	for remaining > 0 {
		if len(current) == 0 {
			return nil, fmt.Errorf("depends_on cycle detected among the remaining %d job(s)", remaining)
		}
		ids := make([]string, 0, len(current))
		for id := range current {
			ids = append(ids, id)
		}
		sort.Strings(ids) // deterministic level ordering
		level := make([]Contract, 0, len(ids))
		for _, id := range ids {
			level = append(level, byID[id])
		}
		levels = append(levels, level)
		remaining -= len(ids)

		next := map[string]bool{}
		for _, id := range ids {
			for _, dep := range dependents[id] {
				indegree[dep]--
				if indegree[dep] == 0 {
					next[dep] = true
				}
			}
		}
		current = next
	}
	return levels, nil
}

// envelopeCovers reports whether candidate (a job's allowed.write pattern)
// stays within one of the plan's declared envelope patterns.
func envelopeCovers(envelope []string, candidate string) bool {
	for _, e := range envelope {
		if envelopePatternCovers(e, candidate) {
			return true
		}
	}
	return false
}

// envelopePatternCovers is deliberately conservative: an exact match, or
// containment inside a declared "dir/**" recursive tree. A declared pattern
// with no wildcard, or a single-level "dir/*", only covers an identical
// candidate — no partial credit — so a sub-job can't smuggle a write pattern
// outside the operator-declared blast radius past a lenient glob heuristic.
func envelopePatternCovers(declared, candidate string) bool {
	declared = normalizePattern(declared)
	candidate = normalizePattern(candidate)
	if declared == candidate {
		return true
	}
	if strings.HasSuffix(declared, "/**") {
		base := strings.TrimSuffix(declared, "/**")
		c := strings.TrimSuffix(candidate, "/**")
		return c == base || strings.HasPrefix(c, base+"/")
	}
	return false
}

// normalizePattern collapses "." and ".." segments (and backslashes) before
// the envelope comparison. Contract.Validate only rejects patterns whose
// CLEANED form escapes workspace.root, so without cleaning here too a
// candidate like "src/../secrets/**" would pass validation (it stays inside
// the root) AND prefix-match a declared "src/**" — smuggling a write target
// outside the declared envelope while remaining inside the workspace.
func normalizePattern(p string) string {
	return path.Clean(strings.ReplaceAll(p, `\`, "/"))
}

// ResolveArtifactSources populates each job's ArtifactSources map from the
// `produces` declarations of its depends_on ancestors, failing closed when a
// consumed artifact has no producing ancestor in the set. ArtifactSources is
// deliberately not part of job YAML (yaml:"-"), so it must be recomputed
// wherever a set of parsed contracts is about to execute together — both
// ValidatePlan (plan authoring) and `gov batch run` (execution of exploded
// job files) call this. Ambiguity (several producing ancestors of the same
// artifact name) resolves to the lexicographically-last producer for
// determinism. Mutates jobs in place.
func ResolveArtifactSources(jobs []Contract) ValidationErrors {
	producersByName := make(map[string][]string)
	for _, job := range jobs {
		for _, artifact := range job.Produces {
			if artifact.Name != "" {
				producersByName[artifact.Name] = append(producersByName[artifact.Name], job.JobID)
			}
		}
	}
	ancestorMap := planAncestors(jobs)
	var errs ValidationErrors
	for i := range jobs {
		field := fmt.Sprintf("jobs[%d].consumes", i)
		sources := map[string]string{}
		for _, name := range jobs[i].Consumes {
			ancestors := ancestorMap[jobs[i].JobID]
			var matches []string
			for _, producer := range producersByName[name] {
				if ancestors[producer] {
					matches = append(matches, producer)
				}
			}
			sort.Strings(matches)
			if len(matches) == 0 {
				errs = append(errs, ValidationError{Field: field, Message: fmt.Sprintf("artifact %q is not produced by any depends_on ancestor", name)})
			} else {
				sources[name] = matches[len(matches)-1]
			}
		}
		if len(sources) > 0 {
			jobs[i].ArtifactSources = sources
		}
	}
	return errs
}

func planAncestors(jobs []Contract) map[string]map[string]bool {
	direct := make(map[string][]string, len(jobs))
	for _, job := range jobs {
		direct[job.JobID] = append([]string{}, job.DependsOn...)
	}
	memo := map[string]map[string]bool{}
	visiting := map[string]bool{}
	var visit func(string) map[string]bool
	visit = func(id string) map[string]bool {
		if cached, ok := memo[id]; ok {
			return cached
		}
		if visiting[id] {
			return map[string]bool{}
		}
		visiting[id] = true
		out := map[string]bool{}
		for _, dep := range direct[id] {
			out[dep] = true
			for ancestor := range visit(dep) {
				out[ancestor] = true
			}
		}
		visiting[id] = false
		memo[id] = out
		return out
	}
	for _, job := range jobs {
		visit(job.JobID)
	}
	return memo
}
