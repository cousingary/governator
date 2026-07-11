package panel

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/cousingary/governator/internal/contracts"
)

const (
	memberSchemaFile     = "panel-member.schema.json"
	comparisonSchemaFile = "panel-comparison.schema.json"
	judgmentSchemaFile   = "panel-judgment.schema.json"
)

type Options struct {
	Root           string
	OutDir         string
	Envelope       []string
	Count          int
	Agent          string
	MaxTotalTokens int
	Intent         string

	// MinSuccess, MemberTimeoutSeconds, HardTimeoutSeconds, and the Diversity*
	// fields configure contracts.PanelSpec's quorum/diversity block (Phase 2).
	// Every field is optional; 0/"" defers to PanelSpec's Effective* defaults
	// (wait for every member, one distinct backend per member), so a caller
	// that never sets them gets exactly the pre-Phase-2 behavior.
	MinSuccess           int
	MemberTimeoutSeconds int
	HardTimeoutSeconds   int
	DiversityKey         string
	DiversityMinUnique   int
	DiversityFallbackKey string
}

func GeneratePlan(opts Options) (contracts.Plan, error) {
	if opts.Count < 2 {
		return contracts.Plan{}, fmt.Errorf("panel size must be at least 2")
	}
	if opts.Agent == "" {
		opts.Agent = contracts.AgentAuto
	}
	outRel := filepath.ToSlash(filepath.Clean(opts.OutDir))
	if filepath.IsAbs(outRel) || outRel == "." || outRel == ".." || strings.HasPrefix(outRel, "../") {
		return contracts.Plan{}, fmt.Errorf("out dir must be relative to workspace root")
	}
	if opts.MaxTotalTokens <= 0 {
		return contracts.Plan{}, fmt.Errorf("max total tokens must be positive")
	}
	perJobTokens := opts.MaxTotalTokens / (opts.Count + 2)
	if perJobTokens <= 0 {
		perJobTokens = 1
	}
	panelSpec := &contracts.PanelSpec{
		ID: "panel", ComparisonJob: "panel-compare", Judge: "panel-judge",
		MinSuccess: opts.MinSuccess, MemberTimeoutSeconds: opts.MemberTimeoutSeconds, HardTimeoutSeconds: opts.HardTimeoutSeconds,
	}
	if opts.DiversityKey != "" || opts.DiversityMinUnique > 0 || opts.DiversityFallbackKey != "" {
		panelSpec.Diversity = &contracts.PanelDiversity{GroupBy: opts.DiversityKey, MinUnique: opts.DiversityMinUnique, FallbackGroupBy: opts.DiversityFallbackKey}
	}
	memberMaxMinutes := secondsToMinutesCeil(panelSpec.EffectiveMemberTimeoutSeconds())

	schemaPrefix := outRel + "/schemas/"
	members := make([]string, 0, opts.Count)
	jobs := make([]contracts.Contract, 0, opts.Count+2)
	memberArtifacts := make([]string, 0, opts.Count)
	for i := 1; i <= opts.Count; i++ {
		id := fmt.Sprintf("panel-member-%d", i)
		artifact := fmt.Sprintf("panel_member_%d", i)
		members = append(members, id)
		memberArtifacts = append(memberArtifacts, artifact)
		jobs = append(jobs, readOnlyJob(opts.Root, id, "panel_analysis", opts.Agent, contracts.ModeArchitect, perJobTokens, memberMaxMinutes, []contracts.ArtifactSpec{{
			Name: artifact, Path: fmt.Sprintf(".governator/artifacts/%s.json", artifact), Schema: schemaPrefix + memberSchemaFile, MaxBytes: 262144,
		}}, nil, nil, fmt.Sprintf("Analyze the intent independently as anonymous panelist %d. Write only the declared JSON artifact; do not modify source.\n\nINTENT:\n%s", i, strings.TrimSpace(opts.Intent))))
	}
	panelSpec.Members = members
	comparisonID := panelSpec.ComparisonJob
	comparisonArtifact := "panel_comparison"
	jobs = append(jobs, readOnlyJob(opts.Root, comparisonID, "panel_comparison", opts.Agent, contracts.ModeVerifier, perJobTokens, 10, []contracts.ArtifactSpec{{
		Name: comparisonArtifact, Path: ".governator/artifacts/panel-comparison.json", Schema: schemaPrefix + comparisonSchemaFile, MaxBytes: 262144,
	}}, memberArtifacts, members, "Generate the deterministic comparison artifact with `gov panel compare --out .governator/artifacts/panel-comparison.json .governator/consumed/panel_member_*`. Do not edit source."))
	judgeConsumes := []string{comparisonArtifact}
	judgeDepends := append(append([]string{}, members...), comparisonID)
	jobs = append(jobs, readOnlyJob(opts.Root, panelSpec.Judge, "panel_judgment", opts.Agent, contracts.ModeArchitect, perJobTokens, 10, []contracts.ArtifactSpec{{
		Name: "panel_judgment", Path: ".governator/artifacts/panel-judgment.json", Schema: schemaPrefix + judgmentSchemaFile, MaxBytes: 262144,
	}}, judgeConsumes, judgeDepends, "Judge the anonymized panel bundle and deterministic comparison artifact. Your verdict is advisory only; validators remain sovereign. Write only the declared JSON artifact."))
	return contracts.Plan{Panel: panelSpec, Jobs: jobs}, nil
}

// secondsToMinutesCeil converts a panel quorum timeout (second granularity)
// to the whole-minute granularity contracts.Budget.MaxMinutes uses, rounding
// up so a job never gets less wall-clock time than the operator asked for.
// The result is never below 1: budget.max_minutes must be positive
// (Contract.Validate).
func secondsToMinutesCeil(seconds int) int {
	m := (seconds + 59) / 60
	if m < 1 {
		return 1
	}
	return m
}

func readOnlyJob(root, id, jobType, agent string, mode contracts.Mode, maxTokens, maxMinutes int, produces []contracts.ArtifactSpec, consumes []string, depends []string, task string) contracts.Contract {
	validators := []string{"test -f " + produces[0].Path}
	if id == "panel-compare" {
		validators = []string{"gov panel compare --out .governator/artifacts/panel-comparison.json .governator/consumed/panel_member_*", "test -f .governator/artifacts/panel-comparison.json"}
	}
	return contracts.Contract{
		Task: task, JobID: id, JobType: jobType, Agent: agent, Mode: mode,
		Workspace: contracts.Workspace{Root: root, Worktree: "auto"},
		Allowed:   contracts.Permissions{Read: []string{"**"}, Write: []string{}, Execute: []string{"test -f *", "gov panel compare *"}},
		Forbidden: contracts.Forbidden{Paths: []string{".git/**"}, Commands: []string{"rm -rf", "git push"}, Behaviors: []string{"write_source", "network"}},
		// MaxNewFiles is 1, not 0: every governed run writes RESULT.json into
		// the worktree root (outside .governator/, so it isn't excluded by
		// filterSourceChanges), which the fingerprint diff counts as one new
		// file regardless of mode. MaxNewFiles: 0 would budget-exceed every
		// real panel member run before Phase 2's quorum/diversity logic ever
		// got exercised — pre-existing (this readOnlyJob predates Phase 2),
		// caught here because Phase 2 is the first code to run a panel member
		// end-to-end instead of only validating its generated contract.
		Budget:    contracts.Budget{MaxMinutes: maxMinutes, MaxCommands: 10, MaxFilesChanged: 1, MaxLinesChanged: 1, MaxNewFiles: 1, MaxDeleted: 0, MaxTokens: maxTokens},
		Preflight: contracts.Preflight{IntendedWrites: []string{}},
		Success:   contracts.Success{RequiredFiles: []string{}, Validators: validators},
		Produces:  produces, Consumes: consumes, DependsOn: depends, RiskClass: "low", OnViolation: "quarantine",
	}
}

func SchemaFiles() map[string][]byte {
	return map[string][]byte{
		memberSchemaFile:     []byte(`{"type":"object","required":["summary","findings"],"properties":{"summary":{"type":"string"},"findings":{"type":"array","items":{"type":"string"}},"risks":{"type":"array","items":{"type":"string"}}},"additionalProperties":false}`),
		comparisonSchemaFile: []byte(`{"type":"object","required":["version","participants","differing_paths"],"properties":{"version":{"type":"number"},"participants":{"type":"array","items":{"type":"object"}},"differing_paths":{"type":"array","items":{"type":"string"}}},"additionalProperties":false}`),
		judgmentSchemaFile:   []byte(`{"type":"object","required":["summary","recommendation"],"properties":{"summary":{"type":"string"},"recommendation":{"type":"string"},"concerns":{"type":"array","items":{"type":"string"}}},"additionalProperties":false}`),
	}
}

type ArtifactInput struct {
	Name string
	Path string
	Data []byte
}

type Comparison struct {
	Version        int           `json:"version"`
	Participants   []Participant `json:"participants"`
	DifferingPaths []string      `json:"differing_paths"`
}

type Participant struct {
	Label       string `json:"label"`
	SourceName  string `json:"source_name"`
	SHA256      string `json:"sha256"`
	ContentJSON any    `json:"content_json"`
}

func CompareArtifacts(inputs []ArtifactInput) (Comparison, error) {
	if len(inputs) < 2 {
		return Comparison{}, fmt.Errorf("at least two artifacts are required")
	}
	sort.Slice(inputs, func(i, j int) bool { return inputs[i].Name < inputs[j].Name })
	comparison := Comparison{Version: 1}
	values := make([]any, 0, len(inputs))
	for i, input := range inputs {
		var raw any
		if err := json.Unmarshal(input.Data, &raw); err != nil {
			return Comparison{}, fmt.Errorf("parse %s: %w", input.Name, err)
		}
		sanitized := stripIdentity(raw)
		sum := sha256.Sum256(input.Data)
		comparison.Participants = append(comparison.Participants, Participant{Label: fmt.Sprintf("panelist_%d", i+1), SourceName: input.Name, SHA256: hex.EncodeToString(sum[:]), ContentJSON: sanitized})
		values = append(values, sanitized)
	}
	paths := map[string]bool{}
	collectDiffPaths("$", values, paths)
	comparison.DifferingPaths = make([]string, 0, len(paths))
	for p := range paths {
		comparison.DifferingPaths = append(comparison.DifferingPaths, p)
	}
	sort.Strings(comparison.DifferingPaths)
	return comparison, nil
}

func CompareFiles(paths []string) ([]byte, error) {
	inputs := make([]ArtifactInput, 0, len(paths))
	for _, p := range paths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, err
		}
		inputs = append(inputs, ArtifactInput{Name: filepath.Base(p), Path: p, Data: data})
	}
	comparison, err := CompareArtifacts(inputs)
	if err != nil {
		return nil, err
	}
	return json.MarshalIndent(comparison, "", "  ")
}

func stripIdentity(value any) any {
	switch v := value.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, child := range v {
			if identityKey(k) {
				continue
			}
			out[k] = stripIdentity(child)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, child := range v {
			out[i] = stripIdentity(child)
		}
		return out
	default:
		return value
	}
}

func identityKey(key string) bool {
	switch strings.ToLower(key) {
	case "agent", "backend", "model", "provider", "candidate", "api_key":
		return true
	}
	return false
}

func collectDiffPaths(at string, values []any, out map[string]bool) {
	if len(values) < 2 || allEqual(values) {
		return
	}
	keys := map[string]bool{}
	allObjects := true
	for _, value := range values {
		obj, ok := value.(map[string]any)
		if !ok {
			allObjects = false
			break
		}
		for k := range obj {
			keys[k] = true
		}
	}
	if allObjects && len(keys) > 0 {
		for _, k := range sortedBoolKeys(keys) {
			children := make([]any, 0, len(values))
			for _, value := range values {
				children = append(children, value.(map[string]any)[k])
			}
			collectDiffPaths(at+"."+k, children, out)
		}
		return
	}
	out[at] = true
}

func allEqual(values []any) bool {
	for i := 1; i < len(values); i++ {
		if !reflect.DeepEqual(values[0], values[i]) {
			return false
		}
	}
	return true
}

func sortedBoolKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
