package contracts

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
)

type ResultDocument struct {
	Status                string         `json:"status"`
	FilesChanged          []string       `json:"files_changed"`
	CommandsRun           int            `json:"commands_run"`
	Validation            map[string]any `json:"validation"`
	Violations            []string       `json:"violations"`
	Blockers              []string       `json:"blockers"`
	NextRecommendedAction string         `json:"next_recommended_action"`
}

func CanonicalJSON(c Contract) ([]byte, error) { return json.Marshal(c) }

func ContractHash(c Contract) (string, error) {
	b, err := CanonicalJSON(c)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

func CompilePrompt(c Contract, worktree string) (string, error) {
	b, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return "", err
	}
	role := map[Mode]string{
		ModeScout:       "inspect and report without modifying files",
		ModeSurgeon:     "make the smallest targeted change that satisfies the contract",
		ModeBatchWorker: "apply the requested bounded change consistently",
		ModeVerifier:    "verify deterministically without modifying files",
		ModeRepair:      "diagnose and repair only the stated failure",
		ModeArchitect:   "analyze architecture and report without modifying files",
	}[c.Mode]
	prompt := fmt.Sprintf(`You are an execution agent inside Governator.
Mode: %s - %s.
Task: %s
The only writable project root is %s.
The JSON contract below is authoritative. Never access forbidden paths, run forbidden commands, or exceed budgets.
Run only commands permitted by allowed.execute. Keep all writes within allowed.write.
Before exit, write RESULT.json in the worktree with JSON fields status, files_changed, commands_run, validation, violations, blockers, next_recommended_action.
RESULT.json is advisory; the controller independently verifies every claim.

CONTRACT:
%s
`, c.Mode, role, strings.TrimSpace(c.Task), worktree, b)
	if c.Output != nil && c.Output.Style == "terse" {
		prompt += fmt.Sprintf(`
Output discipline: terse. Keep the final response under %d words. Do not restate the task, narrate routine progress, or add generic advice. Report only actions, verification, blockers, and the final status. Never omit evidence or RESULT.json to save words.
`, c.Output.EffectiveMaxFinalWords())
	}
	prompt += networkAnnotation(c)
	return prompt, nil
}

// networkAnnotation is the prompt-level compensation for backends that declare
// NetworkControl=false (Claude, GLM, OpenCode, Pi). The runtime's fingerprint
// scan is the authoritative network floor, but a model that interprets
// "behaviors: [network]" as a vague hint will still happily run curl/wget/npm
// install mid-task. Naming the concrete verbs the controller will flag makes
// the contract's network prohibition behavior the agent actually has, not just
// one it will be retroactively quarantined for. No-op (and omitted from the
// prompt entirely) when the contract does not forbid network.
func networkAnnotation(c Contract) string {
	for _, behavior := range c.Forbidden.Behaviors {
		if behavior == "network" {
			return `
Network discipline: this contract forbids network access. Do not run network-bound commands — including but not limited to curl, wget, git fetch, git pull, git push, git clone, npm/pnpm/yarn install, pip install, uv sync, cargo add/fetch, go get, apt/apk/dnf, brew, docker pull, ssh, scp, rsync over a remote host, or any tool that contacts a registry, API, or remote host. The controller independently audits your transcript; a network command quarantines the run even if the rest of the work is correct.
`
		}
	}
	return ""
}
