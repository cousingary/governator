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
	return fmt.Sprintf(`You are an execution agent inside Governator.
Mode: %s - %s.
Task: %s
The only writable project root is %s.
The JSON contract below is authoritative. Never access forbidden paths, run forbidden commands, or exceed budgets.
Run only commands permitted by allowed.execute. Keep all writes within allowed.write.
Before exit, write RESULT.json in the worktree with JSON fields status, files_changed, commands_run, validation, violations, blockers, next_recommended_action.
RESULT.json is advisory; the controller independently verifies every claim.

CONTRACT:
%s
`, c.Mode, role, strings.TrimSpace(c.Task), worktree, b), nil
}
