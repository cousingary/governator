package contextgraph

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/cousingary/governator/internal/config"
)

type Status struct {
	Mode     string
	Provider string
	Bin      string
	Path     string
	Enabled  bool
}

type Stats struct {
	Version       string         `json:"version"`
	Initialized   bool           `json:"initialized"`
	ProjectPath   string         `json:"projectPath"`
	IndexPath     string         `json:"indexPath"`
	FileCount     int            `json:"fileCount"`
	NodeCount     int            `json:"nodeCount"`
	EdgeCount     int            `json:"edgeCount"`
	DBSizeBytes   int64          `json:"dbSizeBytes"`
	LastIndexed   string         `json:"lastIndexed"`
	Pending       map[string]int `json:"pendingChanges"`
	Languages     []string       `json:"languages"`
	WorktreeState any            `json:"worktreeMismatch"`
}

func Resolve() (Status, error) {
	cfg, err := config.Load()
	if err != nil {
		return Status{}, err
	}
	status := Status{Mode: cfg.Graph.Mode, Provider: cfg.Graph.Provider, Bin: cfg.Graph.Bin}
	if status.Mode == "off" {
		return status, nil
	}
	path, err := exec.LookPath(status.Bin)
	if err != nil {
		if status.Mode == "required" {
			return status, fmt.Errorf("%s graph provider is required but %q was not found in PATH", status.Provider, status.Bin)
		}
		return status, nil
	}
	status.Path = path
	status.Enabled = true
	return status, nil
}

func Version(status Status) (string, error) {
	if !status.Enabled {
		return "", fmt.Errorf("graph provider is not enabled")
	}
	output, err := exec.Command(status.Path, "version").CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("%s version: %w: %s", status.Provider, err, strings.TrimSpace(string(output)))
	}
	return strings.TrimSpace(string(output)), nil
}

func Inspect(status Status, project string) (Stats, error) {
	if !status.Enabled {
		return Stats{}, fmt.Errorf("graph provider is not enabled")
	}
	output, err := exec.Command(status.Path, "status", "--json", project).CombinedOutput()
	if err != nil {
		return Stats{}, fmt.Errorf("%s status: %w: %s", status.Provider, err, strings.TrimSpace(string(output)))
	}
	var stats Stats
	if err := json.Unmarshal(output, &stats); err != nil {
		return Stats{}, fmt.Errorf("decode %s status: %w", status.Provider, err)
	}
	return stats, nil
}
