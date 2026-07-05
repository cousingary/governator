package tokenoptimizer

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/cousingary/governator/internal/config"
)

type Status struct {
	Mode    string
	Bin     string
	Path    string
	Enabled bool
}

func Resolve() (Status, error) {
	cfg, err := config.Load()
	if err != nil {
		return Status{}, err
	}
	status := Status{Mode: cfg.RTK.Mode, Bin: cfg.RTK.Bin}
	if status.Mode == "off" {
		return status, nil
	}
	path, err := exec.LookPath(status.Bin)
	if err != nil {
		if status.Mode == "required" {
			return status, fmt.Errorf("rtk is required but %q was not found in PATH", status.Bin)
		}
		return status, nil
	}
	status.Path = path
	status.Enabled = true
	return status, nil
}

func PromptAnnotation() (string, error) {
	status, err := Resolve()
	if err != nil || !status.Enabled {
		return "", err
	}
	bin := strings.TrimSpace(status.Bin)
	if bin == "" {
		bin = "rtk"
	}
	return fmt.Sprintf(`
Token optimization: RTK is available as %q. Prefix supported shell commands with rtk
(for example: rtk git status, rtk go test ./..., rtk grep pattern .). Keep command
semantics inside the contract; RTK is an output filter, not an authority bypass.
`, bin), nil
}
