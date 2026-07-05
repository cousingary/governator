package doctor

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"

	"github.com/cousingary/governator/internal/agents"
	"github.com/cousingary/governator/internal/config"
	"github.com/cousingary/governator/internal/contextgraph"
	"github.com/cousingary/governator/internal/protectedpaths"
	"github.com/cousingary/governator/internal/tokenoptimizer"
)

type Status string

const (
	StatusOK   Status = "ok"
	StatusWarn Status = "warn"
	StatusFail Status = "fail"
)

type Check struct {
	Name     string
	Status   Status
	Detail   string
	Required bool
}

func Run() []Check {
	checks := []Check{
		checkConfig(),
		checkGit(),
		checkPython(),
		checkRTK(),
		checkContextGraph(),
		checkProtectedManifest(),
		checkLedgerDirectory(),
		checkLandlock(),
		checkDrvfs(),
		// Phase 5: backend CLI flag-drift probes. Each adapter depends on a
		// small set of native flags that the backend can rename under us; the
		// probe runs the backend with --help/version and asserts the flags
		// still appear. Non-required (WARN) — a box need not run all backends.
		checkBackendFlags("claude", "claude", []string{}, []string{"--output-format", "--add-dir", "--permission-mode"}),
		checkBackendFlags("codex", "codex", []string{}, []string{"exec", "--sandbox", "--ask-for-approval", "-C"}),
		checkBackendFlags("glm", "glm", []string{}, []string{"--output-format", "--add-dir", "--permission-mode"}),
		checkBackendFlags("opencode", "opencode", []string{"run"}, []string{"--format", "--dir", "--pure"}),
		checkBackendFlags("pi", "pi", []string{}, []string{"--print", "--mode", "--tools", "--no-session", "--no-extensions", "--no-skills"}),
	}
	for _, row := range agents.CapabilityMatrix() {
		checks = append(checks, Check{
			Name: "capability:" + row.Name, Status: StatusOK, Required: false,
			Detail: fmt.Sprintf("sandbox=%t read-only=%t approval=%t network=%t transcript=%s",
				row.NativeSandbox, row.NativeReadOnly, row.NativeApprovalPolicy,
				row.NetworkControl, row.TranscriptFormat),
		})
	}
	return checks
}

func Passed(checks []Check) bool {
	for _, check := range checks {
		if check.Required && check.Status == StatusFail {
			return false
		}
	}
	return true
}

func checkGit() Check {
	check := Check{Name: "git", Required: true}
	path, err := exec.LookPath("git")
	if err != nil {
		check.Status, check.Detail = StatusFail, "not found in PATH"
		return check
	}
	output, err := exec.Command(path, "--version").Output()
	if err != nil {
		check.Status, check.Detail = StatusFail, err.Error()
		return check
	}
	version, ok := parseVersion(string(output), "git version ")
	if !ok || versionLess(version, [3]int{2, 30, 0}) {
		check.Status, check.Detail = StatusFail, fmt.Sprintf("need git >=2.30; got %s", strings.TrimSpace(string(output)))
		return check
	}
	help, _ := exec.Command(path, "worktree", "-h").CombinedOutput()
	if !bytes.Contains(help, []byte("git worktree")) || !bytes.Contains(help, []byte("add")) {
		check.Status, check.Detail = StatusFail, "git worktree support was not detected"
		return check
	}
	check.Status, check.Detail = StatusOK, fmt.Sprintf("%d.%d.%d with worktree support", version[0], version[1], version[2])
	return check
}

func checkPython() Check {
	check := Check{Name: "python3", Required: true}
	path, err := exec.LookPath("python3")
	if err != nil {
		check.Status, check.Detail = StatusFail, "not found in PATH"
		return check
	}
	output, err := exec.Command(path, "--version").CombinedOutput()
	if err != nil {
		check.Status, check.Detail = StatusFail, err.Error()
		return check
	}
	check.Status, check.Detail = StatusOK, strings.TrimSpace(string(output))
	return check
}

func checkRTK() Check {
	status, err := tokenoptimizer.Resolve()
	check := Check{Name: "rtk token optimizer", Required: status.Mode == "required"}
	if err != nil {
		check.Status, check.Detail = StatusFail, err.Error()
		return check
	}
	if status.Mode == "off" {
		check.Status, check.Detail = StatusOK, "disabled by configuration"
		return check
	}
	if !status.Enabled {
		check.Status, check.Detail = StatusWarn, status.Bin+" not found in PATH; token optimization inactive"
		return check
	}
	output, versionErr := exec.Command(status.Path, "--version").CombinedOutput()
	if versionErr != nil {
		check.Status = StatusWarn
		if check.Required {
			check.Status = StatusFail
		}
		check.Detail = fmt.Sprintf("%s found but --version failed: %v", status.Path, versionErr)
		return check
	}
	check.Status, check.Detail = StatusOK, strings.TrimSpace(string(output))
	return check
}

func checkContextGraph() Check {
	status, err := contextgraph.Resolve()
	check := Check{Name: "context graph", Required: status.Mode == "required"}
	if err != nil {
		check.Status, check.Detail = StatusFail, err.Error()
		return check
	}
	if status.Mode == "off" {
		check.Status, check.Detail = StatusOK, "disabled by configuration"
		return check
	}
	if !status.Enabled {
		check.Status, check.Detail = StatusWarn, fmt.Sprintf("%s (%s) not found in PATH; structural context inactive", status.Provider, status.Bin)
		return check
	}
	version, err := contextgraph.Version(status)
	if err != nil {
		check.Status = StatusWarn
		if check.Required {
			check.Status = StatusFail
		}
		check.Detail = err.Error()
		return check
	}
	cwd, err := os.Getwd()
	if err != nil {
		check.Status, check.Detail = StatusWarn, fmt.Sprintf("%s; cannot inspect current directory: %v", version, err)
		return check
	}
	stats, err := contextgraph.Inspect(status, cwd)
	if err != nil || !stats.Initialized {
		check.Status, check.Detail = StatusOK, version+"; current directory not indexed"
		return check
	}
	check.Status = StatusOK
	check.Detail = fmt.Sprintf("%s; files=%d nodes=%d edges=%d db_bytes=%d index=%s", version, stats.FileCount, stats.NodeCount, stats.EdgeCount, stats.DBSizeBytes, stats.IndexPath)
	return check
}

func checkProtectedManifest() Check {
	check := Check{Name: "protected paths", Required: true}
	manifest := protectedpaths.Manifest()
	file, err := os.Open(manifest)
	if err != nil {
		check.Status, check.Detail = StatusFail, fmt.Sprintf("%s: %v", manifest, err)
		return check
	}
	defer file.Close()

	active := 0
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			active++
		}
	}
	if err := scanner.Err(); err != nil {
		check.Status, check.Detail = StatusFail, fmt.Sprintf("%s: %v", manifest, err)
		return check
	}
	check.Status, check.Detail = StatusOK, fmt.Sprintf("%s readable (%d active patterns)", manifest, active)
	return check
}

func checkLedgerDirectory() Check {
	check := Check{Name: "ledger directory", Required: true}
	home, err := governorHome()
	if err != nil {
		check.Status, check.Detail = StatusFail, err.Error()
		return check
	}
	if err := os.MkdirAll(home, 0o700); err != nil {
		check.Status, check.Detail = StatusFail, err.Error()
		return check
	}
	probe, err := os.CreateTemp(home, ".doctor-write-")
	if err != nil {
		check.Status, check.Detail = StatusFail, err.Error()
		return check
	}
	name := probe.Name()
	closeErr := probe.Close()
	removeErr := os.Remove(name)
	if closeErr != nil || removeErr != nil {
		check.Status, check.Detail = StatusFail, fmt.Sprintf("write probe cleanup failed: close=%v remove=%v", closeErr, removeErr)
		return check
	}
	check.Status, check.Detail = StatusOK, home+" writable"
	return check
}

func checkLandlock() Check {
	check := Check{Name: "landlock", Required: false}
	if runtime.GOOS != "linux" {
		check.Status, check.Detail = StatusWarn, "unavailable (non-Linux); optional"
		return check
	}
	data, err := os.ReadFile("/sys/kernel/security/lsm")
	if err != nil {
		check.Status, check.Detail = StatusWarn, "unavailable (kernel LSM list not exposed); optional"
		return check
	}
	if !strings.Contains(string(data), "landlock") {
		check.Status, check.Detail = StatusWarn, "unavailable (not listed by kernel); optional"
		return check
	}
	check.Status, check.Detail = StatusOK, "listed by kernel; adapter self-restriction may be enabled"
	return check
}

func checkDrvfs() Check {
	check := Check{Name: "filesystem", Required: false}
	cwd, err := os.Getwd()
	if err != nil {
		check.Status, check.Detail = StatusWarn, "cannot resolve current directory: "+err.Error()
		return check
	}
	data, err := os.ReadFile("/proc/mounts")
	if err != nil {
		check.Status, check.Detail = StatusWarn, "cannot inspect /proc/mounts: "+err.Error()
		return check
	}

	mountpoint, fsType, options := mountForPath(cwd, string(data))
	if mountpoint == "" {
		check.Status, check.Detail = StatusWarn, "mount not found for "+cwd
		return check
	}
	if fsType == "9p" && strings.Contains(options, "aname=drvfs") {
		check.Status, check.Detail = StatusOK, fmt.Sprintf("drvfs detected at %s; polling/diff watchers required", mountpoint)
		return check
	}
	check.Status, check.Detail = StatusOK, fmt.Sprintf("%s on %s", fsType, mountpoint)
	return check
}

// checkBackendFlags probes a coding-agent backend's --help output to assert the
// native flags the adapter depends on still exist (plan risk: "Backend CLI flag
// drift"). The env override lets tests point at a fake binary. Non-required:
// missing backend = WARN (the box need not run all three), but a present backend
// MISSING a depended-on flag = FAIL (the adapter would mis-govern silently).
func backendHelpArgs(helpArgs []string) []string {
	args := append([]string(nil), helpArgs...)
	return append(args, "--help")
}

func checkBackendFlags(name, defaultBin string, helpArgs, requiredFlags []string) Check {
	check := Check{Name: "backend:" + name, Required: false}
	configName := name
	if name == "claude" {
		configName = "claude-code"
	}
	bin := config.BackendBin(configName)
	if bin == "" {
		bin = defaultBin
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		check.Status, check.Detail = StatusWarn, name+" not found in PATH (adapter unavailable)"
		return check
	}
	args := backendHelpArgs(helpArgs)
	output, _ := exec.Command(path, args...).CombinedOutput()
	body := string(output)
	var missing []string
	for _, flag := range requiredFlags {
		if !strings.Contains(body, flag) {
			missing = append(missing, flag)
		}
	}
	if len(missing) > 0 {
		check.Status = StatusFail
		check.Detail = fmt.Sprintf("%s present but missing flag(s): %s (adapter must be updated)", bin, strings.Join(missing, ", "))
		return check
	}
	check.Status = StatusOK
	check.Detail = fmt.Sprintf("%s present with required flags (%s)", bin, strings.Join(requiredFlags, ", "))
	return check
}

func governorHome() (string, error) {
	cfg, err := config.Load()
	if err != nil {
		return "", err
	}
	return cfg.LedgerDir, nil
}

func checkConfig() Check {
	check := Check{Name: "configuration", Required: true}
	_, err := config.Load()
	if err != nil {
		check.Status, check.Detail = StatusFail, err.Error()
		return check
	}
	check.Status, check.Detail = StatusOK, config.Path()
	return check
}

func parseVersion(value, prefix string) ([3]int, bool) {
	var out [3]int
	value = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(value), prefix))
	value = strings.TrimPrefix(value, "go")
	parts := strings.SplitN(value, ".", 4)
	if len(parts) < 2 {
		return out, false
	}
	for i := 0; i < len(out) && i < len(parts); i++ {
		digits := strings.TrimLeftFunc(parts[i], func(r rune) bool { return r < '0' || r > '9' })
		end := 0
		for end < len(digits) && digits[end] >= '0' && digits[end] <= '9' {
			end++
		}
		if end == 0 {
			return out, false
		}
		n, err := strconv.Atoi(digits[:end])
		if err != nil {
			return out, false
		}
		out[i] = n
	}
	return out, true
}

func versionLess(left, right [3]int) bool {
	for i := range left {
		if left[i] != right[i] {
			return left[i] < right[i]
		}
	}
	return false
}

func mountForPath(target, mounts string) (string, string, string) {
	target = filepath.Clean(target)
	bestMount, bestType, bestOptions := "", "", ""
	for _, line := range strings.Split(mounts, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		mountpoint := unescapeMount(fields[1])
		if target != mountpoint && !strings.HasPrefix(target, strings.TrimRight(mountpoint, "/")+"/") {
			continue
		}
		if len(mountpoint) > len(bestMount) {
			bestMount, bestType, bestOptions = mountpoint, fields[2], fields[3]
		}
	}
	return bestMount, bestType, bestOptions
}

func unescapeMount(value string) string {
	replacer := strings.NewReplacer(`\040`, " ", `\011`, "\t", `\012`, "\n", `\134`, `\`)
	return replacer.Replace(value)
}
