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
	return []Check{
		checkGit(),
		checkPython(),
		checkProtectedManifest(),
		checkLedgerDirectory(),
		checkLandlock(),
		checkDrvfs(),
	}
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

func checkProtectedManifest() Check {
	check := Check{Name: "protected paths", Required: true}
	manifest, err := protectedManifestPath()
	if err != nil {
		check.Status, check.Detail = StatusFail, err.Error()
		return check
	}
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

func protectedManifestPath() (string, error) {
	if explicit := strings.TrimSpace(os.Getenv("GOV_PROTECTED_PATHS")); explicit != "" {
		return filepath.Clean(explicit), nil
	}
	if state := strings.TrimSpace(os.Getenv("CLAUDE_HARNESS_STATE")); state != "" {
		return filepath.Join(state, "protected_paths.txt"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".governed-harness", "state", "protected_paths.txt"), nil
}

func governorHome() (string, error) {
	if explicit := strings.TrimSpace(os.Getenv("GOVERNATOR_HOME")); explicit != "" {
		return filepath.Clean(explicit), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("resolve home directory: %w", err)
	}
	return filepath.Join(home, ".governator"), nil
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
