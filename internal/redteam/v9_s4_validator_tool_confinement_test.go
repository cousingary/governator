//go:build redteam

// v9_s4_validator_tool_confinement_test.go is Sol redteam v9's rc3 Session 4
// corpus (agents/governator-sol-upgrade9-rc3-plan.md Session 4,
// agents/governator-sol-upgrade9.md P0-5): "report cases 21-27".
//
// P0-5 was that a structured validator's declared Tools list determined
// the validator toolset IDENTITY (a SHA over each declared tool's
// canonical path/sha/inode) but did not constrain validator EXECUTION:
// shellStage pre-pended filepath.Dir(canonical) for every declared tool
// to PATH and then appended the frozen ambient base PATH, so declaring
// one tool in /usr/bin exposed every other executable there (python3,
// perl, curl, ssh, git, sh, env, ...) -- undeclared, unhashed, and
// replay-invisible.
//
// TestV9Case21/22 prove a structured validator can no longer invoke an
// undeclared tool that happens to share a containing directory with a
// declared one (P0-5's headline defect). TestV9Case23 proves a declared
// tool swapped after identity calculation cannot change the executed
// bytes (the registry's hash check fails closed at re-resolve inside
// sealedValidatorToolsets). TestV9Case24/25 prove undeclared Git and
// undeclared scripts are unreachable through PATH. TestV9Case26 proves
// a changed Tools declaration changes the validator toolset identity
// hash (replay-binding). TestV9Case27 proves the structured validator's
// PATH environment variable contains EXACTLY the per-validator sealed
// directory and nothing else -- no ambient base PATH, no auto-added git
// directory.
package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/enforce"
	"github.com/cousingary/governator/internal/toolregistry"
)

// validatorConfinementSkipIfUnsupported gates the cases that actually
// run a structured validator under real Landlock enforcement. Cases that
// only prove identity-calculation or fail-closed behavior before any
// sandboxed launch (TestV9Case23/26) do not need this gate.
func validatorConfinementSkipIfUnsupported(t *testing.T) {
	t.Helper()
	if !enforce.Supported() {
		t.Skip("conditional: this host cannot provide externally enforced containment (Landlock ABI/unshare unavailable) -- nothing to exercise")
	}
}

// enrollValidatorTool enrolls a single named tool at the host's resolved
// path for that name, so the test's structured ValidatorSpec can declare
// it and sealedValidatorToolsets can resolve+seal it. t.Skip if the host
// lacks the named binary, since these fixtures are only meaningful when
// the declared tool is actually available.
func enrollValidatorTool(t *testing.T, name string) {
	t.Helper()
	path, err := exec.LookPath(name)
	if err != nil {
		t.Skipf("conditional: declared tool %q is unavailable on this host (%v) -- case needs the real binary to enroll", name, err)
	}
	if canonical, cerr := filepath.EvalSymlinks(path); cerr == nil {
		path = canonical
	}
	if _, err := toolregistry.Enroll(name, path); err != nil {
		t.Fatalf("enroll declared validator tool %q: %v", name, err)
	}
}

// buildPathPrinterBinary compiles a tiny Go binary that prints its own
// /proc/self/exe path to stdout, used by TestV9Case27 to prove the
// structured validator's PATH is exactly the per-validator sealed dir
// (the sealed copy's /proc/self/exe resolves there, never to the
// originally enrolled path).
func buildPathPrinterBinary(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	src := filepath.Join(dir, "main.go")
	source := `package main

import (
	"fmt"
	"os"
)

func main() {
	exe, err := os.Readlink("/proc/self/exe")
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Print(exe)
}
`
	if err := os.WriteFile(src, []byte(source), 0644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "path-printer")
	cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, src)
	cmd.Dir = dir
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build path-printer binary: %v: %s", err, combined)
	}
	return out
}

// TestV9Case21DeclaredGoInvokingPython3IsDenied is report case 21
// (P0-5's headline example): a structured validator that declares ONLY
// `go` cannot invoke `python3`, even when python3 lives in the same
// /usr/bin directory as go. Pre-fix, filepath.Dir(/usr/bin/go) added
// /usr/bin to PATH and python3 was reachable through it. Post-fix, the
// sealed per-validator dir contains only the verified-bytes copy of go;
// PATH=that dir alone, so bash's lookup of python3 fails and the
// validator exits non-zero (quarantining the run).
func TestV9Case21DeclaredGoInvokingPython3IsDenied(t *testing.T) {
	validatorConfinementSkipIfUnsupported(t)
	enrollValidatorTool(t, "go")

	root := fixtureRepo(t)
	c := baseContract(root)
	c.Success = contracts.Success{
		RequiredFiles: []string{"output/result.txt"},
		Validators:    []string{"python3 --version"},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command: "python3 --version",
			Tools:   []string{"go"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if rec.Status == "APPROVED" {
		t.Fatalf("structured validator declaring only \"go\" was able to invoke undeclared python3 through PATH (status=APPROVED) -- P0-5 regression")
	}
}

// TestV9Case22DeclaredUsrBinToolInvokingAnotherIsDenied is report case
// 22: declaring one tool that lives in /usr/bin must not expose the
// directory's other executables. Pre-fix the validator could freely
// invoke any /usr/bin neighbor of the declared tool; post-fix only the
// declared tool's sealed copy is on PATH.
func TestV9Case22DeclaredUsrBinToolInvokingAnotherIsDenied(t *testing.T) {
	validatorConfinementSkipIfUnsupported(t)
	enrollValidatorTool(t, "cat")
	// ls must be reachable on PATH for the assertion to be meaningful
	// (otherwise "ls not found" is just "no ls anywhere", not "ls is
	// reachable through the declared tool's containing directory").
	if _, err := exec.LookPath("ls"); err != nil {
		t.Skip("conditional: ls is unavailable on this host -- case needs cat and ls to share a containing directory to prove confinement")
	}

	root := fixtureRepo(t)
	c := baseContract(root)
	c.Success = contracts.Success{
		RequiredFiles: []string{"output/result.txt"},
		Validators:    []string{"ls >/dev/null"},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command: "ls >/dev/null",
			Tools:   []string{"cat"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if rec.Status == "APPROVED" {
		t.Fatalf("structured validator declaring only \"cat\" was able to invoke undeclared ls through PATH (status=APPROVED) -- P0-5 regression")
	}
}

// TestV9Case23DeclaredToolSwappedAfterIdentityCalcFailsClosed is report
// case 23: a declared tool whose enrolled file is replaced (different
// bytes, same path) between identity calculation and validator execution
// cannot slip new bytes past the identity that was frozen. The
// registry's hash pin is re-verified when sealedValidatorToolsets opens
// its handle, so the swap is detected and the run errors out before any
// validator executes -- "old bytes or fail-closed" per the report.
//
// This case does not gate on enforce.Supported: the failure happens at
// sealedValidatorToolsets's pre-execution re-resolve, before any
// sandboxed launch is constructed. A host without Landlock still
// reproduces it.
func TestV9Case23DeclaredToolSwappedAfterIdentityCalcFailsClosed(t *testing.T) {
	// Build two distinct fake "go" binaries: enrolledGo is what the
	// registry pins, swappedGo is what a same-uid attacker writes over
	// the enrolled path before the run reaches sealedValidatorToolsets.
	dir := t.TempDir()
	enrolledSrc := filepath.Join(dir, "enrolled.go")
	enrolledGo := filepath.Join(dir, "go")
	swappedSrc := filepath.Join(dir, "swapped.go")
	swappedGo := filepath.Join(dir, "go-hostile")
	sources := map[string]string{
		enrolledSrc: "package main\n\nimport (\n\t\"fmt\"\n)\n\nfunc main() {\n\tfmt.Println(\"enrolled\")\n}\n",
		swappedSrc:  "package main\n\nimport (\n\t\"fmt\"\n)\n\nfunc main() {\n\tfmt.Println(\"swapped\")\n}\n",
	}
	binaries := map[string]string{
		enrolledSrc: enrolledGo,
		swappedSrc:  swappedGo,
	}
	for src, body := range sources {
		if err := os.WriteFile(src, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
		out := binaries[src]
		cmd := exec.Command("go", "build", "-buildvcs=false", "-o", out, src)
		cmd.Dir = dir
		if combined, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build %s: %v: %s", out, err, combined)
		}
	}
	if _, err := toolregistry.Enroll("go", enrolledGo); err != nil {
		t.Fatal(err)
	}
	// Swap BEFORE the run starts: enrolledGo's path now holds swappedGo's
	// bytes. The registry still pins enrolledGo's original hash.
	if err := os.Rename(swappedGo, enrolledGo); err != nil {
		t.Fatal(err)
	}

	root := fixtureRepo(t)
	c := baseContract(root)
	c.Success = contracts.Success{
		RequiredFiles: []string{"output/result.txt"},
		Validators:    []string{"go"},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command: "go",
			Tools:   []string{"go"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, runErr := runGovernedAllowError(t, t.TempDir(), bin, c)
	if rec.Status == "APPROVED" {
		t.Fatalf("swapped declared tool executed under the original identity (status=APPROVED) -- P0-5 regression: %v", runErr)
	}
}

// TestV9Case24UndeclaredGitIsDenied is report case 24: a structured
// validator that does NOT declare git cannot invoke it. Pre-fix the
// shellStage helper auto-prepended filepath.Dir(git.CanonicalPath) to
// PATH for every validator; post-fix, a structured validator that needs
// git must declare it explicitly (per the report's "+ an explicitly
// declared Git when needed").
func TestV9Case24UndeclaredGitIsDenied(t *testing.T) {
	validatorConfinementSkipIfUnsupported(t)
	enrollValidatorTool(t, "true")

	root := fixtureRepo(t)
	c := baseContract(root)
	c.Success = contracts.Success{
		RequiredFiles: []string{"output/result.txt"},
		Validators:    []string{"git --version"},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command: "git --version",
			Tools:   []string{"true"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if rec.Status == "APPROVED" {
		t.Fatalf("structured validator without declared git was able to invoke git through PATH (status=APPROVED) -- P0-5 regression")
	}
}

// TestV9Case25UndeclaredScriptIsDenied is report case 25: a structured
// validator cannot reach a workspace script via bare-name PATH lookup
// when no tool by that name is declared. Pre-fix the workspace's parent
// directory (or the ambient base PATH) made such lookups accidentally
// succeed; post-fix, the sealed per-validator dir is the only PATH
// entry, so a script that lives in the workspace is invisible to bash's
// PATH resolution unless a tool of the same name is declared.
func TestV9Case25UndeclaredScriptIsDenied(t *testing.T) {
	validatorConfinementSkipIfUnsupported(t)
	enrollValidatorTool(t, "true")

	root := fixtureRepo(t)
	// Place a script directly in the workspace root and chmod it
	// executable. The validator invokes it by bare name (no ./ prefix),
	// forcing bash to consult PATH -- which contains only the sealed
	// per-validator dir.
	scriptPath := filepath.Join(root, "workspace-script")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho script-ran\n"), 0755); err != nil {
		t.Fatal(err)
	}
	c := baseContract(root)
	c.Success = contracts.Success{
		RequiredFiles: []string{"output/result.txt"},
		Validators:    []string{"workspace-script"},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command: "workspace-script",
			Tools:   []string{"true"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	if rec.Status == "APPROVED" {
		t.Fatalf("structured validator reached an undeclared workspace script through PATH (status=APPROVED) -- P0-5 regression")
	}
}

// TestV9Case26ValidatorToolDeclarationChangeChangesIdentity lives in
// internal/runtime/identity_test.go (alongside TestV9Case17/18), not
// here: it is a property of the identity-hash function
// (resolveValidatorToolset, package-internal) and that file's existing
// v9-case pattern is to call such helpers directly. Enrolled in the
// manifest under the same name.

// TestV9Case27StructuredValidatorPathContainsOnlyDeclaredTools is report
// case 27: a structured validator's PATH environment variable, as
// observed INSIDE the sandboxed validator process, contains EXACTLY the
// per-validator sealed directory and nothing else -- no ambient base
// PATH, no auto-added git directory. Proven by a cleanup validator (the
// smallest structured-validator stage that can declare a WriteRoot and
// actually land a file in the workspace) writing $PATH to output/path.txt
// and the test asserting the result is precisely one entry matching the
// sealed dir prefix.
func TestV9Case27StructuredValidatorPathContainsOnlyDeclaredTools(t *testing.T) {
	validatorConfinementSkipIfUnsupported(t)
	enrollValidatorTool(t, "true")

	root := fixtureRepo(t)
	c := baseContract(root)
	c.Cleanup = &contracts.Cleanup{
		Required:   false,
		Validators: []string{"printf '%s' \"$PATH\" > output/path.txt"},
		ValidatorSpecs: []contracts.ValidatorSpec{{
			Command:    "printf '%s' \"$PATH\" > output/path.txt",
			Tools:      []string{"true"},
			WriteRoots: []string{"output"},
		}},
	}
	bin := fakeBackend(t, standardBackendBody(""))

	rec, _ := runGovernedAllowError(t, t.TempDir(), bin, c)
	data, rerr := os.ReadFile(filepath.Join(root, "output", "path.txt"))
	if rerr != nil {
		// If the cleanup validator never wrote the file (e.g. the run
		// died earlier for a host-specific reason), the PATH assertion
		// is vacuous -- skip rather than fail on infrastructure that
		// never exercised the property.
		if rec.Status == "APPROVED" {
			t.Fatalf("run APPROVED but output/path.txt was never written -- expected the structured cleanup validator to capture its own PATH")
		}
		t.Skipf("conditional: structured cleanup validator did not write output/path.txt on this host (status=%s) -- cannot prove PATH contents", rec.Status)
	}
	pathValue := strings.TrimSpace(string(data))
	if pathValue == "" {
		t.Fatalf("structured validator PATH was empty -- expected at least the sealed dir entry")
	}
	// PATH must be exactly one entry (no list separator) and that entry
	// must be the per-validator sealed dir created by
	// sealedValidatorToolsets (MkdirTemp "gov-validator-cleanup-0-*").
	if strings.Contains(pathValue, string(os.PathListSeparator)) {
		t.Fatalf("structured validator PATH contains multiple entries (%q) -- ambient base PATH or auto-added git dir leaked into the sealed-dir-only policy", pathValue)
	}
	if !strings.Contains(filepath.Base(pathValue), "gov-validator-cleanup-0-") {
		t.Fatalf("structured validator PATH entry %q is not the sealed per-validator dir (expected a /tmp/gov-validator-cleanup-0-* path)", pathValue)
	}
	// The sealed dir's only executable must be the declared tool (true).
	// Listing the dir from the test process (not the sandboxed one)
	// proves the dir population itself is correct -- a complementary
	// property to the in-sandbox PATH check above.
	entries, lerr := os.ReadDir(pathValue)
	if lerr != nil {
		t.Fatalf("read sealed validator dir %q: %v", pathValue, lerr)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if len(names) != 1 || names[0] != "true" {
		t.Fatalf("sealed validator dir %q contains %v -- expected exactly one entry named \"true\" for the declared tool", pathValue, names)
	}
}
