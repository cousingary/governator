//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestAttack26FakeBashInjectedThroughPathIsRejected is the post-v4 hardening
// plan's Session 2 (item C) redteam attack: "fake unshare/bash/docker
// injected via PATH must not be executed with Governator authority."
//
// Every job contract's success.validators (contracts/schema.go requires at
// least one) runs as a `bash -lc <command>` subprocess -- see
// runner.go/runtime.go's shell() helpers. Before this session, that bash
// invocation used a bare "bash" argv0, letting os/exec's own ambient PATH
// lookup resolve it -- exactly the class of gap S4 closed for git (report
// attack 10) but never applied to bash, even though bash is the shell every
// validator command actually executes through on every governed run,
// unconditionally.
//
// This test pins bash's real canonical path in the trusted-tool registry
// (mirroring TestAttack10's setup for git), then prepends a hostile "bash"
// earlier on PATH that -- if it were ever invoked with Governator's
// authority -- would both leave a detectable marker AND report every
// command as failing. The base contract's own validator
// ("test -f output/result.txt") must still be evaluated by the real,
// registry-pinned bash: the run reaches APPROVED, and the hostile script
// never runs at all.
func TestAttack26FakeBashInjectedThroughPathIsRejected(t *testing.T) {
	root := fixtureRepo(t)

	registryFile := filepath.Join(t.TempDir(), "tools.yaml")
	t.Setenv("GOV_TOOLREGISTRY_FILE", registryFile)

	// Pin the real system git binary explicitly rather than whatever
	// exec.LookPath("git") finds first on this machine's ambient PATH: a
	// dev box can have a personal git wrapper earlier on PATH (a shell
	// script, e.g. with a `#!/usr/bin/env bash` shebang) whose OWN
	// interpreter lookup happens at the kernel/shebang level, entirely
	// outside this test's PATH poisoning and outside the trusted-tool
	// registry's reach -- pinning to that wrapper would make this test
	// depend on that script's internals instead of cleanly proving the one
	// property it's actually about: bash resolution honors the registry
	// pin. /usr/bin/git is a real compiled binary with no shebang of its
	// own to confound this.
	realGit := "/usr/bin/git"
	if _, err := os.Stat(realGit); err != nil {
		t.Fatalf("/usr/bin/git not present on this host: %v", err)
	}
	realBash, err := exec.LookPath("bash")
	if err != nil {
		t.Fatal(err)
	}
	if canonical, everr := filepath.EvalSymlinks(realBash); everr == nil {
		realBash = canonical
	}
	registryYAML := "tools:\n" +
		"  - name: git\n    kind: trusted_controller\n    path: " + realGit + "\n" +
		"  - name: bash\n    kind: trusted_controller\n    path: " + realBash + "\n"
	if err := os.WriteFile(registryFile, []byte(registryYAML), 0644); err != nil {
		t.Fatal(err)
	}

	fakeBashMarker := filepath.Join(t.TempDir(), "fake-bash-ran.txt")
	fakeBashDir := t.TempDir()
	fakeBash := filepath.Join(fakeBashDir, "bash")
	// Mirrors TestAttack10's fake-git shape: record that it ran, then fail
	// closed loudly so a successful run PROVES the fake never executed
	// rather than merely being consistent with it not executing.
	if err := os.WriteFile(fakeBash, []byte("#!/bin/sh\nprintf ran > "+fakeBashMarker+"\nprintf 'fake bash\\n' >&2\nexit 1\n"), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", fakeBashDir+string(os.PathListSeparator)+os.Getenv("PATH"))

	c := baseContract(root)
	bin := fakeBackend(t, standardBackendBody(""))
	rec := runGoverned(t, t.TempDir(), bin, c)
	if rec.Status != "APPROVED" {
		t.Fatalf("expected APPROVED using the registry-pinned real bash to run success.validators despite a hostile bash earlier on PATH, got status=%s message=%s", rec.Status, rec.Message)
	}
	if _, err := os.Stat(fakeBashMarker); !os.IsNotExist(err) {
		t.Fatal("hostile PATH-shadowing bash executed instead of the registry-pinned real bash")
	}
}
