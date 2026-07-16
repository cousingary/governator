//go:build redteam

package redteam

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/controllerenv"
	stageexec "github.com/cousingary/governator/internal/stage"
)

func writeV7S3Probe(t *testing.T, dir, result string) {
	t.Helper()
	path := filepath.Join(dir, "s3-probe")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nprintf %s "+result+"\n"), 0755); err != nil {
		t.Fatal(err)
	}
}

func runV7S3Stage(t *testing.T, workdir string, env controllerenv.Frozen, command string) string {
	t.Helper()
	executable, err := stageexec.HashExecutable("/bin/sh")
	if err != nil {
		t.Fatal(err)
	}
	result, err := stageexec.NewExecutor().Run(context.Background(), stageexec.StageSpec{
		RunID: "v7-s3", StageID: "frozen-environment", Executable: executable,
		Arguments: []string{"-c", command}, WorkingDirectory: workdir,
		Environment:      stageexec.FrozenEnvironment{Values: env.Values, Hash: env.Hash},
		NetworkPolicy:    stageexec.NetworkPolicyDenied,
		CredentialPolicy: stageexec.CredentialPolicyNone,
	})
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(result.Output)
}

// TestV7Case19AmbientPATHMutationAfterConstructionCannotRedirectStage is
// corpus case 19: PATH is captured once, then an attacker changes ambient
// PATH before launch. The stage must still execute the originally captured
// tool.
func TestV7Case19AmbientPATHMutationAfterConstructionCannotRedirectStage(t *testing.T) {
	trusted, hostile, workdir := t.TempDir(), t.TempDir(), t.TempDir()
	writeV7S3Probe(t, trusted, "trusted")
	writeV7S3Probe(t, hostile, "hostile")
	t.Setenv("PATH", trusted)
	frozen := controllerenv.Freeze()
	t.Setenv("PATH", hostile)
	if got := runV7S3Stage(t, workdir, frozen, "s3-probe"); got != "trusted" {
		t.Fatalf("post-construction PATH mutation redirected stage: got %q", got)
	}
}

// TestV7Case20ControllerValuesMutationAfterConstructionCannotReachStage is
// corpus case 20: every allowlisted controller value is changed after the
// snapshot. Execution and the environment hash remain bound to the snapshot.
func TestV7Case20ControllerValuesMutationAfterConstructionCannotReachStage(t *testing.T) {
	workdir := t.TempDir()
	originals := map[string]string{"HOME": "/frozen/home", "TMPDIR": "/frozen/tmp", "LANG": "C", "LC_ALL": "C", "TZ": "UTC"}
	for key, value := range originals {
		t.Setenv(key, value)
	}
	frozen := controllerenv.Freeze()
	for key := range originals {
		t.Setenv(key, "/hostile/"+strings.ToLower(key))
	}
	if err := frozen.Validate(); err != nil {
		t.Fatal(err)
	}
	got := runV7S3Stage(t, workdir, frozen, `printf "%s|%s|%s|%s|%s" "$HOME" "$TMPDIR" "$LANG" "$LC_ALL" "$TZ"`)
	if got != "/frozen/home|/frozen/tmp|C|C|UTC" {
		t.Fatalf("post-construction controller environment mutation reached stage: %q", got)
	}
}
