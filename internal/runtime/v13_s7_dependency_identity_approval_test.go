package runtime

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cousingary/governator/internal/toolregistry"
)

func writeFakePython3WithBrokenSitePackages(t *testing.T) string {
	t.Helper()

	stdlibDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(stdlibDir, "os.py"), []byte("# stdlib\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	siteDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(siteDir, "real_module.py"), []byte("# dep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(siteDir, "nonexistent-target"), filepath.Join(siteDir, "broken_link.py")); err != nil {
		t.Fatal(err)
	}

	realPython := resolveTestTool(t, "python3")
	script := "#!/bin/sh\n" +
		"for arg in \"$@\"; do\n" +
		"  case \"$arg\" in\n" +
		"    *sysconfig*)\n" +
		"      printf 'PATH stdlib=%s\\n' '" + stdlibDir + "'\n" +
		"      printf 'PATH platstdlib=%s\\n' '" + stdlibDir + "'\n" +
		"      printf 'PATH purelib=%s\\n' '" + siteDir + "'\n" +
		"      printf 'PATH platlib=%s\\n' '" + siteDir + "'\n" +
		"      printf 'IDENTITY {\"version\":\"3.13.5-fake\",\"implementation_name\":\"cpython\",\"cache_tag\":\"cpython-313\",\"hexversion\":50529008,\"abiflags\":\"\",\"maxsize\":9223372036854775807,\"byteorder\":\"little\",\"platform\":\"linux\",\"config_vars\":{\"EXT_SUFFIX\":\".cpython-313-x86_64-linux-gnu.so\",\"Py_ENABLE_SHARED\":1,\"SIZEOF_VOID_P\":8,\"SOABI\":\"cpython-313-x86_64-linux-gnu\",\"WITH_PYMALLOC\":1}}\\n'\n" +
		"      exit 0\n" +
		"      ;;\n" +
		"  esac\n" +
		"done\n" +
		"exec '" + realPython + "' \"$@\"\n"

	bin := filepath.Join(t.TempDir(), "python3")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin
}

func setAssayEnvWithFakePython(t *testing.T, repo, fakePython string) {
	t.Helper()
	t.Setenv("GOV_ASSAY_REPO", repo)
	t.Setenv("GOV_ASSAY_PYTHON", "python3")
	t.Setenv("GOV_ASSAY_TIMEOUT_SECONDS", "10")
	if _, err := toolregistry.Enroll("python3", fakePython); err != nil {
		t.Fatalf("enroll fake python3: %v", err)
	}
}

func TestV13Case286AssayerDependencyHashingFailureQuarantines(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	assayerRepo := writeAssayerStub(t, stubPassVerdict)
	fakePython := writeFakePython3WithBrokenSitePackages(t)
	setAssayEnvWithFakePython(t, assayerRepo, fakePython)

	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	c := assayProducerContract(root, "blocking")

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status == "APPROVED" {
		t.Fatalf("run reached APPROVED with an unresolvable Assayer dependency identity (status=%s message=%s)", rec.Status, rec.Message)
	}
	if !strings.Contains(rec.Message, "ASSAYER_DEPENDENCY_IDENTITY_UNKNOWN") {
		t.Fatalf("expected quarantine to name ASSAYER_DEPENDENCY_IDENTITY_UNKNOWN, got message=%q", rec.Message)
	}
}

func TestV13Case287UnknownDependencyIdentityCannotApprove(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	assayerRepo := writeAssayerStub(t, stubPassVerdict)
	fakePython := writeFakePython3WithBrokenSitePackages(t)
	setAssayEnvWithFakePython(t, assayerRepo, fakePython)

	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	c := assayProducerContract(root, "blocking")

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status == "APPROVED" {
		t.Fatalf("unknown dependency identity must block production approval (status=%s message=%s)", rec.Status, rec.Message)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); err == nil {
		t.Fatal("unknown-dependency-identity run merged effectful work into the live root before quarantining -- merge must be skipped entirely")
	}
}

func TestV13Case288SourceStringRegressionCannotSubstituteForRuntimeEnforcement(t *testing.T) {
	root, _ := fixture(t)
	writeArtifactSchema(t, root)
	home := t.TempDir()
	t.Setenv("GOV_HOME", home)

	assayerRepo := writeAssayerStub(t, stubPassVerdict)
	fakePython := writeFakePython3WithBrokenSitePackages(t)
	setAssayEnvWithFakePython(t, assayerRepo, fakePython)

	bin := writeFakeBackend(t, `mkdir -p output .governator/artifacts
printf 'ok\n' > output/result.txt
printf '{"summary":"ok"}' > .governator/artifacts/scout.json
printf '{"status":"complete","files_changed":["output/result.txt"],"commands_run":0,"validation":{"self_checked":true},"violations":[],"blockers":[],"next_recommended_action":"none"}\n' > RESULT.json
printf '{"type":"result","total_cost_usd":0.05}\n'
`)
	t.Setenv("GOV_CLAUDE_BIN", bin)
	promptRoot := t.TempDir()
	writePrompt(t, promptRoot, "claude-code", "surgeon")
	t.Setenv("GOV_PROMPTS", promptRoot)

	c := assayProducerContract(root, "blocking")

	rec, err := New().Run(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if rec.Status == "APPROVED" {
		t.Fatal("runtime did not enforce the dependency-identity invariant -- a source-string test would pass while approval proceeds")
	}
	if !strings.Contains(rec.Message, "ASSAYER_DEPENDENCY_IDENTITY_UNKNOWN") {
		t.Fatalf("the runtime violation must be emitted as a quarantine result, not merely recorded as a comment or identity field; got message=%q", rec.Message)
	}
	if !strings.Contains(rec.Message, "production approval blocked") {
		t.Fatalf("violation must state that production approval is blocked, got message=%q", rec.Message)
	}
}
