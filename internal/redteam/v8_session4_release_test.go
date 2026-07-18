//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	govruntime "github.com/cousingary/governator/internal/runtime"
)

func TestV8Case20DirtyReleaseArtifactRejected(t *testing.T) {
	commit := "2020202020202020202020202020202020202020"
	dist, repoRoot, platform := buildReleaseFixtureDist(t, releaseFixtureOpts{
		version:        "1.0.2-rc2-redteam20",
		manifestCommit: commit,
		mode:           0755,
		artifactDirty:  true,
	})

	out, err := runReleaseVerify(t, dist, repoRoot, platform)
	if err == nil {
		t.Fatalf("release_verify.sh accepted an archived binary whose version --json reported dirty=true; output:\n%s", out)
	}
	if !strings.Contains(out, "dirty=true") {
		t.Fatalf("expected release_verify.sh to fail on dirty=true, got:\n%s", out)
	}
}

func TestV8Case21UnsignedRCReleaseRejected(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..")
	cmd := exec.Command("python3", filepath.Join(repoRoot, "scripts", "release_policy.py"), "signature",
		"--version", "1.0.2-rc2",
		"--require", "1",
		"--minisig", filepath.Join(t.TempDir(), "missing.minisig"),
	)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("release policy accepted an unsigned rc build; output:\n%s", out)
	}
	if !strings.Contains(string(out), "requires an asymmetric minisign signature") {
		t.Fatalf("expected asymmetric-signature refusal, got:\n%s", out)
	}
}

func TestV8Case22DarwinBuildRefusesApprovalOrMerge(t *testing.T) {
	root := fixtureRepo(t)
	home := t.TempDir()
	bin := fakeBackend(t, `mkdir -p output
printf 'ok\n' > output/result.txt
cat <<'EOF'
{"type":"result","subtype":"success"}
EOF
`)
	c := baseContract(root)
	c.Local = nil

	prev := govruntime.RuntimeGOOS
	govruntime.RuntimeGOOS = "darwin"
	defer func() { govruntime.RuntimeGOOS = prev }()

	rec := runGoverned(t, home, bin, c)
	if rec.Status == "APPROVED" || rec.Status == "MERGED_LEDGER_PENDING" {
		t.Fatalf("darwin build approved or merged despite feature-limited non-approving policy: %+v", rec)
	}
	if !strings.Contains(rec.Message, "darwin builds are feature-limited") {
		t.Fatalf("expected darwin refusal message, got %+v", rec)
	}
	if _, err := os.Stat(filepath.Join(root, "output", "result.txt")); !os.IsNotExist(err) {
		t.Fatalf("darwin refusal still merged output into live root, stat err=%v", err)
	}
}
