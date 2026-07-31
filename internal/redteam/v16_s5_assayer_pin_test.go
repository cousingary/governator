//go:build redteam

package redteam

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

var sha256HexRE = regexp.MustCompile(`^[0-9a-f]{40}$`)

func TestV16Case400AssayerLockPinIsLoadBearingExactSHA(t *testing.T) {
	lockPath := filepath.Join("..", "..", "assayer.lock")
	data, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatalf("read assayer.lock: %v", err)
	}

	var ref string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.Split(line, "#")[0]
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "ref=") {
			ref = line[4:]
			break
		}
	}
	if ref == "" {
		t.Fatal("assayer.lock does not declare a ref= entry")
	}

	if !sha256HexRE.MatchString(ref) {
		t.Fatalf("assayer.lock ref=%q is not an exact 40-hex-char git SHA; a moving branch or tag ref would make CI non-reproducible", ref)
	}

	t.Run("moving_branch_ref_rejected", func(t *testing.T) {
		for _, bad := range []string{"main", "v1.1.11", "HEAD", "release/latest"} {
			if sha256HexRE.MatchString(bad) {
				t.Fatalf("validator incorrectly accepts non-SHA ref %q", bad)
			}
		}
	})

	t.Run("workflow_reads_pin", func(t *testing.T) {
		wfPath := filepath.Join("..", "..", ".github", "workflows", "release.yml")
		wf, err := os.ReadFile(wfPath)
		if err != nil {
			t.Fatalf("read release.yml: %v", err)
		}
		if !strings.Contains(string(wf), "assayer.lock") {
			t.Fatal("release.yml does not reference assayer.lock — the pin is not load-bearing in CI")
		}
		if !strings.Contains(string(wf), "steps.assayer-ref.outputs.ref") {
			t.Fatal("release.yml does not use the parsed assayer.lock ref for checkout")
		}
	})
}
