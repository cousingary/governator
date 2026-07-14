package containment

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestScopeKillsDetachedSetsidDescendant is the primitive-level regression
// for report P0-4 / §9 attack 8: a setsid'd, double-forked grandchild that
// outlives its parent's own exit must not survive Extinguish, regardless of
// which method NewScope selected for this host.
func TestScopeKillsDetachedSetsidDescendant(t *testing.T) {
	dir := t.TempDir()
	transcriptDir := t.TempDir() // deliberately outside dir -- mirrors runtime.go's transcripts/ living outside the worktree
	marker := filepath.Join(dir, "escaped.txt")

	scope, err := NewScope("containment-unit-test-"+t.Name(), false)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	t.Logf("scope method: %s", scope.Method())

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	script := "#!/bin/sh\nset -eu\nsetsid sh -c 'sleep 2; printf leak > " + marker + "' < /dev/null > /dev/null 2>&1 &\nprintf started\n"
	bin := filepath.Join(dir, "script.sh")
	if err := os.WriteFile(bin, []byte(script), 0755); err != nil {
		t.Fatal(err)
	}

	cmd := scope.Command(ctx, bin, nil, dir)
	out, err := os.CreateTemp(transcriptDir, "out")
	if err != nil {
		t.Fatal(err)
	}
	defer out.Close()
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	scope.Started(cmd.Process.Pid)
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Wait: %v", err)
	}

	proof, err := scope.Extinguish(ctx, 5*time.Second, dir)
	if err != nil {
		t.Fatalf("Extinguish: %v (proof=%+v)", err, proof)
	}
	if proof.Degraded {
		t.Fatalf("scope degraded to bare process group: %s", proof.Note)
	}
	if !proof.Killed || !proof.WorkspaceFDScanClean {
		t.Fatalf("incomplete extinction proof: %+v", proof)
	}

	// Give the detached child every chance to win the race; Extinguish
	// having returned nil must mean it already lost.
	time.Sleep(3 * time.Second)
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatalf("detached descendant survived Extinguish and wrote %s: err=%v", marker, err)
	}
}

// TestScopeExtinguishNoopWhenNothingStarted covers the agentTimeout<=0 path
// in runtime.go: a Scope that never launched anything must still produce a
// clean Proof instead of erroring.
func TestScopeExtinguishNoopWhenNothingStarted(t *testing.T) {
	scope, err := NewScope("containment-unit-test-noop", false)
	if err != nil {
		t.Fatalf("NewScope: %v", err)
	}
	proof, err := scope.Extinguish(context.Background(), 2*time.Second, t.TempDir())
	if err != nil {
		t.Fatalf("Extinguish on never-started scope: %v", err)
	}
	if !proof.Frozen || !proof.Killed || !proof.WorkspaceFDScanClean {
		t.Fatalf("expected vacuous success, got %+v", proof)
	}
}
