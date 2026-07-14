//go:build redteam

package redteam

import (
	"bytes"
	"os/exec"
	"testing"
)

// TestAttack15MalformedGateCheckInputFailsClosed is report P1-11 / §9
// attack 15: `printf '{broken' | gov gate check` must never be treated as
// "no decision" (which callers read as approval). Malformed protocol input
// must always produce a structured DENY, an explicit PROTOCOL_ERROR, a
// nonzero exit code, and a durable emergency audit record. Fixed by S7:
// cmd/gov/main.go's gateCmd now routes a stdin-read/JSON/tool-name failure
// through denyGateProtocolError, reusing the readHookPayload/
// hookProtocolError machinery `gov hook pre-tool-use` already used
// correctly for the identical class of input (see
// cmd/gov/main_test.go::TestAttack15GateCheckMalformedInputFailsClosed for
// the full contract, including the hook_events audit record).
func TestAttack15MalformedGateCheckInputFailsClosed(t *testing.T) {
	bin := govBinary(t)
	home := t.TempDir()
	cmd := exec.Command(bin, "gate", "check")
	cmd.Env = append(cmd.Environ(), "GOV_HOME="+home)
	cmd.Stdin = bytes.NewBufferString("{broken")
	out, err := cmd.CombinedOutput()

	if err == nil {
		t.Fatalf("expected nonzero exit for malformed gate check input, got exit 0: %s", out)
	}
	if !bytes.Contains(out, []byte("PROTOCOL_ERROR")) {
		t.Fatalf("expected an explicit PROTOCOL_ERROR in output, got: %s", out)
	}
	if !bytes.Contains(out, []byte("DENY")) {
		t.Fatalf("expected a structured DENY, got: %s", out)
	}
}
