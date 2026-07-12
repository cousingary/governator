// Package containment implements the Session 3 (Phase 2) risk-class
// containment policy: a risk_class: high contract must not silently resolve
// to local execution. Qualifying containment is hardened Docker
// (contracts.DockerRunnerConfig.IsHardened), a backend with a verified native
// sandbox capability, or an explicitly signed operator override. Every other
// case fails closed before launch.
package containment

import (
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/cousingary/governator/internal/contracts"
)

// Enforce applies the risk-class containment policy and returns a non-nil
// error when a high-risk contract lacks qualifying containment. It is
// fail-closed by construction: nativeSandbox reports whether the resolved
// backend declares a native sandbox capability (verified at the agent layer,
// never trusted from the contract alone), and pubKeyHex is the operator
// override public key from config — empty means overrides are refused, so a
// high-risk job with no qualifying containment simply cannot run.
//
// Non-high-risk contracts pass through untouched (the policy is risk-tiered).
func Enforce(c contracts.Contract, nativeSandbox bool, pubKeyHex string) error {
	if strings.TrimSpace(c.RiskClass) != "high" {
		return nil
	}
	switch c.EffectiveRunner() {
	case "docker":
		if c.Docker != nil && c.Docker.IsHardened() {
			return nil
		}
		if VerifyOverride(c, pubKeyHex) {
			return nil
		}
		return fmt.Errorf(
			"containment: risk_class: high requires a hardened docker config " +
				"(non-root user, read-only rootfs, cap-drop=ALL, no-new-privileges, pinned image) " +
				"or a signed operator override; the declared docker config is not hardened")
	case "local":
		if nativeSandbox {
			return nil
		}
		if VerifyOverride(c, pubKeyHex) {
			return nil
		}
		return fmt.Errorf(
			"containment: risk_class: high with runner: local requires a backend "+
				"with a verified native sandbox or a signed operator override; "+
				"%q does not declare a native sandbox capability", c.Agent)
	default:
		return fmt.Errorf("containment: risk_class: high does not support runner %q", c.EffectiveRunner())
	}
}

// VerifyOverride reports whether the contract carries a valid signed override
// for its job_id AND its exact content, verified against pubKeyHex. An empty
// pubKeyHex refuses every override (fail-closed: no operator key configured
// means no escape hatch). The signed message is SigningMessage(c) — see
// OverrideMessage for why the contract hash is part of what's signed.
func VerifyOverride(c contracts.Contract, pubKeyHex string) bool {
	if c.Containment == nil {
		return false
	}
	reason := strings.TrimSpace(c.Containment.OverrideReason)
	sigHex := strings.TrimSpace(c.Containment.OverrideSignature)
	if reason == "" || sigHex == "" || strings.TrimSpace(pubKeyHex) == "" {
		return false
	}
	pub, err := hex.DecodeString(strings.TrimSpace(pubKeyHex))
	if err != nil || len(pub) != ed25519.PublicKeySize {
		return false
	}
	sig, err := hex.DecodeString(sigHex)
	if err != nil || len(sig) != ed25519.SignatureSize {
		return false
	}
	msg, err := SigningMessage(c)
	if err != nil {
		return false
	}
	return ed25519.Verify(ed25519.PublicKey(pub), msg, sig)
}

// SigningMessage builds the exact bytes an operator signs to authorize a
// containment override for contract c: OverrideMessage over c's job_id, the
// hash of c with its containment block cleared (the signature can't cover
// itself), and the override reason. Exposed so `gov containment message`,
// tests, and VerifyOverride can never drift on the format.
func SigningMessage(c contracts.Contract) ([]byte, error) {
	stripped := c
	stripped.Containment = nil
	hash, err := contracts.ContractHash(stripped)
	if err != nil {
		return nil, err
	}
	reason := ""
	if c.Containment != nil {
		reason = strings.TrimSpace(c.Containment.OverrideReason)
	}
	return OverrideMessage(c.JobID, hash, reason), nil
}

// OverrideMessage is the exact bytes an operator signs (ed25519) to authorize
// a containment override for one contract. Binding the job_id prevents an
// override minted for one high-risk job being replayed against another;
// binding contractHash (the contract's hash with its containment block
// cleared) prevents the sharper replay where the SAME job's contract body is
// edited after signing — widened scope, network enablement, a different
// image — while the old signature keeps verifying. Any content edit changes
// the hash and invalidates the signature. Exposed so signing tooling and
// tests produce matching signatures without duplicating the format.
func OverrideMessage(jobID, contractHash, reason string) []byte {
	return []byte(jobID + ":" + contractHash + ":" + reason)
}
