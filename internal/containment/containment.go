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

// LocalEffectfulTieringEnforced reports whether Session 6's local-run gate is
// active. Unknown/empty values fail closed to enforced; config validation keeps
// operator-authored values to "enforce" or "off".
func LocalEffectfulTieringEnforced(mode string) bool {
	return strings.TrimSpace(mode) != "off"
}

// Effectful reports whether a contract can create persistent effects in the
// workspace/artifact graph. Pure read-only scout contracts can be medium risk
// without host containment; any declared write/produced artifact is effectful.
func Effectful(c contracts.Contract) bool {
	return len(c.Allowed.Write) > 0 || len(c.Preflight.IntendedWrites) > 0 || len(c.Produces) > 0
}

// RequiresHostContainment reports whether this contract must prove host-level
// containment. High risk remains fail-closed as before. Session 6 adds medium
// risk when the job is effectful and local effectful tiering is enforced.
func RequiresHostContainment(c contracts.Contract, enforceLocalEffectful bool) bool {
	risk := strings.TrimSpace(c.RiskClass)
	if risk == "high" {
		return true
	}
	return enforceLocalEffectful && risk == "medium" && Effectful(c)
}

// Enforce applies the default risk-class containment policy. It preserves the
// historical call shape while enabling Session 6's enforced-by-default
// medium/high effectful local-run gate.
func Enforce(c contracts.Contract, externallyEnforced bool, pubKeyHex string) error {
	return EnforcePolicy(c, externallyEnforced, pubKeyHex, true)
}

// EnforcePolicy applies the risk-class containment policy and returns a
// non-nil error when a contract lacks qualifying containment. It is
// fail-closed by construction: pubKeyHex is the operator override public key
// from config — empty means overrides are refused.
//
// externallyEnforced reports whether Governator's OWN external-enforcement
// layer is available for a "local" runner (internal/enforce: Landlock LSM
// filesystem confinement + a network namespace with no route, applied to the
// launched process from outside it, independent of anything the backend
// claims about itself). Per Sol P0-3 (Session 5, report §9 attack 5): a
// backend's declared or probe-attested native sandbox is evidence, never
// proof — a program that knows it is being tested can behave only during the
// test. It no longer qualifies a "local" runner on its own; only this
// externally-enforced boundary or a signed operator override does.
func EnforcePolicy(c contracts.Contract, externallyEnforced bool, pubKeyHex string, enforceLocalEffectful bool) error {
	if !RequiresHostContainment(c, enforceLocalEffectful) {
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
			"containment: risk_class %q requires a hardened docker config "+
				"(non-root user, read-only rootfs, cap-drop=ALL, no-new-privileges, pinned image, network=deny) "+
				"or a signed operator override; the declared docker config is not hardened", strings.TrimSpace(c.RiskClass))
	case "local":
		if externallyEnforced {
			return nil
		}
		if VerifyOverride(c, pubKeyHex) {
			return nil
		}
		return fmt.Errorf(
			"containment: risk_class %q effectful runner: local requires Governator's own externally "+
				"enforced sandbox (Landlock LSM + network namespace; see internal/enforce), hardened docker, "+
				"or a signed operator override; this host cannot provide that enforcement layer, and %q's own "+
				"declared/attested native sandbox is evidence, not proof, and no longer qualifies on its own "+
				"(Sol P0-3)", strings.TrimSpace(c.RiskClass), c.Agent)
	default:
		return fmt.Errorf("containment: risk_class %q does not support runner %q", strings.TrimSpace(c.RiskClass), c.EffectiveRunner())
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
