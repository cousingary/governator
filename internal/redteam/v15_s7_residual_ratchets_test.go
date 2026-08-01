//go:build redteam

// v15_s7_residual_ratchets_test.go is rc8-upg15 Session 7's P2-3 ratchet,
// case 391 (Sol15 P2-3 "Public signing keys need an external trust anchor").
// A release signature verified only against a key shipped beside the
// payload proves integrity but NOT origin: an attacker controlling the
// bundle ships a forged key next to a forged signature and every check
// still passes. Session 7 makes external trust-anchor sourcing the
// documented default of the release verifiers and bundle-local sourcing an
// explicit, warned-about opt-in:
//
//   - scripts/release_policy.py signature rejects trust material resolving
//     inside --artifacts-dir (BUNDLE_LOCAL_TRUST_ANCHOR) unless
//     --allow-bundle-local-trust-anchor is passed (with a loud warning);
//   - scripts/audit_bundle_validate.py evaluates a trust-posture gate
//     BEFORE any completeness check: no trust anchors at all fails
//     NO_EXTERNAL_TRUST_ANCHOR unless --allow-unverified-signature is
//     passed (the old silent signature skip no longer exists), and
//     bundle-local anchors fail BUNDLE_LOCAL_TRUST_ANCHOR without the
//     explicit opt-in;
//   - scripts/bundle_verify.py cross-checks the bundle's signer fingerprint
//     against an externally supplied --trusted-fingerprints-file and warns
//     WEAK_ORIGIN_AUTHENTICATION when none is supplied.
//
// The production fingerprint B5CBEE8BBA8826A7 is published out-of-band in
// agents/governator-signing-key-fingerprint.txt (separate nested repo) and
// mirrored to VPS 216.158.228.204 (docs/signing_key.md); those channels are
// operator actions, not code. This case ratchets the verifier-side property
// so a future change cannot silently make a bundle-local anchor sufficient
// again.
package redteam

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func s7Script(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", name)
}

func s7FileSHA256(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// s7MinisignFixture generates an ephemeral minisign key, stages an artifacts
// directory with one archive artifact + checksums.txt + a valid signature
// over it (mirroring v11_s1's s1Stage layout: the EXTERNAL trust file and
// key directory live OUTSIDE the artifacts dir), and also stages a
// bundle-local copy of both INSIDE the artifacts dir (so checksums.txt
// covers them, exactly as a real release's checksums cover every shipped
// file). Returns every path plus the signer fingerprint.
func s7MinisignFixture(t *testing.T) (artifactsDir, checksums, minisig, trustFile, keyDir, localTrust, localKeys, fingerprint string) {
	t.Helper()
	if _, err := exec.LookPath("minisign"); err != nil {
		t.Skip("minisign is required for the trust-anchor ratchet")
	}
	work := t.TempDir()
	artifactsDir = filepath.Join(work, "dist")
	keyDir = filepath.Join(work, "keys")
	if err := os.MkdirAll(artifactsDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secKey := filepath.Join(work, "sec.key")
	pub := filepath.Join(work, "pub.key")
	gen := exec.Command("minisign", "-G", "-W", "-p", pub, "-s", secKey)
	gen.Stdin = strings.NewReader("")
	if out, err := gen.CombinedOutput(); err != nil {
		t.Fatalf("minisign -G: %v\n%s", err, out)
	}
	pubData, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	pubLines := strings.Split(string(pubData), "\n")
	if len(pubLines) < 2 {
		t.Fatalf("unexpected minisign public key file")
	}
	pubPacket, err := base64.StdEncoding.DecodeString(strings.TrimSpace(pubLines[1]))
	if err != nil || len(pubPacket) != 42 || string(pubPacket[:2]) != "Ed" {
		t.Fatalf("unexpected minisign public key packet: len=%d err=%v", len(pubPacket), err)
	}
	// Derive the cryptographic key ID from the packet, exactly as
	// release_policy.py does. Minisign's human-readable comment is
	// untrusted metadata and differs across packaged Minisign versions.
	fingerprint = strings.ToUpper(hex.EncodeToString(reverseBytes(pubPacket[2:10])))

	artifact := filepath.Join(artifactsDir, "gov_1.0.0_linux_amd64.tar.gz")
	if err := os.WriteFile(artifact, []byte("release artifact bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Bundle-local copies INSIDE the artifacts dir, staged before
	// checksums.txt is written so the checksums cover them like any other
	// shipped file.
	localTrust = filepath.Join(artifactsDir, "trust.txt")
	if err := os.WriteFile(localTrust, []byte(fingerprint+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	localKeys = filepath.Join(artifactsDir, "keys")
	if err := os.MkdirAll(localKeys, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(localKeys, fingerprint+".pub"), pubData, 0o644); err != nil {
		t.Fatal(err)
	}
	checksums = filepath.Join(artifactsDir, "checksums.txt")
	var b strings.Builder
	fmt.Fprintf(&b, "%s  gov_1.0.0_linux_amd64.tar.gz\n", s7FileSHA256(t, artifact))
	fmt.Fprintf(&b, "%s  trust.txt\n", s7FileSHA256(t, localTrust))
	if err := os.WriteFile(checksums, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	minisig = filepath.Join(artifactsDir, "checksums.txt.minisig")
	sign := exec.Command("minisign", "-S", "-s", secKey, "-m", checksums, "-x", minisig, "-c", "s7 ratchet fixture")
	sign.Stdin = strings.NewReader("")
	if out, err := sign.CombinedOutput(); err != nil {
		t.Fatalf("minisign -S: %v\n%s", err, out)
	}

	trustFile = filepath.Join(work, "trust.txt")
	if err := os.WriteFile(trustFile, []byte(fingerprint+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(keyDir, fingerprint+".pub"), pubData, 0o644); err != nil {
		t.Fatal(err)
	}
	return artifactsDir, checksums, minisig, trustFile, keyDir, localTrust, localKeys, fingerprint
}

func reverseBytes(in []byte) []byte {
	out := append([]byte(nil), in...)
	for left, right := 0, len(out)-1; left < right; left, right = left+1, right-1 {
		out[left], out[right] = out[right], out[left]
	}
	return out
}

func s7RunPolicy(t *testing.T, args ...string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", append([]string{s7Script(t, "release_policy.py"), "signature"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestV15Case391BundleLocalTrustAnchorAloneIsInsufficientWithoutExternalFingerprint(t *testing.T) {
	artifactsDir, checksums, minisig, trustFile, keyDir, localTrust, localKeys, _ := s7MinisignFixture(t)

	// A bundle-local fingerprints file (resolved inside the artifacts
	// directory it verifies) must be REJECTED: a key that travels beside
	// the payload proves integrity but not origin.
	out, err := s7RunPolicy(t,
		"--version", "1.0.0", "--require", "1",
		"--minisig", minisig,
		"--trusted-fingerprints-file", localTrust,
		"--checksums", checksums,
		"--trusted-public-keys-dir", localKeys,
		"--artifacts-dir", artifactsDir,
	)
	if err == nil {
		t.Fatalf("release_policy accepted a bundle-local trust anchor despite a valid signature; a key shipped beside the payload must never be sufficient (Sol15 P2-3):\n%s", out)
	}
	if !strings.Contains(out, "BUNDLE_LOCAL_TRUST_ANCHOR") {
		t.Fatalf("expected BUNDLE_LOCAL_TRUST_ANCHOR rejection, got:\n%s", out)
	}

	// The explicit opt-in accepts it -- with a loud weak-origin warning.
	out, err = s7RunPolicy(t,
		"--version", "1.0.0", "--require", "1",
		"--minisig", minisig,
		"--trusted-fingerprints-file", localTrust,
		"--checksums", checksums,
		"--trusted-public-keys-dir", localKeys,
		"--artifacts-dir", artifactsDir,
		"--allow-bundle-local-trust-anchor",
	)
	if err != nil {
		t.Fatalf("release_policy rejected a bundle-local trust anchor despite the explicit opt-in (the opt-in must remain available, warned, for compatibility):\n%s", out)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "WEAK") {
		t.Fatalf("bundle-local opt-in must warn loudly about weak origin authentication, got:\n%s", out)
	}

	// Externally sourced trust material (outside the artifacts dir) is the
	// documented default: full cryptographic success, no bundle-local
	// warning.
	out, err = s7RunPolicy(t,
		"--version", "1.0.0", "--require", "1",
		"--minisig", minisig,
		"--trusted-fingerprints-file", trustFile,
		"--checksums", checksums,
		"--trusted-public-keys-dir", keyDir,
		"--artifacts-dir", artifactsDir,
	)
	if err != nil {
		t.Fatalf("release_policy rejected externally sourced trust material (the documented default):\n%s", out)
	}
	if strings.Contains(out, "BUNDLE_LOCAL_TRUST_ANCHOR") || strings.Contains(out, "WEAK") {
		t.Fatalf("external sourcing must verify cleanly with no bundle-local/weak-origin warning, got:\n%s", out)
	}

	// The external file's CONTENT is still enforced: an externally sourced
	// file naming the wrong fingerprint rejects the release.
	wrongTrust := filepath.Join(filepath.Dir(trustFile), "wrong_trust.txt")
	if err := os.WriteFile(wrongTrust, []byte("0000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = s7RunPolicy(t,
		"--version", "1.0.0", "--require", "1",
		"--minisig", minisig,
		"--trusted-fingerprints-file", wrongTrust,
		"--checksums", checksums,
		"--trusted-public-keys-dir", keyDir,
		"--artifacts-dir", artifactsDir,
	)
	if err == nil {
		t.Fatalf("release_policy accepted a signature whose signer is not in the external trust anchor:\n%s", out)
	}

	// audit_bundle_validate.py: the release-mode gate must not silently
	// skip signature verification when no trust anchor is supplied (the
	// pre-Sol15 behaviour that let an unverified dist print "verified
	// release").
	validate := s7Script(t, "audit_bundle_validate.py")
	emptyDist := t.TempDir()
	cmd := exec.Command("python3", validate,
		"--dist-dir", emptyDist, "--repo", t.TempDir(), "--release-commit", "0000000")
	outBytes, err := cmd.CombinedOutput()
	out = string(outBytes)
	if err == nil {
		t.Fatalf("audit_bundle_validate passed with no trust anchor at all; a missing external fingerprint must fail closed, not silently skip (Sol15 P2-3):\n%s", out)
	}
	if !strings.Contains(out, "NO_EXTERNAL_TRUST_ANCHOR") {
		t.Fatalf("expected NO_EXTERNAL_TRUST_ANCHOR, got:\n%s", out)
	}

	// The explicit dry-run opt-in passes the trust gate (and then fails on
	// the empty dist's missing evidence -- proving the flow continued past
	// the trust posture check rather than failing on it).
	cmd = exec.Command("python3", validate,
		"--dist-dir", emptyDist, "--repo", t.TempDir(), "--release-commit", "0000000",
		"--allow-unverified-signature")
	outBytes, _ = cmd.CombinedOutput()
	out = string(outBytes)
	if strings.Contains(out, "NO_EXTERNAL_TRUST_ANCHOR") {
		t.Fatalf("--allow-unverified-signature must pass the trust gate, got:\n%s", out)
	}
	if !strings.Contains(out, "WARNING") || !strings.Contains(out, "INCOMPLETE_RELEASE_EVIDENCE") {
		t.Fatalf("expected the dry-run warning followed by the completeness failure, got:\n%s", out)
	}

	// Trust anchors resolving inside the dist directory are bundle-local
	// and rejected without the explicit opt-in.
	cmd = exec.Command("python3", validate,
		"--dist-dir", artifactsDir, "--repo", t.TempDir(), "--release-commit", "0000000",
		"--trusted-fingerprints-file", localTrust,
		"--trusted-public-keys-dir", localKeys)
	outBytes, err = cmd.CombinedOutput()
	out = string(outBytes)
	if err == nil {
		t.Fatalf("audit_bundle_validate accepted a bundle-local trust anchor without the explicit opt-in (Sol15 P2-3):\n%s", out)
	}
	if !strings.Contains(out, "BUNDLE_LOCAL_TRUST_ANCHOR") {
		t.Fatalf("expected BUNDLE_LOCAL_TRUST_ANCHOR from audit_bundle_validate, got:\n%s", out)
	}
}
