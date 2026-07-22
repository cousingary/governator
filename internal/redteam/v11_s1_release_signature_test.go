//go:build redteam

package redteam

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Sol11 (Governator v1.0.2-rc5 plan, Session 1) red-team corpus, release
// signature cases 1-8. The underlying defect (P0-1): scripts/release_policy.py
// extracted the signer key ID from checksums.txt.minisig, checked it against
// docs/TRUSTED_SIGNING_KEYS.txt, and returned success -- WITHOUT EVER
// VERIFYING the Ed25519 signature over checksums.txt. A forged .minisig
// carrying the trusted key ID and zero-filled signature bytes was accepted.
//
// Session 1 closes it by making release_policy.py cryptographically verify
// (minisign -V) the signature over the exact checksums.txt bytes, using a
// PINNED public key whose fingerprint matches the out-of-band anchor, and by
// pinning/recording the minisign verifier itself. Every case below uses an
// ephemeral, purpose-built minisign key pair generated in the test's own
// temp directory -- never the real production key.

// s1PolicyScript resolves scripts/release_policy.py from this test file's
// own location, independent of the caller's working directory.
func s1PolicyScript(t *testing.T) string {
	t.Helper()
	return filepath.Join(repoRootForBundleTests(t), "scripts", "release_policy.py")
}

// s1GenKey generates an ephemeral, unencrypted minisign key pair.
func s1GenKey(t *testing.T, secOut, pubOut string) {
	t.Helper()
	cmd := exec.Command("minisign", "-G", "-W", "-s", secOut, "-p", pubOut)
	cmd.Stdin = strings.NewReader("")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("minisign -G: %v\n%s", err, out)
	}
}

// s1Fingerprint derives the display fingerprint from a minisign .pub file
// (mirrors scripts/release_policy.py's minisign_pubkey_fingerprint).
func s1Fingerprint(t *testing.T, pubPath string) string {
	t.Helper()
	data, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatal(err)
	}
	var blobLine string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "untrusted") {
			continue
		}
		blobLine = line
		break
	}
	if blobLine == "" {
		t.Fatalf("%s: no public key blob line", pubPath)
	}
	blob, err := base64.StdEncoding.DecodeString(blobLine)
	if err != nil || len(blob) < 10 {
		t.Fatalf("%s: invalid public key blob", pubPath)
	}
	id := blob[2:10] // stored little-endian relative to the display fingerprint
	rev := make([]byte, len(id))
	for i := range id {
		rev[i] = id[len(id)-1-i]
	}
	return strings.ToUpper(hex.EncodeToString(rev))
}

// s1Sign signs msgFile into minisigOut with the given secret key.
func s1Sign(t *testing.T, sec, msgFile, minisigOut string) {
	t.Helper()
	cmd := exec.Command("minisign", "-S", "-s", sec, "-m", msgFile, "-x", minisigOut, "-c", "redteam s1")
	cmd.Stdin = strings.NewReader("")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("minisign -S: %v\n%s", err, out)
	}
}

// s1ForgeMinisig writes a structurally valid minisign packet whose signer
// key ID is displayFingerprint but whose signature bytes are all zero -- the
// exact shape of Sol's reproduced forged packet. A real minisign -V against
// the genuine public key rejects it (signature verification failed).
func s1ForgeMinisig(t *testing.T, path, displayFingerprint string) {
	t.Helper()
	fpBytes, err := hex.DecodeString(displayFingerprint)
	if err != nil || len(fpBytes) != 8 {
		t.Fatalf("bad fingerprint %q", displayFingerprint)
	}
	keyID := make([]byte, 8)
	for i := range fpBytes {
		keyID[i] = fpBytes[len(fpBytes)-1-i]
	}
	sigblob := append([]byte("Ed"), keyID...)
	sigblob = append(sigblob, make([]byte, 64)...) // 64 zero signature bytes
	global := make([]byte, 64)                     // zero global signature
	content := "untrusted comment: forged redteam\n" +
		base64.StdEncoding.EncodeToString(sigblob) + "\n" +
		"trusted comment: forged redteam\n" +
		base64.StdEncoding.EncodeToString(global) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// s1Policy runs release_policy.py signature with the given args, skipping
// the case if minisign is unavailable (every case needs it to verify).
func s1Policy(t *testing.T, args ...string) (string, error) {
	t.Helper()
	if _, err := exec.LookPath("minisign"); err != nil {
		t.Skip("minisign not on PATH")
	}
	cmd := exec.Command("python3", append([]string{s1PolicyScript(t), "signature"}, args...)...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// s1Stage builds a clean release dist directory with one artifact and a
// checksums.txt over it (written BEFORE the minisig exists, so checksums
// covers only the artifact, exactly like scripts/release.sh), signs
// checksums.txt, and returns the paths plus the signer fingerprint. trustDir
// receives a one-line trust root naming the ephemeral signer; keyDir
// receives the matching pinned .pub, exactly as scripts/release.sh provisions
// them. The secret key is left at <work>/sec.key for cases that need to sign
// a second file.
func s1Stage(t *testing.T) (work, dist, trustFile, keyDir, secKey, checksums, minisig, fingerprint string) {
	t.Helper()
	work = t.TempDir()
	dist = filepath.Join(work, "dist")
	trustFile = filepath.Join(work, "trust.txt")
	keyDir = filepath.Join(work, "keys")
	secKey = filepath.Join(work, "sec.key")
	pub := filepath.Join(work, "pub.key")
	for _, d := range []string{dist, keyDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	s1GenKey(t, secKey, pub)
	fingerprint = s1Fingerprint(t, pub)
	if err := os.WriteFile(trustFile, []byte(fingerprint+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(pub); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(filepath.Join(keyDir, fingerprint+".pub"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(dist, "gov_1.0.0_linux_amd64.tar.gz")
	if err := os.WriteFile(artifact, []byte("release artifact bytes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	checksums = filepath.Join(dist, "checksums.txt")
	s1WriteChecksums(t, checksums, dist)
	minisig = filepath.Join(dist, "checksums.txt.minisig")
	s1Sign(t, secKey, checksums, minisig)
	return work, dist, trustFile, keyDir, secKey, checksums, minisig, fingerprint
}

// s1WriteChecksums writes a sha256sum-style checksums.txt over every regular
// file currently in dir (named by bare basename), reusing the package's
// existing fileSHA256Hex helper.
func s1WriteChecksums(t *testing.T, checksumsPath, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		fmt.Fprintf(&b, "%s  %s\n", fileSHA256Hex(t, filepath.Join(dir, e.Name())), e.Name())
	}
	if err := os.WriteFile(checksumsPath, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
}

// s1CommonArgs returns the baseline production-verification args each case
// mutates: the signer is anchored, its key is pinned, checksums cover the
// single artifact, and the minisign verifier is resolved by absolute path.
func s1CommonArgs(trustFile, keyDir, checksums, minisig string) []string {
	mini, _ := exec.LookPath("minisign")
	return []string{
		"--version", "1.0.0", "--require", "1",
		"--minisig", minisig,
		"--trusted-fingerprints-file", trustFile,
		"--checksums", checksums,
		"--trusted-public-keys-dir", keyDir,
		"--artifacts-dir", filepath.Dir(checksums),
		"--minisign-bin", mini,
	}
}

// Case 1: a forged .minisig carrying the trusted key ID and zero-filled
// signature bytes (Sol's exact reproduction) must be rejected by real
// cryptographic verification.
func TestV11Case1ForgedSignatureWithTrustedKeyIDRejected(t *testing.T) {
	_, dist, trustFile, keyDir, _, checksums, _, fp := s1Stage(t)
	forged := filepath.Join(dist, "forged.minisig")
	s1ForgeMinisig(t, forged, fp)

	out, err := s1Policy(t, s1CommonArgs(trustFile, keyDir, checksums, forged)...)
	if err == nil {
		t.Fatalf("release_policy accepted a forged signature with the trusted key ID; output:\n%s", out)
	}
	if !strings.Contains(out, "cryptographic signature verification FAILED") {
		t.Fatalf("expected cryptographic verification to reject the forged packet, got:\n%s", out)
	}
}

// Case 2: a valid minisign signature, but over a DIFFERENT checksum file
// than the one presented, must be rejected. The bogus minisig lives outside
// dist so the artifacts-dir coverage check cannot mask the signature defect.
func TestV11Case2ValidSignatureOverDifferentChecksumFileRejected(t *testing.T) {
	work, dist, trustFile, keyDir, secKey, checksums, _, _ := s1Stage(t)

	other := filepath.Join(work, "checksums_other.txt")
	if err := os.WriteFile(other, []byte("0000000000000000000000000000000000000000000000000000000000000000  other.txt\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	minisigOther := filepath.Join(work, "checksums_other.txt.minisig")
	s1Sign(t, secKey, other, minisigOther)

	out, err := s1Policy(t, s1CommonArgs(trustFile, keyDir, checksums, minisigOther)...)
	if err == nil {
		t.Fatalf("release_policy accepted a signature over a different checksum file; output:\n%s", out)
	}
	if !strings.Contains(out, "cryptographic signature verification FAILED") {
		t.Fatalf("expected signature-over-wrong-file to fail crypto verification, got:\n%s", out)
	}
	_ = dist
}

// Case 3: a valid signature from a key NOT present in the trust root must
// be refused (the signing key is not anchored).
func TestV11Case3SignatureFromUntrustedKeyRejected(t *testing.T) {
	_, _, trustFile, keyDir, _, checksums, minisig, _ := s1Stage(t)
	if err := os.WriteFile(trustFile, []byte("0000000000000000\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := s1Policy(t, s1CommonArgs(trustFile, keyDir, checksums, minisig)...)
	if err == nil {
		t.Fatalf("release_policy accepted a signature from an untrusted key; output:\n%s", out)
	}
	if !strings.Contains(out, "nonproduction/unknown key") {
		t.Fatalf("expected untrusted-key refusal, got:\n%s", out)
	}
}

// Case 4: a fake minisign binary that writes a syntactic forged packet and
// exits zero (simulating a compromised signing step) is caught two ways --
// (a) the forged packet it would produce is rejected by real verification,
// and (b) a substituted verifier whose hash does not match the pin is
// refused before verification even runs.
func TestV11Case4FakeMinisignBinaryWritesSyntacticPacketRejected(t *testing.T) {
	_, dist, trustFile, keyDir, _, checksums, realMinisig, fp := s1Stage(t)

	// (a) The forged packet a fake signing minisign would emit is rejected.
	forged := filepath.Join(dist, "forged.minisig")
	s1ForgeMinisig(t, forged, fp)
	out, err := s1Policy(t, s1CommonArgs(trustFile, keyDir, checksums, forged)...)
	if err == nil {
		t.Fatalf("release_policy accepted the forged packet a fake minisign produces; output:\n%s", out)
	}
	if !strings.Contains(out, "cryptographic signature verification FAILED") {
		t.Fatalf("expected forged packet rejection, got:\n%s", out)
	}

	// (b) A substituted verifier is refused by hash pinning.
	args := append(s1CommonArgs(trustFile, keyDir, checksums, realMinisig),
		"--minisign-bin-hash", "0000000000000000000000000000000000000000000000000000000000000000")
	out, err = s1Policy(t, args...)
	if err == nil {
		t.Fatalf("release_policy used a verifier whose hash did not match the pin; output:\n%s", out)
	}
	if !strings.Contains(out, "minisign binary hash mismatch") {
		t.Fatalf("expected verifier hash-mismatch refusal, got:\n%s", out)
	}
}

// Case 5: checksums.txt modified AFTER signing must be rejected (the
// signature no longer covers the presented bytes).
func TestV11Case5ChecksumsModifiedAfterSigningRejected(t *testing.T) {
	_, _, trustFile, keyDir, _, checksums, minisig, _ := s1Stage(t)
	backup, err := os.ReadFile(checksums)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(checksums, append(append([]byte{}, backup...), []byte("tampered\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.WriteFile(checksums, backup, 0o644)

	out, err := s1Policy(t, s1CommonArgs(trustFile, keyDir, checksums, minisig)...)
	if err == nil {
		t.Fatalf("release_policy accepted checksums modified after signing; output:\n%s", out)
	}
	if !strings.Contains(out, "cryptographic signature verification FAILED") {
		t.Fatalf("expected crypto failure on modified checksums, got:\n%s", out)
	}
}

// Case 6: an archive modified AFTER checksums were generated (checksums.txt
// unchanged, signature valid) must be rejected by the checksum
// self-consistency check.
func TestV11Case6ArchiveModifiedAfterChecksumGenerationRejected(t *testing.T) {
	_, _, trustFile, keyDir, _, checksums, minisig, _ := s1Stage(t)
	artifact := filepath.Join(filepath.Dir(checksums), "gov_1.0.0_linux_amd64.tar.gz")
	if err := os.WriteFile(artifact, []byte("completely different bytes than what was hashed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out, err := s1Policy(t, s1CommonArgs(trustFile, keyDir, checksums, minisig)...)
	if err == nil {
		t.Fatalf("release_policy accepted an archive modified after checksum generation; output:\n%s", out)
	}
	if !strings.Contains(out, "no longer matches its checksum") {
		t.Fatalf("expected checksum self-consistency failure, got:\n%s", out)
	}
}

// Case 7: the anchored fingerprint has no pinned public key in the release
// toolchain's key directory -> verification cannot proceed and must fail.
func TestV11Case7MissingTrustedPublicKeyRejected(t *testing.T) {
	_, _, trustFile, _, _, checksums, minisig, _ := s1Stage(t)
	emptyKeyDir := filepath.Join(t.TempDir(), "emptykeys")
	if err := os.MkdirAll(emptyKeyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := s1Policy(t, s1CommonArgs(trustFile, emptyKeyDir, checksums, minisig)...)
	if err == nil {
		t.Fatalf("release_policy accepted with no pinned public key for the anchored fingerprint; output:\n%s", out)
	}
	if !strings.Contains(out, "no pinned public key for anchored fingerprint") {
		t.Fatalf("expected missing-pinned-pub refusal, got:\n%s", out)
	}
}

// Case 8: a pinned public key whose own fingerprint does not match the
// anchored signer (a substituted/mislabeled verification key -- correct
// filename, wrong bytes) must be rejected. load_pinned_public_keys keys by
// the fingerprint DERIVED from the .pub bytes, so a mislabeled key is not
// found under the anchored fingerprint.
func TestV11Case8TrustedFingerprintDoesNotMatchVerificationKeyRejected(t *testing.T) {
	_, _, trustFile, keyDir, _, checksums, minisig, anchoredFP := s1Stage(t)

	// Generate an unrelated key and install its bytes under the anchored
	// fingerprint's filename (a substituted verification key).
	work := t.TempDir()
	otherPub := filepath.Join(work, "other.pub")
	s1GenKey(t, filepath.Join(work, "other.key"), otherPub)
	otherFP := s1Fingerprint(t, otherPub)
	if otherFP == anchoredFP {
		t.Fatal("setup invariant failed: unrelated key collided with anchored fingerprint")
	}
	// Remove the legitimate pinned key, then install the wrong bytes under
	// the anchored name.
	if err := os.Remove(filepath.Join(keyDir, anchoredFP+".pub")); err != nil {
		t.Fatal(err)
	}
	if data, err := os.ReadFile(otherPub); err != nil {
		t.Fatal(err)
	} else if err := os.WriteFile(filepath.Join(keyDir, anchoredFP+".pub"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	out, err := s1Policy(t, s1CommonArgs(trustFile, keyDir, checksums, minisig)...)
	if err == nil {
		t.Fatalf("release_policy accepted a verification key whose fingerprint differs from the anchor; output:\n%s", out)
	}
	if !strings.Contains(out, "no pinned public key for anchored fingerprint") {
		t.Fatalf("expected verification-key/anchor mismatch refusal, got:\n%s", out)
	}
}
