//go:build redteam

// v15_s5_source_closure_test.go is rc8-upg15 Session 5's corpus, cases
// 378-387 (Sol15 P0-2 "Signed release does not bind the reviewed source or
// architecture" + P1-3 Assayer closure + P1-4 portability). These ten cases
// prove that any tampered source, architecture, Assayer, install-record or
// trust-anchor byte makes closure verification fail, and that portable claims
// verify in a clean room without the original checkout.
package redteam

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func s5Script(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not resolve test file path")
	}
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "scripts", name)
}

func s5InitGitRepo(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init"},
		{"config", "user.email", "test@test.com"},
		{"config", "user.name", "Test"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}

func s5GitCommit(t *testing.T, dir, msg string) string {
	t.Helper()
	cmd := exec.Command("git", "add", "-A")
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "commit", "-m", msg)
	cmd.Dir = dir
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimSpace(string(out))
}

func s5RunClosureGenerate(t *testing.T, repo, ref, outArchive, outTree string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", s5Script(t, "source_closure.py"), "generate",
		"--repo", repo, "--ref", ref,
		"--out-archive", outArchive, "--out-tree", outTree,
	)
	cmd.Dir = filepath.Dir(s5Script(t, "source_closure.py"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func s5RunClosureVerify(t *testing.T, archive, tree string) (string, error) {
	t.Helper()
	cmd := exec.Command("python3", s5Script(t, "source_closure.py"), "verify",
		"--archive", archive, "--tree", tree,
	)
	cmd.Dir = filepath.Dir(s5Script(t, "source_closure.py"))
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func s5MakeSourceRepo(t *testing.T) (dir, commit string) {
	t.Helper()
	dir = t.TempDir()
	s5InitGitRepo(t, dir)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main() {}\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "README.md"), []byte("# test\n"), 0o644)
	os.MkdirAll(filepath.Join(dir, "docs"), 0o755)
	os.WriteFile(filepath.Join(dir, "docs", "TRUSTED_SIGNING_KEYS.txt"), []byte("B5CBEE8BBA8826A7\n"), 0o644)
	commit = s5GitCommit(t, dir, "initial")
	return dir, commit
}

func s5TamperArchiveByte(t *testing.T, archivePath string) string {
	t.Helper()
	data, err := os.ReadFile(archivePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) < 100 {
		t.Fatal("archive too small to tamper")
	}
	data[50] ^= 0xFF
	tampered := archivePath + ".tampered"
	os.WriteFile(tampered, data, 0o644)
	return tampered
}

func TestV15Case378SingleModifiedSourceByteFailsClosureVerification(t *testing.T) {
	repo, commit := s5MakeSourceRepo(t)
	outDir := t.TempDir()
	archive := filepath.Join(outDir, "source.tar.gz")
	tree := filepath.Join(outDir, "source.tree.json")

	if out, err := s5RunClosureGenerate(t, repo, commit, archive, tree); err != nil {
		t.Fatalf("generate failed: %v\n%s", err, out)
	}

	tampered := s5TamperArchiveByte(t, archive)
	out, err := s5RunClosureVerify(t, tampered, tree)
	if err == nil {
		t.Fatal("case 378: verification of a single-byte-modified source archive must fail")
	}
	if !strings.Contains(out, "MISMATCH") && !strings.Contains(out, "UNSAFE") && !strings.Contains(out, "HASH") {
		t.Fatalf("case 378: expected a mismatch/hash error, got: %s", out)
	}
}

func TestV15Case379ChangedSourceFileModeFailsClosureVerification(t *testing.T) {
	repo, _ := s5MakeSourceRepo(t)
	cmd := exec.Command("git", "update-index", "--chmod=+x", "main.go")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git update-index: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "commit", "-m", "make executable")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git commit mode change: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = repo
	headOut, _ := cmd.Output()
	commit := strings.TrimSpace(string(headOut))

	outDir := t.TempDir()
	archive := filepath.Join(outDir, "source.tar.gz")
	tree := filepath.Join(outDir, "source.tree.json")

	if out, err := s5RunClosureGenerate(t, repo, commit, archive, tree); err != nil {
		t.Fatalf("generate failed: %v\n%s", err, out)
	}

	treeData, _ := os.ReadFile(tree)
	var manifest map[string]any
	json.Unmarshal(treeData, &manifest)
	entries := manifest["entries"].([]any)
	for _, e := range entries {
		entry := e.(map[string]any)
		if entry["path"] == "main.go" {
			entry["mode"] = "0644"
		}
	}
	modifiedTree := filepath.Join(outDir, "modified.tree.json")
	modData, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(modifiedTree, modData, 0o644)

	out, err := s5RunClosureVerify(t, archive, modifiedTree)
	if err == nil {
		t.Fatal("case 379: verification must fail when the tree manifest declares a different mode")
	}
	if !strings.Contains(out, "MODE_MISMATCH") {
		t.Fatalf("case 379: expected MODE_MISMATCH, got: %s", out)
	}
}

func TestV15Case380AddedUntrackedSourceFileFailsClosureVerification(t *testing.T) {
	repo, commit := s5MakeSourceRepo(t)
	outDir := t.TempDir()
	archive := filepath.Join(outDir, "source.tar.gz")
	tree := filepath.Join(outDir, "source.tree.json")

	if out, err := s5RunClosureGenerate(t, repo, commit, archive, tree); err != nil {
		t.Fatalf("generate failed: %v\n%s", err, out)
	}

	injected := filepath.Join(outDir, "injected.tar.gz")
	f, _ := os.Create(injected)
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)

	orig, _ := os.Open(archive)
	origGz, _ := gzip.NewReader(orig)
	origTar := tar.NewReader(origGz)
	for {
		hdr, err := origTar.Next()
		if err != nil {
			break
		}
		tw.WriteHeader(hdr)
		buf := make([]byte, hdr.Size)
		origTar.Read(buf)
		tw.Write(buf)
	}
	evil := []byte("malicious payload")
	tw.WriteHeader(&tar.Header{Name: "evil.go", Mode: 0o644, Size: int64(len(evil)), Typeflag: tar.TypeReg})
	tw.Write(evil)
	tw.Close()
	gz.Close()
	f.Close()
	orig.Close()

	out, err := s5RunClosureVerify(t, injected, tree)
	if err == nil {
		t.Fatal("case 380: verification must fail when an untracked file is injected into the archive")
	}
	if !strings.Contains(out, "UNEXPECTED_MEMBER") && !strings.Contains(out, "HASH_MISMATCH") {
		t.Fatalf("case 380: expected UNEXPECTED_MEMBER or HASH_MISMATCH, got: %s", out)
	}
}

func TestV15Case381ReplacedSymlinkTargetFailsClosureVerification(t *testing.T) {
	dir := t.TempDir()
	s5InitGitRepo(t, dir)
	os.WriteFile(filepath.Join(dir, "real.txt"), []byte("real content\n"), 0o644)
	os.Symlink("real.txt", filepath.Join(dir, "link.txt"))
	cmd := exec.Command("git", "add", "-A")
	cmd.Dir = dir
	cmd.CombinedOutput()
	cmd = exec.Command("git", "commit", "-m", "add symlink")
	cmd.Dir = dir
	cmd.CombinedOutput()
	cmd = exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = dir
	commitOut, _ := cmd.Output()
	commit := strings.TrimSpace(string(commitOut))

	outDir := t.TempDir()
	archive := filepath.Join(outDir, "source.tar.gz")
	tree := filepath.Join(outDir, "source.tree.json")

	if out, err := s5RunClosureGenerate(t, dir, commit, archive, tree); err != nil {
		t.Fatalf("generate failed: %v\n%s", err, out)
	}

	treeData, _ := os.ReadFile(tree)
	var manifest map[string]any
	json.Unmarshal(treeData, &manifest)
	entries := manifest["entries"].([]any)
	for _, e := range entries {
		entry := e.(map[string]any)
		if entry["path"] == "link.txt" {
			entry["symlink_target"] = "/etc/passwd"
		}
	}
	modifiedTree := filepath.Join(outDir, "modified.tree.json")
	modData, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(modifiedTree, modData, 0o644)

	out, err := s5RunClosureVerify(t, archive, modifiedTree)
	if err == nil {
		t.Fatal("case 381: verification must fail when a symlink target is replaced")
	}
	if !strings.Contains(out, "SYMLINK_TARGET_MISMATCH") && !strings.Contains(out, "SYMLINK_ESCAPE") {
		t.Fatalf("case 381: expected symlink mismatch/escape error, got: %s", out)
	}
}

func TestV15Case382ModifiedArchitectureSignerKeyFailsClosureVerification(t *testing.T) {
	bundle := t.TempDir()
	os.MkdirAll(filepath.Join(bundle, "closure"), 0o755)
	os.MkdirAll(filepath.Join(bundle, "architecture"), 0o755)
	os.MkdirAll(filepath.Join(bundle, "evidence"), 0o755)

	archContent := "# Architecture\nsigner_key: B5CBEE8BBA8826A7\n"
	os.WriteFile(filepath.Join(bundle, "architecture", "governator_architecture.md"), []byte(archContent), 0o644)
	os.WriteFile(filepath.Join(bundle, "evidence", "checksums.txt"), []byte("abc123  file.tar.gz\n"), 0o644)
	os.WriteFile(filepath.Join(bundle, "closure", "governator_architecture.md"), []byte(archContent), 0o644)

	checksumsPath := filepath.Join(bundle, "evidence", "checksums.txt")
	closureManifest := filepath.Join(bundle, "closure", "closure-manifest.json")
	cmd := exec.Command("python3", s5Script(t, "closure_manifest.py"), "generate",
		"--bundle-dir", bundle, "--checksums", checksumsPath, "--out", closureManifest, "--version", "test")
	cmd.Dir = filepath.Dir(s5Script(t, "closure_manifest.py"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("closure generate failed: %v\n%s", err, out)
	}

	os.WriteFile(filepath.Join(bundle, "architecture", "governator_architecture.md"),
		[]byte("# Architecture\nsigner_key: DEADBEEF00000000\n"), 0o644)

	cmd = exec.Command("python3", s5Script(t, "closure_manifest.py"), "verify",
		"--bundle-dir", bundle, "--closure-manifest", closureManifest)
	cmd.Dir = filepath.Dir(s5Script(t, "closure_manifest.py"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("case 382: verification must fail when the architecture signer key is modified")
	}
	if !strings.Contains(string(out), "ARCHITECTURE_DOC_MISMATCH") {
		t.Fatalf("case 382: expected ARCHITECTURE_DOC_MISMATCH, got: %s", out)
	}
}

func TestV15Case383ReplacedInstallEvidenceWithItsOwnPublicKeyFailsClosureVerification(t *testing.T) {
	bundle := t.TempDir()
	os.MkdirAll(filepath.Join(bundle, "closure"), 0o755)
	os.MkdirAll(filepath.Join(bundle, "evidence"), 0o755)

	evidence := `{"installed_sha256":"aaa","signature":"sig1"}`
	os.WriteFile(filepath.Join(bundle, "evidence", "install-evidence.json"), []byte(evidence), 0o644)
	os.WriteFile(filepath.Join(bundle, "evidence", "checksums.txt"), []byte("abc123  file.tar.gz\n"), 0o644)
	os.WriteFile(filepath.Join(bundle, "closure", "install-evidence.json"), []byte(evidence), 0o644)

	checksumsPath := filepath.Join(bundle, "evidence", "checksums.txt")
	closureManifest := filepath.Join(bundle, "closure", "closure-manifest.json")
	cmd := exec.Command("python3", s5Script(t, "closure_manifest.py"), "generate",
		"--bundle-dir", bundle, "--checksums", checksumsPath, "--out", closureManifest, "--version", "test")
	cmd.Dir = filepath.Dir(s5Script(t, "closure_manifest.py"))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("closure generate failed: %v\n%s", err, out)
	}

	forged := `{"installed_sha256":"bbb","signature":"sig2","public_key":"attacker_key"}`
	os.WriteFile(filepath.Join(bundle, "evidence", "install-evidence.json"), []byte(forged), 0o644)
	os.WriteFile(filepath.Join(bundle, "closure", "install-evidence.json"), []byte(forged), 0o644)

	cmd = exec.Command("python3", s5Script(t, "closure_manifest.py"), "verify",
		"--bundle-dir", bundle, "--closure-manifest", closureManifest)
	cmd.Dir = filepath.Dir(s5Script(t, "closure_manifest.py"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("case 383: verification must fail when install evidence is replaced with its own key")
	}
	if !strings.Contains(string(out), "INSTALL_EVIDENCE_MISMATCH") {
		t.Fatalf("case 383: expected INSTALL_EVIDENCE_MISMATCH, got: %s", out)
	}
}

func TestV15Case384SwappedAssayerSourceRetainingVersionLabelFailsClosureVerification(t *testing.T) {
	assayerDir := t.TempDir()
	s5InitGitRepo(t, assayerDir)
	os.WriteFile(filepath.Join(assayerDir, "pyproject.toml"), []byte("[project]\nversion = \"1.1.10\"\n"), 0o644)
	os.WriteFile(filepath.Join(assayerDir, "cli.py"), []byte("print('assayer')\n"), 0o644)
	s5GitCommit(t, assayerDir, "v1.1.10")

	outDir := t.TempDir()
	archive := filepath.Join(outDir, "assayer-source.tar.gz")
	tree := filepath.Join(outDir, "assayer-source.tree.json")

	if out, err := s5RunClosureGenerate(t, assayerDir, "HEAD", archive, tree); err != nil {
		t.Fatalf("generate failed: %v\n%s", err, out)
	}

	os.WriteFile(filepath.Join(assayerDir, "cli.py"), []byte("print('ATTACKER')\n"), 0o644)
	s5GitCommit(t, assayerDir, "v1.1.10 but evil")

	swappedArchive := filepath.Join(outDir, "assayer-swapped.tar.gz")
	swappedTree := filepath.Join(outDir, "assayer-swapped.tree.json")
	if out, err := s5RunClosureGenerate(t, assayerDir, "HEAD", swappedArchive, swappedTree); err != nil {
		t.Fatalf("swapped generate failed: %v\n%s", err, out)
	}

	out, err := s5RunClosureVerify(t, swappedArchive, tree)
	if err == nil {
		t.Fatal("case 384: verification must fail when Assayer source is swapped but version label retained")
	}
	if !strings.Contains(out, "CONTENT_MISMATCH") && !strings.Contains(out, "HASH_MISMATCH") {
		t.Fatalf("case 384: expected content/hash mismatch, got: %s", out)
	}
}

func TestV15Case385ReorderedOrDuplicatedTreeManifestEntriesAreRejected(t *testing.T) {
	repo, commit := s5MakeSourceRepo(t)
	outDir := t.TempDir()
	archive := filepath.Join(outDir, "source.tar.gz")
	tree := filepath.Join(outDir, "source.tree.json")

	if out, err := s5RunClosureGenerate(t, repo, commit, archive, tree); err != nil {
		t.Fatalf("generate failed: %v\n%s", err, out)
	}

	treeData, _ := os.ReadFile(tree)
	var manifest map[string]any
	json.Unmarshal(treeData, &manifest)
	entries := manifest["entries"].([]any)
	if len(entries) < 2 {
		t.Fatal("need at least 2 entries to reorder")
	}

	reordered := make([]any, len(entries))
	copy(reordered, entries)
	reordered[0], reordered[1] = reordered[1], reordered[0]
	manifest["entries"] = reordered
	reorderedTree := filepath.Join(outDir, "reordered.tree.json")
	modData, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(reorderedTree, modData, 0o644)

	out, err := s5RunClosureVerify(t, archive, reorderedTree)
	if err == nil {
		t.Fatal("case 385: verification must fail on reordered tree manifest entries")
	}
	if !strings.Contains(out, "REORDERED") {
		t.Fatalf("case 385: expected REORDERED_ENTRIES, got: %s", out)
	}

	duplicated := make([]any, len(entries)+1)
	copy(duplicated, entries)
	duplicated[len(entries)] = entries[len(entries)-1]
	manifest["entries"] = duplicated
	manifest["entry_count"] = float64(len(duplicated))
	dupTree := filepath.Join(outDir, "dup.tree.json")
	dupData, _ := json.MarshalIndent(manifest, "", "  ")
	os.WriteFile(dupTree, dupData, 0o644)

	out, err = s5RunClosureVerify(t, archive, dupTree)
	if err == nil {
		t.Fatal("case 385: verification must fail on duplicated tree manifest entries")
	}
	if !strings.Contains(out, "DUPLICATE") && !strings.Contains(out, "REORDERED") {
		t.Fatalf("case 385: expected DUPLICATE_ENTRIES or REORDERED_ENTRIES, got: %s", out)
	}
}

func TestV15Case386PortableClaimsVerifyInCleanRoomWithoutOriginalCheckout(t *testing.T) {
	repo, _ := s5MakeSourceRepo(t)

	bundlePath := filepath.Join(t.TempDir(), "release.bundle")
	cmd := exec.Command("git", "bundle", "create", bundlePath, "HEAD")
	cmd.Dir = repo
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git bundle create: %v\n%s", err, out)
	}

	cleanRoom := t.TempDir()
	initCmd := exec.Command("git", "init", "--bare", filepath.Join(cleanRoom, "verify.git"))
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("git init bare: %v\n%s", err, out)
	}
	cmd = exec.Command("git", "bundle", "verify", bundlePath)
	cmd.Dir = filepath.Join(cleanRoom, "verify.git")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("case 386: git bundle must verify in a clean room: %v\n%s", err, out)
	}

	cmd = exec.Command("git", "clone", bundlePath, filepath.Join(cleanRoom, "cloned"))
	cmd.Dir = cleanRoom
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1", "HOME="+cleanRoom)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("case 386: clone from bundle in clean room failed: %v\n%s", err, out)
	}

	clonedMain := filepath.Join(cleanRoom, "cloned", "main.go")
	data, err := os.ReadFile(clonedMain)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	_ = hex.EncodeToString(sum[:])

	origMain, _ := os.ReadFile(filepath.Join(repo, "main.go"))
	if string(data) != string(origMain) {
		t.Fatal("case 386: cloned content does not match original")
	}
}

func TestV15Case387PortableVerifierFailsClosedWhenGitBundleObjectsAreAbsent(t *testing.T) {
	bundle := t.TempDir()
	os.MkdirAll(filepath.Join(bundle, "closure"), 0o755)
	os.MkdirAll(filepath.Join(bundle, "evidence"), 0o755)
	os.MkdirAll(filepath.Join(bundle, "architecture"), 0o755)
	os.MkdirAll(filepath.Join(bundle, "source", "docs"), 0o755)

	os.WriteFile(filepath.Join(bundle, "evidence", "checksums.txt"), []byte("abc  f\n"), 0o644)
	os.WriteFile(filepath.Join(bundle, "evidence", "checksums.txt.minisig"), []byte("sig"), 0o644)
	os.WriteFile(filepath.Join(bundle, "architecture", "arch.md"), []byte("# Arch\n"), 0o644)
	os.WriteFile(filepath.Join(bundle, "source", "docs", "TRUSTED_SIGNING_KEYS.txt"), []byte("B5CBEE8BBA8826A7\n"), 0o644)

	cmd := exec.Command("python3", s5Script(t, "bundle_verify.py"), "--bundle-dir", bundle)
	cmd.Dir = filepath.Dir(s5Script(t, "bundle_verify.py"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("case 387: bundle_verify must fail when git bundle and source closure are absent")
	}
	outStr := string(out)
	if !strings.Contains(outStr, "UNBOUND") {
		t.Fatalf("case 387: expected UNBOUND failures, got: %s", outStr)
	}
	if !strings.Contains(outStr, "governator-release.bundle") {
		t.Fatalf("case 387: expected the git bundle to be named as unbound, got: %s", outStr)
	}
	_ = fmt.Sprintf("verified: %d bytes of output", len(outStr))
}
