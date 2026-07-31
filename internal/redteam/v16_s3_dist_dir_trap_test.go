//go:build redteam

package redteam

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// v16_s3_dist_dir_trap_test.go is v16-release Session 3's corpus (report
// cases 395-397, findings R5 + R6-secondary): the trap rc8 Session 8 left
// armed -- a stale dist/ silently satisfying every release claim -- is
// converted from a manual OUT_DIR workaround into an enforced, named
// fail-closed invariant.
//
//   - scripts/release_policy.py gains dist_version_mismatch (STALE_DIST_ARTIFACTS)
//     shared by check_architecture_doc.py, release_policy.py and
//     audit_bundle_validate.py, plus out_dir_preserves_modes
//     (OUT_DIR_COERCES_FILE_MODES) shared by release.sh and audit_bundle.sh.
//
// R5 root cause: the /mnt/e 9p/drvfs permission-coercion workaround was an
// invocation-time env override with no code change, so the default --dist-dir
// path (dist/) stayed known-wrong on this host but still the default. dist/
// held a deleted failed attempt's output (gov_local-candidate-8044d02_*.tar.gz,
// no build-manifest.json); any next session that forgot the OUT_DIR redirect
// would validate rc8 against it.

// TestV16Case395MismatchedVersionDistDirFailsStaleDistArtifacts is v16-release
// report case 395 (R5): validation against a dist directory holding a different
// release's artifacts must fail with the named STALE_DIST_ARTIFACTS error,
// never a silent pass. Before S3, check_architecture_doc.py --dist-dir returned
// OK against a pending doc without ever looking at dist/'s contents (the
// artifact/manifest checks fired only for release_state: complete). The fix
// runs the stale-dist check whenever a front-matter doc is given a --dist-dir,
// regardless of release_state, binding to the manifest's OWN version (internal
// consistency) -- never to the doc's governator_tag, so a fixture dist whose
// manifest version differs from the doc tag remains a legitimate test shape.
func TestV16Case395MismatchedVersionDistDirFailsStaleDistArtifacts(t *testing.T) {
	writeDoc := func(t *testing.T, tag, state string) string {
		t.Helper()
		doc := filepath.Join(t.TempDir(), "architecture.md")
		s3WriteFrontMatterDoc(t, doc, map[string]string{
			"governator_commit":        "37d263cb3f1c694bbe2855bcbccbf5066084c631",
			"governator_tag":           tag,
			"release_state":            state,
			"artifact_manifest_sha256": "null",
		}, "# Doc\n**Status:** current "+tag+"\n")
		return doc
	}

	t.Run("a dist holding a foreign attempt's archives is rejected by name", func(t *testing.T) {
		// The R5 shape if the deleted 8044d02 attempt HAD written a manifest:
		// build-manifest.json claims 1.0.2-rc8 but the only platform archive
		// present is from the failed candidate. A silent pass here would
		// validate rc8's release claims against a different attempt's output.
		dist := t.TempDir()
		writeJSON(t, filepath.Join(dist, "build-manifest.json"), map[string]any{
			"version":       "1.0.2-rc8",
			"source_commit": "37d263cb3f1c694bbe2855bcbccbf5066084c631",
		})
		foreign := filepath.Join(dist, "gov_local-candidate-8044d025e62f_linux_amd64.tar.gz")
		if err := os.WriteFile(foreign, []byte("stale candidate archive\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		doc := writeDoc(t, "v1.0.2-rc8", "pending")
		out, err := s3RunCheckArchitectureDoc(t, doc, "--dist-dir", dist)
		if err == nil {
			t.Fatalf("expected check_architecture_doc to reject a dist with foreign archives, got success:\n%s", out)
		}
		if !strings.Contains(out, "STALE_DIST_ARTIFACTS") {
			t.Fatalf("expected the named STALE_DIST_ARTIFACTS error, got:\n%s", out)
		}
		if !strings.Contains(out, "gov_local-candidate-8044d025e62f_linux_amd64.tar.gz") {
			t.Fatalf("expected the failure to name the foreign archive, got:\n%s", out)
		}
	})

	t.Run("a dist with no build-manifest.json is rejected (the exact rc8 dist/ shape)", func(t *testing.T) {
		// S0's R5 reproduction: dist/ held the deleted 8044d02 attempt's
		// archives with NO manifest (cut before that stage). Before S3 this
		// invocation returned OK silently because release_state was pending
		// and the manifest check never ran -- the latent trap.
		dist := t.TempDir()
		if err := os.WriteFile(
			filepath.Join(dist, "gov_local-candidate-8044d025e62f_linux_amd64.tar.gz"),
			[]byte("stale\n"), 0o644,
		); err != nil {
			t.Fatal(err)
		}
		doc := writeDoc(t, "v1.0.2-rc8", "pending")
		out, err := s3RunCheckArchitectureDoc(t, doc, "--dist-dir", dist)
		if err == nil {
			t.Fatalf("expected check_architecture_doc to reject a manifest-less dist, got success:\n%s", out)
		}
		if !strings.Contains(out, "STALE_DIST_ARTIFACTS") || !strings.Contains(out, "build-manifest.json") {
			t.Fatalf("expected STALE_DIST_ARTIFACTS naming the absent build-manifest.json, got:\n%s", out)
		}
	})

	t.Run("a self-consistent dist passes (the both-directions positive control)", func(t *testing.T) {
		// The mirror of the two rejections above: a dist whose archives agree
		// with its manifest's declared version passes. This proves the check
		// is detecting staleness, not merely the presence of a --dist-dir.
		dist := t.TempDir()
		writeJSON(t, filepath.Join(dist, "build-manifest.json"), map[string]any{
			"version":       "1.0.2-rc8",
			"source_commit": "37d263cb3f1c694bbe2855bcbccbf5066084c631",
		})
		if err := os.WriteFile(
			filepath.Join(dist, "gov_1.0.2-rc8_linux_amd64.tar.gz"),
			[]byte("real rc8 archive\n"), 0o644,
		); err != nil {
			t.Fatal(err)
		}
		doc := writeDoc(t, "v1.0.2-rc8", "pending")
		if out, err := s3RunCheckArchitectureDoc(t, doc, "--dist-dir", dist); err != nil {
			t.Fatalf("expected a self-consistent dist to pass, got error: %v\n%s", err, out)
		}
	})
}

// TestV16Case396ModeCoercingOutDirFailsBeforeAnyArtifact is v16-release report
// case 396 (R5): a mode-coercing OUT_DIR (9p/drvfs, e.g. /mnt/e, which rewrites
// every extracted mode to 0777) must fail the probe BEFORE any artifact is
// written, with the named OUT_DIR_COERCES_FILE_MODES error. rc8 Session 8
// applied the OUT_DIR redirect as a manual env override; S3 converts it into an
// enforced invariant. The probe is behavioural (chmod a probe dir 0500, read
// the mode back) and never hardcodes a path -- the plan's explicit requirement.
func TestV16Case396ModeCoercingOutDirFailsBeforeAnyArtifact(t *testing.T) {
	probeScript := s7Script(t, "release_policy.py")
	scriptsDir := filepath.Dir(probeScript)

	t.Run("a filesystem whose chmod is a no-op fails the probe", func(t *testing.T) {
		// Simulate the exact 9p/drvfs fault (/mnt/e rewrites every mode to
		// 0777): neutralize os.chmod so the 0500 probe directory never has its
		// mode changed, then read it back. On a real drvfs mount the read-back
		// is 0777; under this fault injection it is whatever mkdtemp created
		// (~0700) -- either way != 0500, which is the property being detected.
		// This is fault injection of the host behaviour the probe exists to
		// catch, NOT a faked attestation (standing rule 12): the probe still
		// observes the real read-back mode and decides from it.
		dist := t.TempDir()
		// The program takes the scripts dir and the dist dir as argv so no
		// Go-side interpolation is needed (the python body uses %-formatting
		// of its own, which must not collide with fmt.Sprintf verbs).
		prog := `
import os, sys
sys.path.insert(0, sys.argv[1])
import release_policy
release_policy.os.chmod = lambda *a, **k: None  # simulate 9p/drvfs mode coercion
ok, mode, msg = release_policy.out_dir_preserves_modes(sys.argv[2])
sys.stdout.write("ok=" + repr(ok) + " mode=%o\n" % mode)
if msg:
    sys.stderr.write(msg + "\n")
sys.exit(0 if ok else 2)
`
		cmd := exec.Command("python3", "-c", prog, scriptsDir, dist)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Fatalf("expected the probe to fail when chmod is a no-op, but it passed:\n%s", out)
		}
		combined := string(out)
		if !strings.Contains(combined, "ok=False") {
			t.Fatalf("expected out_dir_preserves_modes to report preserves=False, got:\n%s", combined)
		}
		if !strings.Contains(combined, "OUT_DIR_COERCES_FILE_MODES") {
			t.Fatalf("expected the named OUT_DIR_COERCES_FILE_MODES error, got:\n%s", combined)
		}
	})

	t.Run("release.sh and audit_bundle.sh both wire the probe", func(t *testing.T) {
		// The probe must actually be invoked at both release entry points,
		// not merely defined in release_policy.py. A future edit that drops
		// the call would otherwise re-arm the trap with no test failing.
		repoRoot := filepath.Join(scriptsDir, "..")
		for _, rel := range []string{"scripts/release.sh", "scripts/audit_bundle.sh"} {
			path := filepath.Join(repoRoot, rel)
			body, rerr := os.ReadFile(path)
			if rerr != nil {
				t.Fatalf("read %s: %v", rel, rerr)
			}
			if !strings.Contains(string(body), "out-dir-mode-probe") {
				t.Fatalf("%s does not invoke the out-dir-mode-probe -- the probe is defined but not wired", rel)
			}
			if !strings.Contains(string(body), "OUT_DIR_COERCES_FILE_MODES") {
				t.Fatalf("%s does not surface the OUT_DIR_COERCES_FILE_MODES context -- a coerced OUT_DIR would not be named", rel)
			}
		}
	})
}

// TestV16Case397ModeProbeDoesNotFalsePositiveOnNativeFilesystem is v16-release
// report case 397 (R5): the both-directions mirror of 396. The mode-coercion
// probe must NOT false-positive on a normal ext4/tmpfs OUT_DIR (the actual
// release target, e.g. /home/lam/governator-release-dist), or it would block
// every legitimate release. This runs the REAL release_policy.py CLI against a
// Go test tempdir (which lives on the host's native filesystem) and expects it
// to pass -- proving the probe keys off observed mode behaviour, not off a
// hardcoded refusal.
func TestV16Case397ModeProbeDoesNotFalsePositiveOnNativeFilesystem(t *testing.T) {
	probeScript := s7Script(t, "release_policy.py")
	native := t.TempDir()

	cmd := exec.Command("python3", probeScript, "out-dir-mode-probe", "--dist-dir", native)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("expected the probe to pass on a native filesystem (%s) with no false positive, got error: %v\n%s", native, err, out)
	}
	// A passing probe is silent (no named error) -- any STALE/COERCE diagnostic
	// here would itself be the false positive this case exists to catch.
	if strings.Contains(string(out), "OUT_DIR_COERCES_FILE_MODES") {
		t.Fatalf("the probe false-posititived on a native filesystem, reporting coercion:\n%s", out)
	}
}
