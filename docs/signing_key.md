# Production signing key: generation, publication, rotation, revocation

P1-5 (Sol10 rc4 Session 8): "a public key shipped only beside its own
signature proves nothing." This document is the procedure for anchoring a
real trust root before Governator ships its first signed production
release.

**The permanent production signing key was generated and anchored on
2026-07-22** (rc4 Session 8 close-out, Jeremy's explicit authorization).
Fingerprint `B5CBEE8BBA8826A7`, published out-of-band in
`agents/governator-signing-key-fingerprint.txt` and mirrored to VPS
`monpaga@216.158.228.204:~/governator-signing-key-fingerprint.txt`.
rc4 is the first release signed by this key. The procedure below remains
authoritative for all future rotations and revocations.

## 1. Generate the key

```
minisign -G -W -s <secure, offline location>/governator-release.key -p governator-release.pub
```

`-W` skips the interactive password prompt only when explicitly requested —
prefer an encrypted secret key (omit `-W`) stored offline; `scripts/release.sh`
reads an unencrypted key path via `GOV_RELEASE_MINISIGN_KEY` only in a
non-interactive CI signing step, never as the long-term custody form.

## 2. Record the fingerprint

`minisign -G`'s own output prints the public key's comment line:
`minisign public key <16-hex-char fingerprint>`. That fingerprint —
not the key file itself — is what gets published and cross-checked.

## 3. Publish out-of-band

The fingerprint must be published through a channel independent of this
repository and independent of any release artifact: e.g. a signed
announcement on a separate platform the maintainer controls, cross-posted
in at least one place a compromised release pipeline could not also
control. `docs/publishing.md` already tells verifiers never to trust a key
or fingerprint bundled inside the release itself — this step is what makes
that instruction possible to follow.

## 4. Anchor it in the repo

Only after step 3, add the fingerprint (and only the fingerprint — never
the secret key) to `docs/TRUSTED_SIGNING_KEYS.txt`, AND pin the matching
public key at `docs/signing_keys/<FINGERPRINT>.pub` (as of rc5, Sol11 P0-1).
A key ID alone cannot verify a signature, so the release toolchain keeps its
own pinned copy of the Ed25519 verification public key here; its fingerprint
must equal an entry in `docs/TRUSTED_SIGNING_KEYS.txt` (the out-of-band
anchor), and it is never discovered beside a release or via PATH lookup.
From that commit forward, `scripts/release_policy.py signature` (wired into
`scripts/release.sh`) refuses any `REQUIRE_ASYMMETRIC_SIGNATURE=1` release
whose `checksums.txt.minisig` was not signed by an anchored key, AND
cryptographically verifies (`minisign -V`) the signature over the exact
`checksums.txt` bytes using that pinned public key — so a forged packet
carrying a trusted key ID, a signature over a different file, or checksums
modified after signing is rejected. See `internal/redteam`'s
`TestV10Case40ReleaseSignedWithNonproductionUnknownKeyFailsRelease` (rc4,
unanchored-key refusal) and the `TestV11Case1`..`TestV11Case8` corpus
(rc5, cryptographic-verification refusals), all run against ephemeral,
non-production test key pairs.

## 5. Sign releases

Set `GOV_RELEASE_MINISIGN_KEY` to the (unencrypted, CI-only) secret key
path when running `scripts/release.sh` for a real release. The signer
fingerprint is recorded in `test-summary.json`/`build-manifest.json`
alongside the release's other identity fields — that is "recording the
signer fingerprint in release metadata," the last item P1-5 asks for.

## 6. Rotation

Generate a new key pair (steps 1–2), publish the new fingerprint through
the same out-of-band channel used for the original (step 3), and add it to
`docs/TRUSTED_SIGNING_KEYS.txt` as an additional line **before** the old
key stops signing releases — there must be no gap where a release is
signed by a key not yet anchored. Once every release signed by the old key
is out of active support, remove its fingerprint from
`docs/TRUSTED_SIGNING_KEYS.txt` (revocation) and publish that removal
through the same out-of-band channel, so a verifier checking an old
archive learns the key is no longer trusted going forward without losing
the ability to verify archives it legitimately signed at the time.

## 7. Revocation (compromise)

If the secret key is ever suspected compromised: remove its fingerprint
from `docs/TRUSTED_SIGNING_KEYS.txt` immediately, publish the revocation
out-of-band with the reason and the last known-good release it legitimately
signed, and follow the rotation procedure above for the replacement key.
Do not wait for a scheduled rotation.
