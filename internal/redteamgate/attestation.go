package redteamgate

import (
	"crypto/ed25519"
	"crypto/sha256"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	AttestationCategoryCore           = "core"
	AttestationCategorySystemdEnabled = "systemd-enabled"
	AttestationCategoryDockerEnabled  = "docker-enabled"
	AttestationCategoryFallbackHost   = "fallback-path"
	AttestationCategoryDarwin         = "darwin"
	defaultAttestationMaxAge          = 24 * time.Hour
)

var RequiredAttestationCategories = []string{
	AttestationCategoryCore,
	AttestationCategorySystemdEnabled,
	AttestationCategoryDockerEnabled,
	AttestationCategoryFallbackHost,
	AttestationCategoryDarwin,
}

// CapabilityAttestation is host-signed evidence for one actual red-team run.
// The detached log is stored next to its JSON file as <attestation>.json.log.
// Keeping the log bytes with the signed record lets a verifier check both the
// signature and that the claimed pass/skip/fail sets are not merely assertions.
type CapabilityAttestation struct {
	AttestationID              string                      `json:"attestation_id"`
	Category                   string                      `json:"category"`
	HostIdentity               string                      `json:"host_identity"`
	Platform                   string                      `json:"platform"`
	Kernel                     string                      `json:"kernel"`
	Capabilities               map[string]CapabilityRecord `json:"capabilities"`
	ProbeImplementationVersion string                      `json:"probe_implementation_version"`
	GovernatorCommit           string                      `json:"governator_commit"`
	AssayerCommit              string                      `json:"assayer_commit"`
	ReleaseVersion             string                      `json:"release_version"`
	TestSourceHash             string                      `json:"test_source_hash"`
	TestBinarySHA256           string                      `json:"test_binary_sha256"`
	ToolchainHash              string                      `json:"toolchain_hash"`
	TestCommand                []string                    `json:"test_command"`
	PassedTests                []string                    `json:"passed_tests"`
	SkippedTests               []string                    `json:"skipped_tests"`
	FailedTests                []string                    `json:"failed_tests"`
	RawLogSHA256               string                      `json:"raw_log_sha256"`
	StartedAt                  string                      `json:"started_at"`
	CompletedAt                string                      `json:"completed_at"`
	SigningKeyID               string                      `json:"signing_key_id"`
	Signature                  string                      `json:"signature"`
	NonApproving               bool                        `json:"non_approving,omitempty"`

	verified bool
}

// AttestationBinding is the release identity an attestation must describe.
// The gate receives this independently from the evidence it is verifying;
// attestations for a different release cannot establish their own target.
type AttestationBinding struct {
	GovernatorCommit string
	AssayerCommit    string
	ReleaseVersion   string
	TestSourceHash   string
	TestBinarySHA256 string
	ToolchainHash    string
}

// TrustedAttestationSigner is a release-reviewed public signer. Categories
// limits the key to the capability hosts it is authorized to attest for.
type TrustedAttestationSigner struct {
	KeyID      string   `json:"key_id"`
	PublicKey  string   `json:"public_key"`
	Categories []string `json:"categories"`
}

type TrustedSignerRegistry struct {
	Signers []TrustedAttestationSigner `json:"signers"`
}

//go:embed trusted_attestation_signers.json
var defaultTrustedSignerRegistryJSON []byte

func DefaultTrustedSignerRegistry() (TrustedSignerRegistry, error) {
	return ParseTrustedSignerRegistry(defaultTrustedSignerRegistryJSON)
}

func ParseTrustedSignerRegistry(data []byte) (TrustedSignerRegistry, error) {
	var registry TrustedSignerRegistry
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&registry); err != nil {
		return TrustedSignerRegistry{}, fmt.Errorf("attestation signer registry: %w", err)
	}
	for _, signer := range registry.Signers {
		publicKey, err := hex.DecodeString(signer.PublicKey)
		if signer.KeyID == "" || err != nil || len(publicKey) != ed25519.PublicKeySize || SigningKeyID(ed25519.PublicKey(publicKey)) != signer.KeyID || len(signer.Categories) == 0 {
			return TrustedSignerRegistry{}, fmt.Errorf("attestation signer registry has invalid signer %q", signer.KeyID)
		}
	}
	return registry, nil
}

func LoadTrustedSignerRegistry(path string) (TrustedSignerRegistry, error) {
	if path == "" {
		return DefaultTrustedSignerRegistry()
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return TrustedSignerRegistry{}, err
	}
	return ParseTrustedSignerRegistry(data)
}

// AttestationVerificationOptions contains verifier-owned values. Defaults are
// intentionally not used by the release command: it must supply its own
// expected binding and release time rather than trust evidence-provided values.
type AttestationVerificationOptions struct {
	TrustRegistry   TrustedSignerRegistry
	ExpectedBinding *AttestationBinding
	ReleaseTime     time.Time
	MaxAge          time.Duration
}

func CanonicalAttestationPayload(a CapabilityAttestation) ([]byte, error) {
	payload := map[string]any{
		"attestation_id":               a.AttestationID,
		"category":                     a.Category,
		"host_identity":                a.HostIdentity,
		"platform":                     a.Platform,
		"kernel":                       a.Kernel,
		"capabilities":                 a.Capabilities,
		"probe_implementation_version": a.ProbeImplementationVersion,
		"governator_commit":            a.GovernatorCommit,
		"assayer_commit":               a.AssayerCommit,
		"release_version":              a.ReleaseVersion,
		"test_source_hash":             a.TestSourceHash,
		"test_binary_sha256":           a.TestBinarySHA256,
		"toolchain_hash":               a.ToolchainHash,
		"test_command":                 a.TestCommand,
		"passed_tests":                 a.PassedTests,
		"skipped_tests":                a.SkippedTests,
		"failed_tests":                 a.FailedTests,
		"raw_log_sha256":               a.RawLogSHA256,
		"started_at":                   a.StartedAt,
		"completed_at":                 a.CompletedAt,
		"signing_key_id":               a.SigningKeyID,
		"non_approving":                a.NonApproving,
	}
	// encoding/json sorts map keys, so the signed representation is stable and
	// independent of Go struct layout.
	return json.Marshal(payload)
}

func SignCapabilityAttestation(a *CapabilityAttestation, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return fmt.Errorf("attestation signing key has invalid length")
	}
	message, err := CanonicalAttestationPayload(*a)
	if err != nil {
		return err
	}
	a.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, message))
	return nil
}

func ParseEd25519PrivateKey(value string) (ed25519.PrivateKey, error) {
	decoded, err := hex.DecodeString(strings.TrimSpace(value))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("expected a %d-byte hexadecimal Ed25519 private key", ed25519.PrivateKeySize)
	}
	return ed25519.PrivateKey(decoded), nil
}

func SigningKeyID(publicKey ed25519.PublicKey) string {
	digest := sha256.Sum256(publicKey)
	return "ed25519:" + hex.EncodeToString(digest[:])
}

func BindingConsistent(atts []CapabilityAttestation) (bool, string) {
	if len(atts) == 0 {
		return false, "no capability attestations supplied"
	}
	base := atts[0]
	for _, a := range atts[1:] {
		if a.GovernatorCommit != base.GovernatorCommit || a.AssayerCommit != base.AssayerCommit ||
			a.TestSourceHash != base.TestSourceHash || a.TestBinarySHA256 != base.TestBinarySHA256 ||
			a.ToolchainHash != base.ToolchainHash || a.ReleaseVersion != base.ReleaseVersion {
			return false, fmt.Sprintf("attestation %q binding differs from %q (governator/assayer/test-source/test-binary/toolchain/version must all match)", a.Category, base.Category)
		}
	}
	return true, ""
}

type AggregationResult struct {
	OK                     bool            `json:"ok"`
	Problems               []string        `json:"problems,omitempty"`
	CoveredTests           map[string]bool `json:"-"`
	NonApprovingCategories map[string]bool `json:"-"`
	CategoriesPresent      []string        `json:"categories_present"`
}

// AggregateAndVerify accepts only attestations previously loaded through
// LoadAttestations. S2 deliberately does not use coverage to waive a skip;
// S3 will add category-aware, capability-proven coverage.
func AggregateAndVerify(atts []CapabilityAttestation, requiredCategories []string) AggregationResult {
	res := AggregationResult{CoveredTests: make(map[string]bool), NonApprovingCategories: make(map[string]bool)}
	if len(atts) == 0 {
		res.Problems = append(res.Problems, "no capability attestations supplied")
		return res
	}
	for _, a := range atts {
		if !a.verified {
			res.Problems = append(res.Problems, fmt.Sprintf("attestation %q was not signature-verified by the loader", a.Category))
		}
	}
	if len(res.Problems) > 0 {
		return res
	}
	if ok, msg := BindingConsistent(atts); !ok {
		res.Problems = append(res.Problems, msg)
		return res
	}
	present := make(map[string]bool)
	for _, a := range atts {
		present[a.Category] = true
		res.CategoriesPresent = append(res.CategoriesPresent, a.Category)
		if a.NonApproving {
			res.NonApprovingCategories[a.Category] = true
		}
		for _, test := range a.PassedTests {
			res.CoveredTests[test] = true
		}
	}
	sort.Strings(res.CategoriesPresent)
	for _, category := range requiredCategories {
		if !present[category] {
			res.Problems = append(res.Problems, fmt.Sprintf("required attestation category %q is missing from the supplied set", category))
		}
	}
	res.OK = len(res.Problems) == 0
	return res
}

// SkipCoveredByAttestations intentionally does not waive a mandatory skip in
// S2. Cryptographically valid documents are necessary but not sufficient:
// S3 supplies the test-to-category and capability-proof relationship.
func SkipCoveredByAttestations(_ string, _ AggregationResult, capabilities map[string]CapabilityRecord, caseEntry CaseEntry) bool {
	if caseEntry.Conditional && caseEntry.AllowedSkip != nil && caseEntry.AllowedSkip.Predicate != "" {
		record, ok := capabilities[caseEntry.AllowedSkip.Predicate]
		return ok && record.State == CapabilityAbsent
	}
	return false
}

func LoadAttestations(dir string) ([]CapabilityAttestation, error) {
	return LoadAttestationsWithOptions(dir, AttestationVerificationOptions{ReleaseTime: time.Now().UTC(), MaxAge: defaultAttestationMaxAge})
}

// LoadAttestationsWithOptions rejects every malformed, unsigned, invalid,
// untrusted, stale, differently-bound, or log-inconsistent record before it
// reaches aggregation.
func LoadAttestationsWithOptions(dir string, options AttestationVerificationOptions) ([]CapabilityAttestation, error) {
	if options.ReleaseTime.IsZero() {
		return nil, fmt.Errorf("attestation release time is required")
	}
	if options.MaxAge <= 0 {
		return nil, fmt.Errorf("attestation max age must be positive")
	}
	if options.TrustRegistry.Signers == nil {
		registry, err := DefaultTrustedSignerRegistry()
		if err != nil {
			return nil, err
		}
		options.TrustRegistry = registry
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("attestation dir: %w", err)
	}
	var atts []CapabilityAttestation
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("attestation %s: %w", entry.Name(), err)
		}
		var attestation CapabilityAttestation
		decoder := json.NewDecoder(strings.NewReader(string(data)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&attestation); err != nil {
			return nil, fmt.Errorf("attestation %s: %w", entry.Name(), err)
		}
		logData, err := os.ReadFile(path + ".log")
		if err != nil {
			return nil, fmt.Errorf("attestation %s: signed log: %w", entry.Name(), err)
		}
		if err := verifyAttestation(attestation, logData, options); err != nil {
			return nil, fmt.Errorf("attestation %s: %w", entry.Name(), err)
		}
		attestation.verified = true
		atts = append(atts, attestation)
	}
	if len(atts) == 0 {
		return nil, fmt.Errorf("no .json attestations in %s", dir)
	}
	return atts, nil
}

func verifyAttestation(a CapabilityAttestation, logData []byte, options AttestationVerificationOptions) error {
	if err := requireAttestationFields(a); err != nil {
		return err
	}
	if options.ExpectedBinding != nil && !matchesBinding(a, *options.ExpectedBinding) {
		return fmt.Errorf("binding does not match the independently supplied release identity")
	}
	started, err := time.Parse(time.RFC3339, a.StartedAt)
	if err != nil {
		return fmt.Errorf("invalid started_at: %w", err)
	}
	completed, err := time.Parse(time.RFC3339, a.CompletedAt)
	if err != nil {
		return fmt.Errorf("invalid completed_at: %w", err)
	}
	if completed.Before(started) {
		return fmt.Errorf("completion precedes start")
	}
	if completed.After(options.ReleaseTime.Add(5*time.Minute)) || options.ReleaseTime.Sub(completed) > options.MaxAge {
		return fmt.Errorf("attestation completion is outside the configured freshness window")
	}
	logHash := sha256.Sum256(logData)
	if !strings.EqualFold(a.RawLogSHA256, hex.EncodeToString(logHash[:])) {
		return fmt.Errorf("signed log hash differs from companion log")
	}
	if err := verifyLoggedResults(a, string(logData)); err != nil {
		return err
	}
	signer, err := trustedSigner(a, options.TrustRegistry)
	if err != nil {
		return err
	}
	publicKey, err := hex.DecodeString(signer.PublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("trusted signer %q has invalid public key", signer.KeyID)
	}
	if SigningKeyID(ed25519.PublicKey(publicKey)) != signer.KeyID || signer.KeyID != a.SigningKeyID {
		return fmt.Errorf("signing key identity does not match trusted public key")
	}
	signature, err := base64.RawStdEncoding.DecodeString(a.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return fmt.Errorf("invalid attestation signature encoding")
	}
	payload, err := CanonicalAttestationPayload(a)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return fmt.Errorf("invalid attestation signature")
	}
	return nil
}

func requireAttestationFields(a CapabilityAttestation) error {
	fields := map[string]string{
		"attestation_id": a.AttestationID, "category": a.Category, "host_identity": a.HostIdentity,
		"platform": a.Platform, "kernel": a.Kernel, "probe_implementation_version": a.ProbeImplementationVersion,
		"governator_commit": a.GovernatorCommit, "assayer_commit": a.AssayerCommit, "release_version": a.ReleaseVersion,
		"test_source_hash": a.TestSourceHash, "test_binary_sha256": a.TestBinarySHA256, "toolchain_hash": a.ToolchainHash,
		"raw_log_sha256": a.RawLogSHA256, "started_at": a.StartedAt, "completed_at": a.CompletedAt,
		"signing_key_id": a.SigningKeyID, "signature": a.Signature,
	}
	for name, value := range fields {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("missing %s", name)
		}
	}
	if len(a.Capabilities) == 0 || len(a.TestCommand) == 0 {
		return fmt.Errorf("missing capabilities or test command")
	}
	return nil
}

func trustedSigner(a CapabilityAttestation, registry TrustedSignerRegistry) (TrustedAttestationSigner, error) {
	for _, signer := range registry.Signers {
		if signer.KeyID != a.SigningKeyID {
			continue
		}
		for _, category := range signer.Categories {
			if category == a.Category {
				return signer, nil
			}
		}
		return TrustedAttestationSigner{}, fmt.Errorf("signer %q is not trusted for category %q", signer.KeyID, a.Category)
	}
	return TrustedAttestationSigner{}, fmt.Errorf("untrusted attestation signer %q", a.SigningKeyID)
}

func matchesBinding(a CapabilityAttestation, expected AttestationBinding) bool {
	return a.GovernatorCommit == expected.GovernatorCommit && a.AssayerCommit == expected.AssayerCommit &&
		a.ReleaseVersion == expected.ReleaseVersion && a.TestSourceHash == expected.TestSourceHash &&
		a.TestBinarySHA256 == expected.TestBinarySHA256 && a.ToolchainHash == expected.ToolchainHash
}

func verifyLoggedResults(a CapabilityAttestation, log string) error {
	passed, skipped, failed := AttestationResultsFromLog(log)
	if !sameStringSet(passed, a.PassedTests) || !sameStringSet(skipped, a.SkippedTests) || !sameStringSet(failed, a.FailedTests) {
		return fmt.Errorf("signed test result lists do not match companion log")
	}
	return nil
}

// AttestationResultsFromLog derives exactly the test result sets that are
// signed by a capability host and later compared against its detached log.
func AttestationResultsFromLog(log string) (passed, skipped, failed []string) {
	for name, outcome := range ParseVerboseLog(log) {
		switch outcome.Result {
		case "PASS":
			passed = append(passed, name)
		case "SKIP":
			skipped = append(skipped, name)
		case "FAIL":
			failed = append(failed, name)
		}
	}
	sort.Strings(passed)
	sort.Strings(skipped)
	sort.Strings(failed)
	return passed, skipped, failed
}

func sameStringSet(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	copyLeft, copyRight := append([]string(nil), left...), append([]string(nil), right...)
	sort.Strings(copyLeft)
	sort.Strings(copyRight)
	for index := range copyLeft {
		if copyLeft[index] != copyRight[index] {
			return false
		}
	}
	return true
}
