package redteamgate

import "fmt"

// PlatformStatus classifies one Go GOOS value for rc5 production release
// (Sol12 P1-1 "Darwin production support is unproven after Linux memfd
// changes"). scripts/release.sh's PLATFORMS variable is caller-controlled
// (an operator can set PLATFORMS="windows/amd64" with no prior validation)
// -- before Session 6 its per-artifact "approving" flag defaulted to true
// for anything whose GOOS didn't literally start with "darwin_", so an
// unsupported platform would have shipped silently marked fully approving.
// ClassifyPlatform/ApprovedForProduction is the one authoritative decision
// this codebase makes about which platforms a production release may name;
// scripts/release.sh mirrors it in bash (it cannot import this package
// while building the very binary this package is part of) and must be kept
// in sync by hand -- see release.sh's PLATFORMS validation loop.
type PlatformStatus string

const (
	// PlatformApproving is a platform whose build is production-capable
	// with no known degraded modes. Only "linux" today.
	PlatformApproving PlatformStatus = "approving"
	// PlatformNonApproving is a platform that builds and cross-compiles
	// cleanly (internal/assay/snapshot_other.go, internal/runtime/
	// artifacts_other.go and their _linux.go siblings), and MAY ship, but
	// never claims production approval: no native acceptance evidence
	// exists for it (see AttestationCategoryDarwin), so every artifact for
	// it is labeled non-approving/degraded rather than silently trusted.
	// Only "darwin" today.
	PlatformNonApproving PlatformStatus = "non-approving"
	// PlatformUnsupported is any GOOS this codebase has made no claim
	// about at all. Building for it, let alone shipping it as part of a
	// production release, must be refused outright -- there is no
	// "unknown, default to approving" fallback.
	PlatformUnsupported PlatformStatus = "unsupported"
)

// approvingPlatforms/degradedPlatforms are the only two recognized GOOS
// sets. Adding a platform to either requires the corresponding real
// evidence: approvingPlatforms needs full native acceptance evidence
// (AttestationCategory* in attestation.go); degradedPlatforms only needs
// the cross-compile + explicit non-approving declaration this session
// establishes for Darwin.
var approvingPlatforms = map[string]bool{
	"linux": true,
}

var degradedPlatforms = map[string]bool{
	"darwin": true,
}

// ClassifyPlatform reports goos's PlatformStatus.
func ClassifyPlatform(goos string) PlatformStatus {
	if approvingPlatforms[goos] {
		return PlatformApproving
	}
	if degradedPlatforms[goos] {
		return PlatformNonApproving
	}
	return PlatformUnsupported
}

// ApprovedForProduction reports whether goos may claim a fully-approving
// rc5 production release: no degraded modes, no refusal. A non-approving
// platform (Darwin) and an unsupported platform both return false --
// callers that need to distinguish "ships, but degraded" from "refuse to
// build at all" should call ClassifyPlatform directly.
func ApprovedForProduction(goos string) (bool, string) {
	switch ClassifyPlatform(goos) {
	case PlatformApproving:
		return true, ""
	case PlatformNonApproving:
		return false, fmt.Sprintf("platform %q is explicitly non-approving for this release: it builds and may ship, but carries no native production acceptance evidence (see docs/security.md's Session 6 closure entry, Sol12 P1-1)", goos)
	default:
		return false, fmt.Sprintf("platform %q is not a recognized release target at all (refusing rather than defaulting an unknown platform to approving)", goos)
	}
}
