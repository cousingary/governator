package agents

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sort"
	"strings"
)

// baselineAllowedEnvKeys is the small, fixed set of variables every
// governed backend launch keeps regardless of what the adapter declares:
// enough to find binaries, locate a home directory, and behave sanely in
// a terminal-adjacent locale. Sol P1-14: the launch used to inherit the
// FULL parent environment unconditionally (cloud credentials, unrelated
// provider keys, SSH agent sockets, CI tokens, everything) — this baseline
// plus each backend's own config.Backend.AllowedEnv declaration is now the
// entire surface a governed backend process ever sees.
//
// XDG_RUNTIME_DIR and DBUS_SESSION_BUS_ADDRESS are here for a different
// reason than the rest: they are not the backend's own business, they are
// what the Session 2 containment wrapper (systemd-run --user --scope)
// needs to reach the user's session bus. Verified empirically on this
// platform: systemd-run inherits the launching exec.Cmd's Env, and
// without these two the wrapper itself fails to connect to the bus
// before the backend ever runs -- stripping them would silently break
// every scoped (i.e. every production) governed launch, not just tighten it.
var baselineAllowedEnvKeys = []string{
	"PATH", "HOME", "LANG", "LC_ALL", "TMPDIR", "TZ",
	"XDG_RUNTIME_DIR", "DBUS_SESSION_BUS_ADDRESS",
}

// BuildAllowedEnv returns a filtered copy of the current process
// environment: only names in baselineAllowedEnvKeys plus extra survive.
// Every other inherited variable — AWS_*, GITHUB_TOKEN, SSH_AUTH_SOCK,
// unrelated provider credentials, DB URLs, signing keys — is stripped by
// default rather than passed opaquely to a governed backend.
func BuildAllowedEnv(extra []string) []string {
	allowed := make(map[string]bool, len(baselineAllowedEnvKeys)+len(extra))
	for _, k := range baselineAllowedEnvKeys {
		allowed[k] = true
	}
	for _, k := range extra {
		if k != "" {
			allowed[k] = true
		}
	}
	if os.Getenv("GOV_TEST_ALLOW_FAKE_ENV") == "1" {
		for _, pair := range os.Environ() {
			name, _, ok := strings.Cut(pair, "=")
			if ok && strings.HasPrefix(name, "FAKE_") {
				allowed[name] = true
			}
		}
	}
	out := make([]string, 0, len(allowed))
	names := make([]string, 0, len(allowed))
	for name := range allowed {
		if isInjectionEnv(name) {
			continue
		}
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if v, ok := os.LookupEnv(name); ok {
			out = append(out, name+"="+v)
		}
	}
	return out
}

func isInjectionEnv(name string) bool {
	switch name {
	case "BASH_ENV", "ENV", "SHELLOPTS", "BASHOPTS", "CDPATH", "GLOBIGNORE", "PROMPT_COMMAND",
		"LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "PYTHONPATH", "PYTHONHOME",
		"PERL5OPT", "RUBYOPT", "NODE_OPTIONS":
		return true
	}
	return strings.HasPrefix(name, "GIT_")
}

// EnvPolicyHash returns a stable digest of the *set of variable names*
// that BuildAllowedEnv(extra) would expose to a subprocess — never the
// values (Sol P1-14: "record the environment policy hash; never the
// values"). Two backends with the same declared names hash identically
// regardless of what those variables currently contain on this host.
func EnvPolicyHash(extra []string) string {
	names := append([]string(nil), baselineAllowedEnvKeys...)
	for _, k := range extra {
		if k != "" {
			names = append(names, k)
		}
	}
	sort.Strings(names)
	seen := make(map[string]bool, len(names))
	var b strings.Builder
	for _, n := range names {
		if seen[n] {
			continue
		}
		seen[n] = true
		b.WriteString(n)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}
