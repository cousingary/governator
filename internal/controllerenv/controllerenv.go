// Package controllerenv builds the only environment Governator-controlled
// subprocesses are allowed to inherit.
package controllerenv

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Allowlist is the minimal controller environment surface from Sol v6 S3.
var Allowlist = []string{"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL", "TZ"}

var injectionVars = map[string]bool{
	"BASH_ENV": true, "ENV": true, "SHELLOPTS": true, "BASHOPTS": true,
	"CDPATH": true, "GLOBIGNORE": true, "PROMPT_COMMAND": true,
	"LD_PRELOAD": true, "LD_LIBRARY_PATH": true, "DYLD_INSERT_LIBRARIES": true,
	"PYTHONPATH": true, "PYTHONHOME": true, "PERL5OPT": true,
	"RUBYOPT": true, "NODE_OPTIONS": true,
}

func IsForbidden(name string) bool {
	if injectionVars[name] {
		return true
	}
	return strings.HasPrefix(name, "GIT_")
}

func Base() []string { return With(map[string]string{}) }

// Frozen is the one controller environment snapshot owned by a run.  Values
// are captured once by Freeze; With derives stage-specific overrides from
// those captured values and never consults the ambient process environment.
type Frozen struct {
	Values []string
	Hash   string
}

func Freeze() Frozen {
	values := Base()
	return Frozen{Values: append([]string(nil), values...), Hash: Hash(values)}
}

func (f Frozen) Validate() error {
	if f.Values == nil {
		return fmt.Errorf("controller environment is not frozen")
	}
	if f.Hash == "" || f.Hash != Hash(f.Values) {
		return fmt.Errorf("controller environment hash does not match frozen values")
	}
	return nil
}

func (f Frozen) Lookup(name string) (string, bool) {
	for _, pair := range f.Values {
		key, value, ok := strings.Cut(pair, "=")
		if ok && key == name {
			return value, true
		}
	}
	return "", false
}

func (f Frozen) With(extra map[string]string) Frozen {
	vals := make(map[string]string, len(f.Values)+len(extra))
	for _, pair := range f.Values {
		key, value, ok := strings.Cut(pair, "=")
		if ok && key != "" && !IsForbidden(key) {
			vals[key] = value
		}
	}
	for key, value := range extra {
		if key == "" || strings.Contains(key, "=") || injectionVars[key] {
			continue
		}
		vals[key] = value
	}
	keys := make([]string, 0, len(vals))
	for key := range vals {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, key+"="+vals[key])
	}
	return Frozen{Values: values, Hash: Hash(values)}
}

func With(extra map[string]string) []string {
	vals := map[string]string{}
	for _, k := range Allowlist {
		if IsForbidden(k) {
			continue
		}
		if v, ok := os.LookupEnv(k); ok && v != "" {
			vals[k] = v
		}
	}
	if _, ok := vals["TMPDIR"]; !ok {
		vals["TMPDIR"] = os.TempDir()
	}
	if os.Getenv("GOV_TEST_ALLOW_FAKE_ENV") == "1" {
		for _, pair := range os.Environ() {
			name, value, ok := strings.Cut(pair, "=")
			if ok && strings.HasPrefix(name, "FAKE_") && !IsForbidden(name) {
				vals[name] = value
			}
		}
	}
	for k, v := range extra {
		// Explicit controller-owned overrides are allowed to set GIT_*
		// knobs (for example GIT_CONFIG_NOSYSTEM=1). Ambient inherited
		// GIT_* still never enter because the base loop above names only
		// Allowlist keys.
		if k == "" || strings.Contains(k, "=") || injectionVars[k] {
			continue
		}
		vals[k] = v
	}
	keys := make([]string, 0, len(vals))
	for k := range vals {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, k+"="+vals[k])
	}
	return out
}

func Hash(env []string) string {
	cp := append([]string(nil), env...)
	sort.Strings(cp)
	sum := sha256.Sum256([]byte(strings.Join(cp, "\n")))
	return hex.EncodeToString(sum[:])
}
