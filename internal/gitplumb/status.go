package gitplumb

import (
	"context"
	"fmt"
	"strings"
)

// StatusEntry is one record from `git status --porcelain=v2 -z`, parsed
// byte-wise on NUL delimiters with no shell-style unquoting — unlike the
// human-readable v1 porcelain format, this survives quoted names, escaped
// bytes, tabs, embedded newlines, rename arrows, and filenames that begin
// with pathspec-magic syntax (P1-9), because the machine format never puts
// two records' worth of ambiguity on one text line.
type StatusEntry struct {
	// Kind is the record's leading character: '1' ordinary changed entry,
	// '2' renamed/copied entry, 'u' unmerged entry, '?' untracked, '!'
	// ignored.
	Kind byte
	// XY is the two-character status code (empty for '?'/'!', which carry
	// no status code field).
	XY string
	// Path is the entry's current path, exactly as Git stored it (raw
	// bytes, no quoting applied).
	Path string
	// OrigPath is the pre-rename path, set only for Kind == '2'.
	OrigPath string
}

// StatusPorcelainV2 runs `git status --porcelain=v2 -z` in dir with a
// neutralized environment and parses the NUL-delimited output. A renamed
// or copied entry consumes two consecutive NUL-delimited tokens (the
// record fields ending in the new path, then the raw original path); every
// other kind consumes exactly one.
func StatusPorcelainV2(ctx context.Context, dir string) ([]StatusEntry, error) {
	// Sol v9 P0-6: this standalone call has no Session to reuse a held
	// handle from, so it resolves, opens, uses, and closes its own -- the
	// verified descriptor is exec'd directly (never a bare path string a
	// second resolution could swap), and the fix doesn't require this
	// one-shot caller to carry a Session it has no other use for.
	handle, err := openGitHandle()
	if err != nil {
		return nil, err
	}
	defer handle.Close()
	out, err := runCapture(ctx, handle, dir, nil, "status", "--porcelain=v2", "-z")
	if err != nil {
		return nil, err
	}
	tokens := strings.Split(out, "\x00")
	var entries []StatusEntry
	for i := 0; i < len(tokens); i++ {
		tok := tokens[i]
		if tok == "" {
			continue
		}
		entry, err := parseStatusToken(tok)
		if err != nil {
			return nil, fmt.Errorf("gitplumb: parse status entry %q: %w", tok, err)
		}
		if entry.Kind == '2' {
			i++
			if i >= len(tokens) {
				return nil, fmt.Errorf("gitplumb: renamed/copied entry %q missing its original-path record", tok)
			}
			entry.OrigPath = tokens[i]
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// parseStatusToken splits one porcelain=v2 record on the exact number of
// fixed space-separated fields its kind declares, so the trailing path
// field (which may itself contain spaces) is never truncated.
func parseStatusToken(tok string) (StatusEntry, error) {
	switch tok[0] {
	case '1': // 1 XY sub mH mI mW hH hI path
		parts := strings.SplitN(tok, " ", 9)
		if len(parts) != 9 {
			return StatusEntry{}, fmt.Errorf("malformed ordinary-changed entry")
		}
		return StatusEntry{Kind: '1', XY: parts[1], Path: parts[8]}, nil
	case '2': // 2 XY sub mH mI mW hH hI Xscore path (origPath is the next NUL token)
		parts := strings.SplitN(tok, " ", 10)
		if len(parts) != 10 {
			return StatusEntry{}, fmt.Errorf("malformed renamed/copied entry")
		}
		return StatusEntry{Kind: '2', XY: parts[1], Path: parts[9]}, nil
	case 'u': // u XY sub m1 m2 m3 mW h1 h2 h3 path
		parts := strings.SplitN(tok, " ", 11)
		if len(parts) != 11 {
			return StatusEntry{}, fmt.Errorf("malformed unmerged entry")
		}
		return StatusEntry{Kind: 'u', XY: parts[1], Path: parts[10]}, nil
	case '?', '!': // ? path / ! path
		parts := strings.SplitN(tok, " ", 2)
		if len(parts) != 2 {
			return StatusEntry{}, fmt.Errorf("malformed untracked/ignored entry")
		}
		return StatusEntry{Kind: tok[0], Path: parts[1]}, nil
	default:
		return StatusEntry{}, fmt.Errorf("unknown record kind %q", tok[0])
	}
}
