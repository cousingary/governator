package policy

import (
	"path/filepath"
	"regexp"
	"strings"
)

type CommandClass struct {
	Verb     string
	Resource string
}

var (
	chainRE       = regexp.MustCompile(`&&|\|\||;|\||\n`)
	rtkPrefixRE   = regexp.MustCompile(`(?i)(^|(?:&&|\|\||;|\||\n)\s*)(?:[^\s]*/)?rtk(?:\s+(?:-u|--ultra-compact|-v|-vv|-vvv))*\s+(?:proxy\s+)?`)
	wrapperRE     = regexp.MustCompile(`^(?:sudo|nohup|time|env)\s+`)
	assignmentRE  = regexp.MustCompile(`^(?:\w+=\S+\s+)+`)
	deleteRE      = regexp.MustCompile(`^(rm|rmdir|unlink|shred)\b`)
	interactiveRM = regexp.MustCompile(`^rm\s+-[a-z]*i`)
	recursiveRM   = regexp.MustCompile(`\s--?[a-z]*r`)
	findDeleteRE  = regexp.MustCompile(`\bfind\b.*\s-delete\b`)
	findExecRMRE  = regexp.MustCompile(`\bfind\b.*-exec(?:dir)?\s+rm\b`)
	deviceRE      = regexp.MustCompile(`>\s*/dev/(sd|nvme|disk|hd|vd|mapper)`)
	ddDeviceRE    = regexp.MustCompile(`\bdd\b.*\bof=/dev/`)
	pushRE        = regexp.MustCompile(`^git\s+push\b`)
	mainRE        = regexp.MustCompile(`\b(main|master)\b`)
	forceRE       = regexp.MustCompile(`(--force\b|--force-with-lease\b|\s-f\b)`)
	dropRE        = regexp.MustCompile(`\b(drop\s+(table|database|schema|index|view)|truncate\s+table)\b`)
)

// NormalizeShellCommand removes RTK's transparent output-filter prefix before
// governance evaluates command intent. The original command still executes and
// is retained in transcripts; only policy matching uses the normalized form.
func NormalizeShellCommand(command string) string {
	return rtkPrefixRE.ReplaceAllString(command, "$1")
}

// ClassifyShellCommand ports the live Python harness classifier. In full mode,
// every delete is classified; highDangerOnly permits routine single-file cleanup.
func ClassifyShellCommand(command string, highDangerOnly bool) *CommandClass {
	command = NormalizeShellCommand(command)
	for _, segment := range chainRE.Split(command, -1) {
		s := strings.TrimSpace(segment)
		if s == "" {
			continue
		}
		for {
			before := s
			s = wrapperRE.ReplaceAllString(s, "")
			s = assignmentRE.ReplaceAllString(s, "")
			s = NormalizeShellCommand(s)
			if s == before {
				break
			}
		}
		low := strings.ToLower(s)

		if match := deleteRE.FindStringSubmatch(low); match != nil && !interactiveRM.MatchString(low) {
			if !highDangerOnly || match[1] == "shred" || (match[1] == "rm" && recursiveRM.MatchString(low)) {
				return &CommandClass{Verb: "delete", Resource: "file"}
			}
		}
		if findDeleteRE.MatchString(low) || findExecRMRE.MatchString(low) {
			return &CommandClass{Verb: "delete", Resource: "file"}
		}
		if deviceRE.MatchString(low) || ddDeviceRE.MatchString(low) {
			return &CommandClass{Verb: "delete", Resource: "device"}
		}
		if pushRE.MatchString(low) && (mainRE.MatchString(low) || forceRE.MatchString(low)) {
			return &CommandClass{Verb: "push", Resource: "main"}
		}
		if dropRE.MatchString(low) {
			return &CommandClass{Verb: "drop", Resource: "table"}
		}
	}
	return nil
}

// scratchRootRE matches a Claude Code session scratchpad and anything under
// it. Matched against resolved paths only (symlinks followed first).
var scratchRootRE = regexp.MustCompile(`^/tmp/claude-\d+/[^/]+/[^/]+/scratchpad(?:/|$)`)

var devNullRE = regexp.MustCompile(`\d*>\s*/dev/null`)

// ScratchOnlyDelete reports whether every classified delete in command is a
// recursive rm or a find-delete whose targets all resolve inside a scratchpad.
// Anything it cannot prove (variables, quotes, mid-path globs, "..", find -L,
// find -exec, shred, a non-scratch target) returns false so the deny stands.
func ScratchOnlyDelete(command, cwd string) bool {
	command = devNullRE.ReplaceAllString(NormalizeShellCommand(command), "")
	if strings.ContainsAny(command, "$`<>(){}~\\\"'") {
		return false
	}
	sawDelete := false
	for _, segment := range chainRE.Split(command, -1) {
		s := strings.TrimSpace(segment)
		for {
			before := s
			s = wrapperRE.ReplaceAllString(s, "")
			s = assignmentRE.ReplaceAllString(s, "")
			if s == before {
				break
			}
		}
		if s == "" || ClassifyShellCommand(s, true) == nil {
			continue
		}
		f := strings.Fields(s)
		var targets []string
		globOK := false
		switch f[0] {
		case "rm":
			globOK = true
			opts := true
			for _, t := range f[1:] {
				switch {
				case opts && t == "--":
					opts = false
				case opts && strings.HasPrefix(t, "-"):
				default:
					targets = append(targets, t)
				}
			}
		case "find":
			if strings.Contains(s, "-exec") || strings.Contains(s, "-ok") {
				return false
			}
		paths:
			for _, t := range f[1:] {
				switch {
				case t == "-L" || strings.Contains(s, "-follow"):
					return false
				case t == "-H" || t == "-P":
				case strings.HasPrefix(t, "-") || t == "!" || t == ",":
					break paths
				default:
					targets = append(targets, t)
				}
			}
		default:
			return false
		}
		if len(targets) == 0 {
			return false
		}
		for _, t := range targets {
			if !scratchTarget(t, cwd, globOK) {
				return false
			}
		}
		sawDelete = true
	}
	return sawDelete
}

func scratchTarget(t, cwd string, globOK bool) bool {
	if !filepath.IsAbs(t) {
		t = filepath.Join(cwd, t)
	}
	for _, part := range strings.Split(t, "/") {
		if part == ".." {
			return false
		}
	}
	if strings.ContainsAny(t, "*?[]") {
		// A glob only in the last component expands to children of an
		// in-scratch directory; anywhere else it could escape.
		if !globOK || strings.HasSuffix(t, "/") || strings.ContainsAny(filepath.Dir(t), "*?[]") {
			return false
		}
		t = filepath.Dir(t)
	}
	return scratchRootRE.MatchString(resolveExisting(filepath.Clean(t)) + "/")
}

// resolveExisting follows symlinks through the deepest existing ancestor, so a
// link inside the scratchpad that points elsewhere is judged by its target.
func resolveExisting(p string) string {
	rest := ""
	for {
		if r, err := filepath.EvalSymlinks(p); err == nil {
			return filepath.Join(r, rest)
		}
		parent := filepath.Dir(p)
		if parent == p {
			return p
		}
		rest = filepath.Join(filepath.Base(p), rest)
		p = parent
	}
}
