package policy

import (
	"regexp"
	"strings"
)

type CommandClass struct {
	Verb     string
	Resource string
}

var (
	chainRE       = regexp.MustCompile(`&&|\|\||;|\||\n`)
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

// ClassifyShellCommand ports the live Python harness classifier. In full mode,
// every delete is classified; highDangerOnly permits routine single-file cleanup.
func ClassifyShellCommand(command string, highDangerOnly bool) *CommandClass {
	for _, segment := range chainRE.Split(command, -1) {
		s := strings.TrimSpace(segment)
		if s == "" {
			continue
		}
		s = wrapperRE.ReplaceAllString(s, "")
		s = assignmentRE.ReplaceAllString(s, "")
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
