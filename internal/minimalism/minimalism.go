// Package minimalism injects a YAGNI-first ruleset into governed prompts,
// adapted from the ponytail project (MIT license: github.com/DietrichGebert/ponytail).
package minimalism

import "github.com/cousingary/governator/internal/config"

type Status struct {
	Mode    string
	Enabled bool
}

func Resolve() (Status, error) {
	cfg, err := config.Load()
	if err != nil {
		return Status{}, err
	}
	status := Status{Mode: cfg.Minimalism.Mode}
	status.Enabled = status.Mode != "off"
	return status, nil
}

func PromptAnnotation() (string, error) {
	status, err := Resolve()
	if err != nil || !status.Enabled {
		return "", err
	}
	switch status.Mode {
	case "lite":
		return liteText, nil
	case "ultra":
		return fullText + ultraAddendum, nil
	default: // "full"
		return fullText, nil
	}
}

const liteText = `
Minimalism discipline (adapted from ponytail, MIT: github.com/DietrichGebert/ponytail):
Before writing code, prefer in order: do nothing if it isn't needed, reuse existing
code, the standard library, a native platform feature, an already-installed
dependency, a one-liner, and only then new custom code. Add no abstractions,
dependencies, or boilerplate beyond what the task asks for. Mark deliberate
shortcuts inline: // ponytail: <shortcut> (ceiling: <what a fuller solution would add>).
`

const fullText = `
Minimalism discipline, adapted from the ponytail project (MIT: github.com/DietrichGebert/ponytail).
Before writing any code, climb this ladder and stop at the first rung that satisfies the task:
1. Skip it - if the behavior already exists or isn't required, do nothing.
2. Reuse - search the repo for an existing function, type, or pattern that already does this.
3. Standard library - prefer stdlib over third-party code.
4. Native platform feature - prefer an OS/runtime/language built-in over a library.
5. Installed dependency - if the repo already imports something that does this, call it.
6. One-liner - if a full abstraction isn't needed, write the smallest inline expression that works.
7. Minimal custom code - only now write new code, kept to the smallest diff that works.
Do not add abstractions, interfaces, config options, or dependencies nobody asked for.
Do not add speculative flexibility, unused error-handling paths, or boilerplate "for later."
When a deliberate shortcut replaces the fuller solution, mark it inline:
// ponytail: <what was skipped> (ceiling: <what a fuller solution would add>).
`

const ultraAddendum = `
Ultra mode: default to deleting code over adding it. Treat every new file, interface,
config flag, and dependency as unjustified until the task's literal request requires
it. A feature nobody asked for does not ship. A working one-liner beats a
speculative abstraction. Before adding anything, ask whether an engineer paid
strictly for the outcome, not for lines written, would write it - then write only that.
`
