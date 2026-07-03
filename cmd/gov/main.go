package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/cousingary/governator/internal/contracts"
	"github.com/cousingary/governator/internal/doctor"
)

const version = "0.1.0-phase0"

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	if len(args) == 0 {
		usage(os.Stderr)
		return 2
	}

	switch args[0] {
	case "validate":
		return validateCommand(args[1:])
	case "doctor":
		return doctorCommand(args[1:])
	case "version", "--version", "-version":
		fmt.Printf("gov %s\n", version)
		return 0
	case "help", "--help", "-h":
		usage(os.Stdout)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage(os.Stderr)
		return 2
	}
}

func validateCommand(args []string) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: gov validate <job.yaml>")
		return 2
	}
	contract, err := contracts.ParseFile(args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "INVALID %s\n", args[0])
		var validation contracts.ValidationErrors
		if errors.As(err, &validation) {
			for _, item := range validation.Sorted() {
				fmt.Fprintf(os.Stderr, "  - %s\n", item.Error())
			}
		} else {
			fmt.Fprintf(os.Stderr, "  - %v\n", err)
		}
		return 1
	}
	fmt.Printf("VALID %s (job_id=%s mode=%s agent=%s)\n", args[0], contract.JobID, contract.Mode, contract.Agent)
	return 0
}

func doctorCommand(args []string) int {
	if len(args) != 0 {
		fmt.Fprintln(os.Stderr, "usage: gov doctor")
		return 2
	}
	checks := doctor.Run()
	for _, check := range checks {
		label := "OK"
		switch check.Status {
		case doctor.StatusWarn:
			label = "WARN"
		case doctor.StatusFail:
			label = "FAIL"
		}
		fmt.Printf("[%s] %-18s %s\n", label, check.Name, check.Detail)
	}
	if !doctor.Passed(checks) {
		fmt.Println("doctor: FAILED")
		return 1
	}
	fmt.Println("doctor: OK")
	return 0
}

func usage(out *os.File) {
	fmt.Fprintln(out, "Governator — contract-first runtime for replaceable coding agents")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Usage:")
	fmt.Fprintln(out, "  gov validate <job.yaml>  validate a sovereign job contract")
	fmt.Fprintln(out, "  gov doctor               verify Phase 0 runtime prerequisites")
	fmt.Fprintln(out, "  gov version              print the binary version")
}
