package cli

import (
	"errors"
	"fmt"
	"os"
)

// Exit codes are a contract. CI pipelines branch on them, so they may be added to but never
// renumbered.
const (
	// ExitOK means the scan ran and nothing reached the failure threshold.
	ExitOK = 0
	// ExitFailure means the scan itself failed — not that findings were found.
	ExitFailure = 1
	// ExitUsage means the command line was wrong.
	ExitUsage = 2
	// ExitAuth means the cluster refused the credentials.
	ExitAuth = 3
	// ExitPolicy means findings reached the --fail-on threshold. This is the gate code.
	ExitPolicy = 4
)

// ExitError carries an explicit exit code out of a command.
type ExitError struct {
	Code int
	Err  error
}

func (e *ExitError) Error() string { return e.Err.Error() }
func (e *ExitError) Unwrap() error { return e.Err }

func usageErrorf(format string, args ...any) error {
	return &ExitError{Code: ExitUsage, Err: fmt.Errorf(format, args...)}
}

// codeFor maps an error to its exit code.
func codeFor(err error) int {
	if err == nil {
		return ExitOK
	}
	var exit *ExitError
	if errors.As(err, &exit) {
		return exit.Code
	}
	return ExitFailure
}

// reportError prints one actionable line — never a stack trace — and returns the exit code.
func reportError(err error) int {
	if err == nil {
		return ExitOK
	}
	code := codeFor(err)
	fmt.Fprintf(os.Stderr, "error: %v\n", err)
	if code == ExitAuth {
		fmt.Fprintln(os.Stderr,
			"hint: check your kubeconfig context with `kubectl config current-context`")
	}
	return code
}
