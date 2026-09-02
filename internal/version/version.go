// Package version carries build metadata stamped in by the linker at release time.
package version

import (
	"fmt"
	"runtime"
)

// Overridden via -ldflags at build time; the defaults are what a plain `go build` produces.
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

// String is the one-line form printed by `kube-upgrade-check version`.
func String() string {
	return fmt.Sprintf("kube-upgrade-check %s (commit %s, built %s, %s/%s, %s)",
		Version, Commit, Date, runtime.GOOS, runtime.GOARCH, runtime.Version())
}

// UserAgent identifies this tool to the API server, so an operator reading audit logs can
// tell a read-only scan from an actual controller.
func UserAgent() string {
	return fmt.Sprintf("kube-upgrade-check/%s (%s/%s)", Version, runtime.GOOS, runtime.GOARCH)
}
