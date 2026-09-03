package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// Installed through krew, kubectl runs this binary as kubectl-upgrade_check. Every example in the
// help would otherwise name a command the reader does not have installed.
func TestInvokedAs(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })

	// Directory separators are filepath.Base's problem, and which characters count is
	// platform-specific: a backslash separates on Windows and is a legal filename character
	// everywhere else. So paths here are built with filepath.Join, and the bare .exe case covers
	// the Windows suffix on every platform.
	cases := map[string]string{
		filepath.Join("usr", "local", "bin", "kube-upgrade-check"):          "kube-upgrade-check",
		filepath.Join("home", "x", ".krew", "bin", "kubectl-upgrade_check"): "kubectl upgrade-check",
		"kubectl-upgrade_check":     "kubectl upgrade-check",
		"kubectl-upgrade_check.exe": "kubectl upgrade-check",
		"kube-upgrade-check":        "kube-upgrade-check",
	}
	for arg0, want := range cases {
		os.Args = []string{arg0}
		if got := invokedAs(); got != want {
			t.Errorf("invokedAs() with argv[0]=%q = %q, want %q", arg0, got, want)
		}
	}
}

// The root command has to carry that name, or the fix never reaches the help text.
func TestRootCommandUsesTheInvokedName(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })

	os.Args = []string{filepath.Join("anywhere", "kubectl-upgrade_check")}
	if got := newRootCmd().Use; got != "kubectl upgrade-check" {
		t.Errorf("root command Use = %q, want %q", got, "kubectl upgrade-check")
	}
}
