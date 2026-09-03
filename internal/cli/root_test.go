package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Installed through krew, kubectl runs this binary as kubectl-upgrade_check. Every example in the
// help would otherwise name a command the reader does not have installed.
func TestInvokedAs(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })

	// Two things at once. Directory separators are filepath.Base's problem, and which characters
	// count is platform-specific — a backslash separates on Windows and is a legal filename
	// character everywhere else — so paths are built with filepath.Join and the bare .exe case
	// covers the Windows suffix everywhere. And the name comes back without the "kubectl " prefix,
	// because cobra builds every subcommand path from the first word of Use, so the prefix has to
	// decorate the rendered path rather than become part of the command's name.
	cases := map[string]string{
		filepath.Join("usr", "local", "bin", "kube-upgrade-check"):          "kube-upgrade-check",
		filepath.Join("home", "x", ".krew", "bin", "kubectl-upgrade_check"): "upgrade-check",
		"kubectl-upgrade_check":     "upgrade-check",
		"kubectl-upgrade_check.exe": "upgrade-check",
		"kube-upgrade-check":        "kube-upgrade-check",
	}
	for arg0, want := range cases {
		os.Args = []string{arg0}
		got, isPlugin := invokedAs()
		if got != want {
			t.Errorf("invokedAs() with argv[0]=%q = %q, want %q", arg0, got, want)
		}
		if wantPlugin := strings.HasPrefix(filepath.Base(arg0), "kubectl-"); isPlugin != wantPlugin {
			t.Errorf("invokedAs() with argv[0]=%q reported isPlugin=%v, want %v", arg0, isPlugin, wantPlugin)
		}
	}
}

// Every level of the help has to name a command the reader can actually run. Rendering
// `kubectl catalog validate`, which is what happens when the prefix becomes part of the name,
// puts a command that does not exist somewhere people copy from.
func TestPluginHelpNamesRunnableCommandsAtEveryLevel(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	os.Args = []string{filepath.Join("anywhere", "kubectl-upgrade_check")}

	root := newRootCmd()
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, "kubectl upgrade-check"},
		{[]string{"catalog"}, "kubectl upgrade-check catalog"},
		{[]string{"catalog", "validate"}, "kubectl upgrade-check catalog validate"},
		{[]string{"version"}, "kubectl upgrade-check version"},
	} {
		cmd := root
		if len(tc.args) > 0 {
			found, _, err := root.Find(tc.args)
			if err != nil {
				t.Fatalf("%v: %v", tc.args, err)
			}
			cmd = found
		}
		var out bytes.Buffer
		cmd.SetOut(&out)
		if err := cmd.Usage(); err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		if !strings.Contains(out.String(), tc.want) {
			t.Errorf("usage for %v does not name %q:\n%s", tc.args, tc.want, out.String())
		}
		// The prefix must appear once. Applying it per level renders "kubectl kubectl kubectl …".
		if n := strings.Count(out.String(), "kubectl kubectl"); n > 0 {
			t.Errorf("usage for %v repeats the kubectl prefix:\n%s", tc.args, out.String())
		}
	}
}

// Run as itself, nothing is decorated.
func TestPlainBinaryHelpIsUndecorated(t *testing.T) {
	original := os.Args
	t.Cleanup(func() { os.Args = original })
	os.Args = []string{filepath.Join("bin", "kube-upgrade-check")}

	root := newRootCmd()
	cmd, _, err := root.Find([]string{"catalog", "validate"})
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd.SetOut(&out)
	if err := cmd.Usage(); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), "kubectl") {
		t.Errorf("a plain binary must not mention kubectl:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "kube-upgrade-check catalog validate") {
		t.Errorf("usage should name the real path:\n%s", out.String())
	}
}
