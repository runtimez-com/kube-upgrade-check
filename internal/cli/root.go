// Package cli is the command surface.
package cli

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/runtimez-com/kube-upgrade-check/internal/version"
)

// Execute runs the root command and returns the process exit code.
func Execute() int {
	root := newRootCmd()
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error {
		return &ExitError{Code: ExitUsage, Err: err}
	})
	if err := root.Execute(); err != nil {
		return reportError(err)
	}
	return lastExitCode
}

// lastExitCode lets a successful command still exit non-zero for a policy gate, without
// printing the gate as though it were an error.
var lastExitCode = ExitOK

// invokedAs returns the command name to print in usage text, and whether this is running as a
// kubectl plugin.
//
// Installed through krew, this binary is run by kubectl as `kubectl-upgrade_check`, and every
// example in the help would otherwise name a command the reader does not have. kubectl turns the
// underscores back into dashes when it dispatches, so the reverse mapping reconstructs exactly
// what someone typed.
//
// The name is returned without the "kubectl " prefix because cobra derives a command's name from
// the first word of Use, and builds every subcommand's path from it. A Use of "kubectl
// upgrade-check" therefore makes cobra believe the command is called "kubectl", and it renders
// nonsense like `kubectl catalog validate` — a command that does not exist, printed somewhere a
// reader will copy it from. The prefix is applied to the templates instead, where it decorates
// the whole path rather than becoming part of the name.
func invokedAs() (name string, isPlugin bool) {
	name = filepath.Base(os.Args[0])
	if filepath.Ext(name) == ".exe" {
		name = strings.TrimSuffix(name, ".exe")
	}
	if plugin, found := strings.CutPrefix(name, "kubectl-"); found {
		return strings.ReplaceAll(plugin, "_", "-"), true
	}
	return name, false
}

// asKubectlPlugin prefixes every rendered command path with "kubectl ", so subcommands read as
// `kubectl upgrade-check catalog validate` rather than losing the prefix or, worse, keeping it in
// the wrong place.
func asKubectlPlugin(cmd *cobra.Command) {
	rewrite := func(tpl string) string {
		tpl = strings.ReplaceAll(tpl, "{{.UseLine}}", "kubectl {{.UseLine}}")
		tpl = strings.ReplaceAll(tpl, "{{.CommandPath}}", "kubectl {{.CommandPath}}")
		return tpl
	}
	cmd.SetUsageTemplate(rewrite(cmd.UsageTemplate()))
	cmd.SetHelpTemplate(rewrite(cmd.HelpTemplate()))
}

func newRootCmd() *cobra.Command {
	name, isPlugin := invokedAs()
	cmd := newCheckCmd()
	cmd.Use = name
	cmd.Short = "Find what breaks before you upgrade Kubernetes"
	cmd.Long = `Find what breaks before you upgrade Kubernetes.

Reads the cluster in your current kubeconfig context, read-only, and reports what an upgrade
to a target version would break: removed APIs still in use, control-plane and kubelet settings
the target version rejects, in-tree volume plugins that stop working, node-level breaks, and
whether your add-ons support the version you are moving to.

It also reports what it could not check, and why. A check that could not run is never shown
as a check that passed.`
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true

	cmd.AddCommand(newVersionCmd(), newCatalogCmd())
	// The root only. A command with no template of its own asks its parent, so this reaches every
	// subcommand exactly once; applying it to each of them as well prefixes the path per level and
	// renders "kubectl kubectl kubectl upgrade-check catalog validate".
	if isPlugin {
		asKubectlPlugin(cmd)
	}
	return cmd
}

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), version.String())
			return err
		},
	}
}
