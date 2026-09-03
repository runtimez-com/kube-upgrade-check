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

// invokedAs returns the name to print in usage text.
//
// Installed through krew, this binary is run by kubectl as `kubectl-upgrade_check`, and every
// example in the help would otherwise name a command the reader does not have. kubectl turns the
// underscores back into dashes when it dispatches, so the reverse mapping reconstructs exactly
// what someone typed.
func invokedAs() string {
	name := filepath.Base(os.Args[0])
	if ext := filepath.Ext(name); ext == ".exe" {
		name = strings.TrimSuffix(name, ext)
	}
	if plugin, found := strings.CutPrefix(name, "kubectl-"); found {
		return "kubectl " + strings.ReplaceAll(plugin, "_", "-")
	}
	return name
}

func newRootCmd() *cobra.Command {
	cmd := newCheckCmd()
	cmd.Use = invokedAs()
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
