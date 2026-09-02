// Package cli is the command surface.
package cli

import (
	"fmt"

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

func newRootCmd() *cobra.Command {
	cmd := newCheckCmd()
	cmd.Use = "kube-upgrade-check"
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
			fmt.Fprintln(cmd.OutOrStdout(), version.String())
			return nil
		},
	}
}
