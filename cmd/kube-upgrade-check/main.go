// Command kube-upgrade-check reports what breaks when a Kubernetes cluster is upgraded.
//
// It reads a cluster through the API server with the caller's own kubeconfig, evaluates an
// embedded catalog of removed APIs, config breakers, volume plugins, node runtime rules and
// add-on support windows, and prints what it found — and what it could not see.
package main

import (
	"os"

	"github.com/runtimez-com/kube-upgrade-check/internal/cli"
)

func main() {
	os.Exit(cli.Execute())
}
