package cli

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/cluster"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/addons"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/advisory"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/configbreaker"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/noderuntime"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/plugins"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/removedapi"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/render"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
	"github.com/runtimez-com/kube-upgrade-check/internal/score"
	"github.com/runtimez-com/kube-upgrade-check/internal/source"
	"github.com/runtimez-com/kube-upgrade-check/internal/support"
	"github.com/runtimez-com/kube-upgrade-check/internal/version"
)

type checkOptions struct {
	kubeconfig string
	context    string
	target     string
	output     string
	failOn     string
	catalogDir string
	timeout    time.Duration
	strict     bool
}

func newCheckCmd() *cobra.Command {
	var opts checkOptions

	cmd := &cobra.Command{
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error { return runCheck(cmd, opts) },
	}

	flags := cmd.Flags()
	flags.StringVar(&opts.kubeconfig, "kubeconfig", "", "path to the kubeconfig file (defaults to the usual locations)")
	flags.StringVar(&opts.context, "context", "", "kubeconfig context to use (defaults to the current one)")
	flags.StringVar(&opts.target, "target", "", "Kubernetes version to check against, e.g. 1.34 (defaults to one minor up)")
	flags.StringVarP(&opts.output, "output", "o", "table", "output format: table, wide, json or yaml")
	flags.StringVar(&opts.failOn, "fail-on", "", "exit 4 when findings reach this severity: low, medium, high or critical")
	flags.StringVar(&opts.catalogDir, "catalog-dir", "", "read rule catalogs from this directory instead of the embedded copy")
	flags.DurationVar(&opts.timeout, "timeout", cluster.DefaultTimeout, "give up on the cluster after this long")
	flags.BoolVar(&opts.strict, "strict", false, "treat anything that could not be checked as a failure, for CI")

	return cmd
}

func runCheck(cmd *cobra.Command, opts checkOptions) error {
	threshold, err := failOnThreshold(opts.failOn)
	if err != nil {
		return err
	}
	format, err := render.ParseFormat(opts.output)
	if err != nil {
		return usageErrorf("%v", err)
	}
	cat, err := loadCatalog(opts.catalogDir)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(cmd.Context(), opts.timeout)
	defer cancel()

	client, err := cluster.Connect(cluster.Options{Kubeconfig: opts.kubeconfig, Context: opts.context})
	if err != nil {
		return &ExitError{Code: ExitAuth, Err: err}
	}
	info, err := client.Identify(ctx)
	if err != nil {
		return &ExitError{Code: ExitAuth, Err: fmt.Errorf("could not reach the cluster: %w", err)}
	}

	currentVersion := info.GitVersion
	targetVersion := opts.target
	if targetVersion == "" {
		targetVersion = catalog.NextMinor(currentVersion)
		if targetVersion == "" {
			return usageErrorf("could not read a version from the cluster (%q), so --target is required", currentVersion)
		}
	}
	if catalog.MinorKey(targetVersion) == 0 {
		return usageErrorf("--target %q is not a Kubernetes version like 1.34", opts.target)
	}
	// Kubernetes control planes do not go backwards, and every rule in the catalog is phrased as
	// "what breaks on the way up". Answering a downgrade would produce a confident report about
	// a path that does not exist.
	if skew, ok := catalog.MinorSkew(currentVersion, targetVersion); ok && skew < 0 {
		return usageErrorf(
			"this cluster already runs %s, so --target %s would be a downgrade. Kubernetes control "+
				"planes cannot move backwards, and this tool only reports what breaks on the way up",
			catalog.MinorOf(currentVersion), catalog.MinorOf(targetVersion))
	}
	if skew, ok := catalog.MinorSkew(currentVersion, targetVersion); ok && skew == 0 {
		return usageErrorf(
			"this cluster already runs %s, so there is nothing to check. Pass --target %s to see "+
				"what the next upgrade would break",
			catalog.MinorOf(currentVersion), catalog.NextMinor(currentVersion))
	}

	inv := inventory.Collect(ctx, client, info)
	// Which custom resources matter is decided by the add-on catalogs, so the list is read from
	// them rather than hard-coded here.
	inventory.CollectCustomResources(ctx, client, inv, addonInventoryKinds(cat))
	evidence := source.Scan(ctx, client, cat, targetVersion)
	inv.APIUsage = source.ToInventory(evidence.Usages)

	result := assemble(inv, evidence, cat, currentVersion, targetVersion, time.Now())
	result.ToolVersion = version.String()

	printer := &render.Printer{Out: cmd.OutOrStdout(), Format: format}
	if err := printer.Print(result); err != nil {
		return err
	}

	severities := make([]catalog.Severity, 0, len(result.Findings))
	for _, f := range result.Findings {
		severities = append(severities, f.Severity)
	}
	gateErr := gate(threshold, severities, "findings")

	// A gap is only a failure when the caller asked for it to be. By default an unreadable
	// check is reported and the run still succeeds, because most people scanning their own
	// cluster cannot grant themselves more permission on the spot.
	//
	// Both gates report before either exits. Someone who sets both should learn how many
	// findings crossed their threshold as well as that something went unchecked.
	if opts.strict && result.ScanStatus != report.ScanComplete {
		if gateErr != nil {
			fmt.Fprintf(os.Stderr, "%v\n", gateErr)
		}
		return &ExitError{Code: ExitPolicy,
			Err: fmt.Errorf("some checks could not run and --strict was set")}
	}

	if err := gateErr; err != nil {
		// The gate is the answer, not an error: the report already printed, so this exits with
		// the agreed code without printing a failure on top of a successful scan.
		var exit *ExitError
		if ok := asExit(err, &exit); ok {
			fmt.Fprintf(os.Stderr, "%v\n", exit.Err)
			lastExitCode = exit.Code
			return nil
		}
		return err
	}
	return nil
}

// assemble runs every evaluator and folds the results into one report.
func assemble(inv *inventory.Inventory, evidence source.Result, cat *catalog.Catalog,
	currentVersion, targetVersion string, now time.Time) report.Result {

	var findings []report.Finding
	var coverage []report.Coverage

	// Every collector's outcome becomes a row first. Each evaluator reports the gaps it knows
	// about, but a collector that failed for a reason no evaluator happens to consult would
	// otherwise leave no trace, and the scan would call itself complete. --strict is derived
	// from this slice, so anything missing from it is something the gate cannot catch.
	coverage = append(coverage, collectorCoverage(inv)...)

	findings = append(findings, removedapi.Analyze(inv.APIUsage, currentVersion, targetVersion, cat)...)
	coverage = append(coverage, evidence.Coverage...)
	coverage = append(coverage, removedapi.ServedButUnused(evidence.Served, cat, targetVersion))

	cbFindings, cbCoverage := configbreaker.Analyze(inv, currentVersion, targetVersion, cat.ConfigBreakers)
	findings = append(findings, cbFindings...)
	coverage = append(coverage, cbCoverage...)

	plFindings, plCoverage := plugins.Analyze(inv, currentVersion, targetVersion, cat.VolumePlugins)
	findings = append(findings, plFindings...)
	coverage = append(coverage, plCoverage...)

	nrFindings, nrCoverage := noderuntime.Analyze(inv, currentVersion, targetVersion, cat.NodeRuntime)
	findings = append(findings, nrFindings...)
	coverage = append(coverage, nrCoverage...)

	findings = append(findings, advisory.Analyze(currentVersion, targetVersion, inv.ClusterName, cat.Advisories)...)

	addonResult := addons.Analyze(inv, currentVersion, targetVersion, cat.Addons, now)
	findings = append(findings, addonResult.Findings...)
	coverage = append(coverage, addonResult.Coverage...)

	report.Sort(findings)
	scoreValue, level := score.Compute(findings)

	return report.Result{
		Cluster:                 inv.ClusterName,
		Provider:                inv.Provider,
		CurrentVersion:          currentVersion,
		TargetVersion:           targetVersion,
		NodeCount:               len(inv.Nodes),
		Score:                   scoreValue,
		RiskLevel:               level,
		Support:                 support.Status(inv.Provider, currentVersion, now),
		PatchCurrency:           support.PatchCurrency(currentVersion),
		Findings:                findings,
		FindingCountsBySeverity: report.CountBySeverity(findings),
		Addons:                  addonResult.Addons,
		Coverage:                coverage,
		ScanStatus:              report.StatusFor(coverage),
		CheckedAt:               now.UTC(),
	}
}

// collectorCoverage turns what each collector managed to read into report rows.
func collectorCoverage(inv *inventory.Inventory) []report.Coverage {
	var out []report.Coverage
	for _, outcome := range inv.CoverageRows() {
		state := report.CoverageComplete
		switch {
		case !outcome.State.OK:
			state = report.CoverageUnavailable
		case outcome.State.Partial:
			state = report.CoveragePartial
		}
		out = append(out, report.Coverage{
			Source:        outcome.Name,
			State:         state,
			Reason:        outcome.State.Reason,
			VerifyCommand: outcome.State.VerifyCommand,
		})
	}
	return out
}

// addonInventoryKinds is every custom resource kind the catalogs ask about.
func addonInventoryKinds(cat *catalog.Catalog) []string {
	seen := map[string]bool{}
	var kinds []string
	for _, addon := range cat.Addons {
		for _, declared := range addon.InventoryKinds {
			if !seen[declared] {
				seen[declared] = true
				kinds = append(kinds, declared)
			}
		}
	}
	return kinds
}

func asExit(err error, target **ExitError) bool {
	e, ok := err.(*ExitError)
	if ok {
		*target = e
	}
	return ok
}
