package cli

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/addons/predicates"
)

func newCatalogCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "catalog",
		Short: "Inspect and validate the embedded rule catalog",
	}
	cmd.AddCommand(newCatalogListCmd(), newCatalogValidateCmd())
	return cmd
}

func newCatalogListCmd() *cobra.Command {
	var catalogDir string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "Summarise what the catalog covers",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cat, err := loadCatalog(catalogDir)
			if err != nil {
				return err
			}
			out := cmd.OutOrStdout()
			fmt.Fprintf(out, "Removed and deprecated APIs   %d rules, %d detector rows\n",
				len(cat.DeprecationRules), len(cat.DetectorTable))
			fmt.Fprintf(out, "Config breakers               %d rules\n", len(cat.ConfigBreakers))
			fmt.Fprintf(out, "Volume plugins                %d rules\n", len(cat.VolumePlugins))
			fmt.Fprintf(out, "Node runtime                  %d rules\n", len(cat.NodeRuntime))
			fmt.Fprintf(out, "Advisories                    %d rules\n", len(cat.Advisories))
			fmt.Fprintf(out, "Adoption suggestions          %d rules\n", len(cat.AdoptionRules))
			fmt.Fprintf(out, "\nAdd-ons (%d)\n", len(cat.Addons))
			for _, a := range cat.Addons {
				windows := fmt.Sprintf("%d support windows", len(a.SupportWindows))
				if len(a.SupportWindows) == 0 {
					windows = "no vendor compatibility matrix published"
				}
				fmt.Fprintf(out, "  %-16s %-42s %d rules, %d upgrade notes\n  %-16s verified %s · %s\n",
					a.AddonID, windows, len(a.Rules), len(a.UpgradeNotes), "", dashIfEmpty(a.Source.LastVerified), a.Source.URL)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&catalogDir, "catalog-dir", "", "read catalogs from this directory instead of the embedded copy")
	return cmd
}

func newCatalogValidateCmd() *cobra.Command {
	var catalogDir string
	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Check the catalog is loadable and internally consistent",
		Long: `Check the catalog is loadable and internally consistent.

Run this after editing a catalog file. It is the same check CI runs, and it is what stops a
rule that names a predicate nobody implemented from shipping as a rule that silently never
fires.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cat, err := loadCatalog(catalogDir)
			if err != nil {
				return err
			}
			problems := validate(cat)
			out := cmd.OutOrStdout()
			if len(problems) > 0 {
				for _, p := range problems {
					fmt.Fprintf(out, "  %s\n", p)
				}
				return &ExitError{Code: ExitFailure,
					Err: fmt.Errorf("%d catalog problem(s)", len(problems))}
			}
			fmt.Fprintf(out, "Catalog OK: %d API rules, %d config breakers, %d volume plugins, "+
				"%d node runtime, %d advisories, %d add-ons, %d adoption suggestions\n",
				len(cat.DeprecationRules), len(cat.ConfigBreakers), len(cat.VolumePlugins),
				len(cat.NodeRuntime), len(cat.Advisories), len(cat.Addons), len(cat.AdoptionRules))
			return nil
		},
	}
	cmd.Flags().StringVar(&catalogDir, "catalog-dir", "", "read catalogs from this directory instead of the embedded copy")
	return cmd
}

// validate reports every internal inconsistency in one pass, so a contributor fixing a
// catalog sees the whole list rather than discovering problems one run at a time.
func validate(cat *catalog.Catalog) []string {
	var problems []string
	seen := map[string]string{}

	note := func(format string, args ...any) {
		problems = append(problems, fmt.Sprintf(format, args...))
	}
	unique := func(family, id string) {
		if id == "" {
			note("%s: a rule has an empty ruleId", family)
			return
		}
		if prev, dup := seen[id]; dup {
			note("duplicate ruleId %q in %s and %s", id, prev, family)
			return
		}
		seen[id] = family
	}

	for _, r := range cat.DeprecationRules {
		unique("k8s-deprecations", r.RuleID)
		if r.APIVersion == "" || r.Kind == "" {
			note("k8s-deprecations %s: apiVersion and kind are both required", r.RuleID)
		}
		if catalog.MinorKey(r.RemovedIn) == 0 && catalog.MinorKey(r.DeprecatedIn) == 0 {
			note("k8s-deprecations %s: neither removedIn nor deprecatedIn parses as a version", r.RuleID)
		}
	}
	for _, r := range cat.ConfigBreakers {
		unique("k8s-config-breakers", r.RuleID)
		if r.Source != "componentFlag" && r.Source != "kubeletConfig" {
			note("k8s-config-breakers %s: unknown source %q", r.RuleID, r.Source)
		}
		if catalog.MinorKey(r.AppliesFromVersion) == 0 {
			note("k8s-config-breakers %s: appliesFromVersion %q does not parse", r.RuleID, r.AppliesFromVersion)
		}
		if len(r.Selectors) == 0 {
			note("k8s-config-breakers %s: no selectors, so it can never match", r.RuleID)
		}
		if r.DeprecatedSeverity != "" && r.DeprecatedInVersion == "" {
			note("k8s-config-breakers %s: deprecatedSeverity without deprecatedInVersion is unreachable", r.RuleID)
		}
	}
	for _, p := range cat.VolumePlugins {
		if p.VolumeSourceKey == "" {
			note("k8s-plugins: a plugin has no volumeSourceKey")
		}
		if p.BreakIn() == "" && p.DeprecatedIn == "" {
			note("k8s-plugins %s: no version at which anything happens", p.VolumeSourceKey)
		}
	}
	for _, r := range cat.NodeRuntime {
		unique("k8s-node-runtime", r.RuleID)
		if r.IsDetectable() && r.StatusField == "" {
			note("k8s-node-runtime %s: marked detectable but names no status field", r.RuleID)
		}
	}
	for _, r := range cat.Advisories {
		unique("k8s-advisory", r.RuleID)
		if catalog.MinorKey(r.Version) == 0 {
			note("k8s-advisory %s: version %q does not parse", r.RuleID, r.Version)
		}
		// Every advisory is unverifiable by definition, so the command a reader can run
		// themselves is the entire value of the row.
		if strings.TrimSpace(r.VerifyCommand) == "" {
			note("k8s-advisory %s: no verifyCommand, leaving the reader nothing to check", r.RuleID)
		}
	}

	known := predicates.Registry()
	for _, a := range cat.Addons {
		if len(a.Detect.ImageSuffixes) == 0 {
			note("k8s-addons %s: no detect.imageSuffixes, so it can never be detected", a.AddonID)
		}
		if len(a.SupportWindows) == 0 && a.LatestKnownVersion == "" {
			note("k8s-addons %s: no supportWindows and no latestKnownVersion, so upgrade notes "+
				"have no version anchor and would never render", a.AddonID)
		}
		for _, r := range a.Rules {
			unique("k8s-addons/"+a.AddonID, r.RuleID)
			if _, ok := known[r.Kind]; !ok {
				note("k8s-addons %s: rule %s names predicate kind %q, which nothing implements",
					a.AddonID, r.RuleID, r.Kind)
			}
			if r.Severity.Rank() == 0 {
				note("k8s-addons %s: rule %s has unknown severity %q", a.AddonID, r.RuleID, r.Severity)
			}
			// A finding without the vendor's own words is an assertion the reader cannot check.
			if strings.TrimSpace(r.Quote) == "" || strings.TrimSpace(r.SourceURL) == "" {
				note("k8s-addons %s: rule %s has no quote or no sourceUrl", a.AddonID, r.RuleID)
			}
		}
		for _, n := range a.UpgradeNotes {
			if strings.TrimSpace(n.Quote) == "" || strings.TrimSpace(n.SourceURL) == "" {
				note("k8s-addons %s: upgrade note %q has no quote or no sourceUrl", a.AddonID, n.Title)
			}
		}
	}

	sort.Strings(problems)
	return problems
}

func loadCatalog(dir string) (*catalog.Catalog, error) {
	if dir != "" {
		cat, err := catalog.LoadDir(dir)
		if err != nil {
			return nil, fmt.Errorf("load catalog from %s: %w", dir, err)
		}
		return cat, nil
	}
	cat, err := catalog.Load()
	if err != nil {
		return nil, fmt.Errorf("load embedded catalog: %w", err)
	}
	return cat, nil
}

func dashIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "never"
	}
	return s
}
