// Package plugins finds in-tree volume plugins that a target Kubernetes version no longer
// mounts.
//
// The awkward part of this family is tense. A plugin can be deprecated, disabled by default,
// or fully removed, and a cluster can already be past any of those points. A finding that says
// "migrate before upgrading to 1.33" on a cluster already running 1.34 is not just imprecise,
// it sends the reader looking for a future problem when they have a live one. So the wording
// is chosen from where the cluster actually stands, not only from where it is going.
package plugins

import (
	"fmt"
	"sort"
	"strings"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

const (
	notAssessedRuleID = "rtz-k8s-plugin-not-assessed"
	maxNamed          = 50
)

// Analyze reports every object using a volume plugin the target version breaks.
func Analyze(inv *inventory.Inventory, currentVersion, targetVersion string, rules []catalog.VolumePluginRule) ([]report.Finding, []report.Coverage) {
	targetKey := catalog.MinorKey(targetVersion)
	if targetKey == 0 {
		return nil, nil
	}
	currentKey := catalog.MinorKey(currentVersion)

	byKey := map[string]catalog.VolumePluginRule{}
	byProvisioner := map[string]catalog.VolumePluginRule{}
	for _, r := range rules {
		if r.VolumeSourceKey != "" {
			byKey[r.VolumeSourceKey] = r
		}
		if r.Provisioner != "" {
			byProvisioner[r.Provisioner] = r
		}
	}

	drivers := driverSet(inv)
	var findings []report.Finding
	var coverage []report.Coverage

	workloadsRead := inv.Read(inventory.CollectorWorkloads)
	podsRead := inv.Read(inventory.CollectorPods)
	storageRead := inv.Read(inventory.CollectorStorage)

	if workloadsRead {
		for _, w := range inv.Workloads {
			for _, key := range w.VolumeKeys {
				if f := build(byKey, key, w.Kind, w.Ref(), currentKey, targetKey, currentVersion, targetVersion, drivers, ""); f != nil {
					findings = append(findings, *f)
				}
			}
		}
	}
	if podsRead {
		for _, p := range inv.StandalonePods {
			for _, key := range p.VolumeKeys {
				if f := build(byKey, key, "Pod", p.Namespace+"/"+p.Name, currentKey, targetKey, currentVersion, targetVersion, drivers, ""); f != nil {
					findings = append(findings, *f)
				}
			}
		}
	}
	if storageRead {
		for _, pv := range inv.PersistentVolumes {
			for _, key := range pv.SpecKeys {
				if f := build(byKey, key, "PersistentVolume", pv.Name, currentKey, targetKey, currentVersion, targetVersion, drivers, ""); f != nil {
					findings = append(findings, *f)
				}
			}
		}
		usage := claimsPerClass(inv)
		for _, sc := range inv.StorageClasses {
			rule, ok := byProvisioner[sc.Provisioner]
			if !ok {
				continue
			}
			extra := ""
			// Only a positive count is reported. An absent entry means no claim was observed,
			// which is not the same as no claim existing, so a zero must never be used to
			// argue the StorageClass is unused.
			if n := usage[sc.Name]; n > 0 {
				extra = fmt.Sprintf(" %d PersistentVolumeClaim(s) name this StorageClass.", n)
			}
			if f := build(map[string]catalog.VolumePluginRule{rule.VolumeSourceKey: rule},
				rule.VolumeSourceKey, "StorageClass", sc.Name,
				currentKey, targetKey, currentVersion, targetVersion, drivers, extra); f != nil {
				findings = append(findings, *f)
			}
		}
	}

	// Volume sources live in pod specs and PersistentVolumes. If neither could be read, this
	// whole family went unchecked and the report has to say so.
	if !workloadsRead && !podsRead && !storageRead {
		reason := "workloads, pods and storage objects could not be read, so no volume plugin check ran"
		findings = append(findings, report.Finding{
			ID:               report.NewID(notAssessedRuleID, inv.ClusterName),
			RuleID:           notAssessedRuleID,
			Title:            "Volume plugin checks could not run",
			Recommendation:   reason,
			Category:         "RELIABILITY",
			Severity:         catalog.SeverityInfo,
			ResourceName:     inv.ClusterName,
			ResourceType:     "Cluster",
			EnforcementLevel: "advisory",
			Evidence:         []string{reason},
		})
		coverage = append(coverage, report.Coverage{
			Source: "volume plugins", State: report.CoverageUnavailable, Reason: reason,
			RulesSkipped:  len(rules),
			VerifyCommand: "kubectl get pv -o json | jq '.items[].spec | keys'",
		})
		return findings, coverage
	}

	state := report.CoverageComplete
	var reason string
	if !workloadsRead || !podsRead || !storageRead {
		state = report.CoveragePartial
		reason = "some object types could not be read, so the plugin scan saw only part of the cluster"
	}
	coverage = append(coverage, report.Coverage{Source: "volume plugins", State: state, Reason: reason})

	return dedupe(findings), coverage
}

// build makes one finding for an object using one plugin key, or nil when the target version
// does not break it.
func build(rules map[string]catalog.VolumePluginRule, key, kind, resourceName string,
	currentKey, targetKey int, currentVersion, targetVersion string,
	drivers driverInfo, extra string) *report.Finding {

	rule, ok := rules[key]
	if !ok {
		return nil
	}
	breakKey := catalog.MinorKey(rule.BreakIn())
	deprecatedKey := catalog.MinorKey(rule.DeprecatedIn)

	switch {
	case breakKey != 0 && targetKey >= breakKey:
		severity := rule.Severity
		if severity.Rank() == 0 {
			severity = catalog.SeverityCritical
		}
		// Past its break version, this is not upgrade preparation. The volumes are already
		// failing to mount, and the catalog's forward-looking remediation would contradict
		// that, so it is replaced rather than appended to.
		alreadyBroken := currentKey != 0 && currentKey >= breakKey
		remediation := rule.Remediation + csiReadiness(rule, drivers, false)
		title := fmt.Sprintf("%s %s uses the in-tree volume plugin %q, which stops working in %s",
			kind, resourceName, key, rule.BreakIn())
		if alreadyBroken {
			replacement := rule.ReplacementCSIDriver
			if replacement == "" {
				replacement = rule.Replacement
			}
			remediation = fmt.Sprintf(
				"%s %s uses the in-tree volume plugin %q, which the kubelet stopped honouring in %s, "+
					"before this cluster's %s. These volumes are not mounting now. The %s upgrade neither "+
					"caused this nor will fix it.%s Migrate them to %s. This is a live incident, not upgrade preparation.",
				kind, resourceName, key, rule.BreakIn(), catalog.MinorOf(currentVersion), targetVersion,
				csiReadiness(rule, drivers, true), replacement)
			title = fmt.Sprintf("%s %s uses the in-tree volume plugin %q, which already stopped working in %s",
				kind, resourceName, key, rule.BreakIn())
		}
		return &report.Finding{
			ID:               report.NewID("rtz-k8s-plugin-removed-"+key, resourceName),
			RuleID:           "rtz-k8s-plugin-removed-" + key,
			Title:            title,
			Recommendation:   remediation + extra,
			Category:         "RELIABILITY",
			Severity:         severity,
			ScoreImpact:      severity.ScoreImpact(),
			ResourceName:     resourceName,
			ResourceType:     kind,
			AppliesAtVersion: catalog.MinorOf(rule.BreakIn()),
			Evidence:         []string{fmt.Sprintf("%s %s declares volume source %q", kind, resourceName, key)},
		}

	case deprecatedKey != 0 && targetKey >= deprecatedKey:
		removal := ""
		if rule.RemovedIn != "" {
			removal = ", removed in " + rule.RemovedIn
		}
		return &report.Finding{
			ID:     report.NewID("rtz-k8s-plugin-deprecated-"+key, resourceName),
			RuleID: "rtz-k8s-plugin-deprecated-" + key,
			Title: fmt.Sprintf("%s %s uses the deprecated in-tree volume plugin %q (deprecated in %s%s)",
				kind, resourceName, key, rule.DeprecatedIn, removal),
			Recommendation:   rule.Remediation + extra,
			Category:         "RELIABILITY",
			Severity:         catalog.SeverityMedium,
			ScoreImpact:      catalog.SeverityMedium.ScoreImpact(),
			ResourceName:     resourceName,
			ResourceType:     kind,
			AppliesAtVersion: catalog.MinorOf(rule.DeprecatedIn),
			Evidence:         []string{fmt.Sprintf("%s %s declares volume source %q", kind, resourceName, key)},
		}
	}
	return nil
}

// driverInfo is the set of installed CSI drivers, plus whether we could read them at all.
type driverInfo struct {
	known bool
	names map[string]bool
}

func driverSet(inv *inventory.Inventory) driverInfo {
	if !inv.Read(inventory.CollectorStorage) {
		return driverInfo{known: false}
	}
	names := make(map[string]bool, len(inv.CSIDrivers))
	for _, d := range inv.CSIDrivers {
		names[d] = true
	}
	return driverInfo{known: true, names: names}
}

// csiReadiness says whether the replacement driver is already in place.
//
// The tense matters: once the removal is behind the cluster, "you would upgrade without it" is
// simply false, and pairing that with a present-tense body produced a finding that argued with
// itself.
func csiReadiness(rule catalog.VolumePluginRule, drivers driverInfo, past bool) string {
	driver := strings.TrimSpace(rule.ReplacementCSIDriver)
	if driver == "" {
		return ""
	}
	if !drivers.known {
		return fmt.Sprintf(" The replacement CSI driver (%s) could not be checked, because CSIDriver "+
			"objects were not readable. Verify it is installed by hand.", driver)
	}
	if drivers.names[driver] {
		if past {
			return fmt.Sprintf(" The replacement CSI driver (%s) is installed, so the remaining work "+
				"is repointing these volumes at it.", driver)
		}
		return fmt.Sprintf(" The replacement CSI driver (%s) is installed on this cluster, so the "+
			"remaining work is migrating the volumes to it.", driver)
	}
	if past {
		return fmt.Sprintf(" The replacement CSI driver (%s) is not installed, so install it before "+
			"the volumes can be repointed.", driver)
	}
	return fmt.Sprintf(" The replacement CSI driver (%s) is not installed on this cluster, so "+
		"upgrading would leave these volumes with nothing to mount them.", driver)
}

// claimsPerClass counts claims naming each StorageClass.
func claimsPerClass(inv *inventory.Inventory) map[string]int {
	usage := map[string]int{}
	for _, pvc := range inv.PVCs {
		if pvc.StorageClassName != "" {
			usage[pvc.StorageClassName]++
		}
	}
	return usage
}

// dedupe collapses repeated (rule, resource) pairs and orders the result so two runs of the
// same scan produce the same report.
func dedupe(findings []report.Finding) []report.Finding {
	seen := map[string]bool{}
	var out []report.Finding
	for _, f := range findings {
		key := f.RuleID + "|" + f.ResourceName
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, f)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].ResourceName < out[j].ResourceName
	})
	if len(out) > maxNamed*10 {
		out = out[:maxNamed*10]
	}
	return out
}
