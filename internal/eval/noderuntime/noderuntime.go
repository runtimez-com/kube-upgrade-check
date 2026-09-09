// Package noderuntime covers breaks that live on the nodes rather than in the API: the
// container runtime, cgroup version, kubelet flags, and how far the kubelets may lag the
// control plane.
//
// Most rules here are marked undetectable, meaning no Kubernetes API exposes the underlying
// fact under any collector. Those are printed anyway, as INFO items that never move the score,
// because a reader who is about to lose their container runtime should hear about it even when
// we cannot confirm it applies to them. What the tool must never do is let an unverifiable
// item read as either a confirmed break or a clean pass.
package noderuntime

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

const (
	notAssessedRuleID   = "rtz-k8s-node-runtime-not-assessed"
	nodeSkewRuleID      = "rtz-k8s-node-skew"
	kubeProxySkewRuleID = "rtz-k8s-kube-proxy-skew"
	// maxNamed bounds how many objects a single finding lists by name.
	maxNamed = 50
)

// Analyze returns node-level findings for the hop from current to target.
func Analyze(inv *inventory.Inventory, currentVersion, targetVersion string, rules []catalog.NodeRuntimeRule) ([]report.Finding, []report.Coverage) {
	targetKey := catalog.MinorKey(targetVersion)
	if targetKey == 0 {
		return nil, nil
	}
	currentKey := catalog.MinorKey(currentVersion)

	var findings []report.Finding
	var coverage []report.Coverage

	var plain, metricBacked []catalog.NodeRuntimeRule
	for _, rule := range rules {
		if rule.Metric != nil {
			metricBacked = append(metricBacked, rule)
		} else {
			plain = append(plain, rule)
		}
	}
	findings = append(findings, alwaysAdvisory(plain, currentKey, targetKey, targetVersion, inv.ClusterName)...)

	nodesRead := inv.Read(inventory.CollectorNodes) && len(inv.Nodes) > 0
	if !nodesRead {
		reason := "no nodes could be listed, so no node-level check ran"
		if state, ok := inv.Collected[inventory.CollectorNodes]; ok && state.Reason != "" {
			reason = state.Reason
		}
		findings = append(findings, notAssessed(inv.ClusterName, reason))
		coverage = append(coverage, report.Coverage{
			Source:        "node runtime",
			State:         report.CoverageUnavailable,
			Reason:        reason,
			VerifyCommand: "kubectl get nodes -o wide",
		})
		return findings, coverage
	}

	detectable, detectCoverage := detectableRules(inv, plain, targetKey, targetVersion)
	findings = append(findings, detectable...)
	coverage = append(coverage, detectCoverage...)

	metricFindings, metricCoverage := metricRules(inv, metricBacked, currentKey, targetKey, targetVersion)
	findings = append(findings, metricFindings...)
	coverage = append(coverage, metricCoverage...)

	skewFindings, skewCoverage := kubeletSkew(inv, targetVersion)
	findings = append(findings, skewFindings...)
	coverage = append(coverage, skewCoverage...)

	// Without workloads there is no kube-proxy DaemonSet to read a version from, and silence
	// would be indistinguishable from a cluster that simply does not run kube-proxy.
	if inv.Read(inventory.CollectorWorkloads) {
		findings = append(findings, kubeProxySkew(inv, targetVersion)...)
	} else {
		coverage = append(coverage, report.Coverage{
			Source: "node runtime", Scope: "kube-proxy version skew",
			State:         report.CoverageUnavailable,
			Reason:        "workloads could not be listed, so the kube-proxy version could not be read",
			RulesSkipped:  1,
			VerifyCommand: "kubectl -n kube-system get daemonset kube-proxy -o jsonpath='{.spec.template.spec.containers[0].image}'",
		})
	}

	return findings, coverage
}

// alwaysAdvisory surfaces the rules no API can settle.
//
// Bounded to the window (current, target]: a runtime change that landed before the version the
// cluster already runs is not part of this upgrade, and printing it would bury the items that
// are. Severity is forced to INFO regardless of what the catalog says, because the catalog
// severity describes the break's impact if it applies, and we do not know that it does.
func alwaysAdvisory(rules []catalog.NodeRuntimeRule, currentKey, targetKey int, targetVersion, clusterName string) []report.Finding {
	var findings []report.Finding
	for _, rule := range rules {
		if rule.IsDetectable() {
			continue
		}
		removedKey := catalog.MinorKey(rule.RemovedInVersion)
		if removedKey == 0 || targetKey < removedKey {
			continue
		}
		if currentKey != 0 && removedKey <= currentKey {
			continue
		}
		findings = append(findings, report.Finding{
			ID:               report.NewID(rule.RuleID, clusterName),
			RuleID:           rule.RuleID,
			Title:            rule.Title + " [target " + targetVersion + "]",
			Recommendation:   rule.Remediation,
			Category:         "RELIABILITY",
			Severity:         catalog.SeverityInfo,
			ScoreImpact:      0,
			ResourceName:     clusterName,
			ResourceType:     "Cluster",
			EnforcementLevel: "advisory",
			AppliesAtVersion: catalog.MinorOf(rule.RemovedInVersion),
			Evidence: []string{
				"No Kubernetes API exposes this, so it could not be checked against your nodes.",
			},
		})
	}
	return findings
}

// detectableRules evaluates the rules that node status can actually settle.
func detectableRules(inv *inventory.Inventory, rules []catalog.NodeRuntimeRule, targetKey int, targetVersion string) ([]report.Finding, []report.Coverage) {
	var findings []report.Finding
	var coverage []report.Coverage

	for _, rule := range rules {
		if !rule.IsDetectable() || rule.StatusField == "" {
			continue
		}
		removedKey := catalog.MinorKey(rule.RemovedInVersion)
		if removedKey == 0 || targetKey < removedKey {
			continue
		}

		var matched []string
		reported := 0
		for _, node := range inv.Nodes {
			value, ok := node.Status[rule.StatusField]
			text, isText := value.(string)
			if !ok || !isText || text == "" {
				continue
			}
			reported++
			if matches(rule, text) {
				matched = append(matched, fmt.Sprintf("Node %s (%s)", node.Name, text))
			}
		}

		// No node reporting the field is not the same as no node matching it. Saying so keeps a
		// collection gap from reading as a clean result.
		if reported == 0 {
			reason := fmt.Sprintf("no node reported %s, so %s could not be checked",
				rule.StatusField, rule.RuleID)
			findings = append(findings, notAssessed(inv.ClusterName, reason))
			coverage = append(coverage, report.Coverage{
				Source: "node runtime", Scope: rule.StatusField,
				State: report.CoverageUnavailable, Reason: reason, RulesSkipped: 1,
				VerifyCommand: "kubectl get nodes -o wide",
			})
			continue
		}
		coverage = append(coverage, report.Coverage{
			Source: "node runtime", Scope: rule.StatusField, State: report.CoverageComplete,
		})

		if len(matched) == 0 {
			continue
		}
		sort.Strings(matched)
		severity := rule.Severity
		if severity.Rank() == 0 {
			severity = catalog.SeverityCritical
		}
		findings = append(findings, report.Finding{
			ID:                report.NewID(rule.RuleID, matched[0]),
			RuleID:            rule.RuleID,
			Title:             rule.Title + " [target " + targetVersion + "]",
			Recommendation:    rule.Remediation,
			Category:          "RELIABILITY",
			Severity:          severity,
			ScoreImpact:       severity.ScoreImpact(),
			ResourceName:      collapse(matched),
			ResourceType:      "Node",
			AffectedResources: cap50(matched),
			AppliesAtVersion:  catalog.MinorOf(rule.RemovedInVersion),
			Evidence:          matched,
		})
	}
	return findings, coverage
}

func matches(rule catalog.NodeRuntimeRule, value string) bool {
	switch rule.Condition {
	case "startsWith":
		return rule.Value != "" && strings.HasPrefix(value, rule.Value)
	case "equals":
		return rule.Value != "" && value == rule.Value
	case "contains":
		return rule.Value != "" && strings.Contains(value, rule.Value)
	default:
		return false
	}
}

// kubeletSkew reports nodes that would sit too far behind the target control plane.
//
// A kubelet may run at most three minor versions behind the API server. The bands are graded
// rather than binary because sitting exactly at the limit is legal but leaves no headroom, and
// that is worth saying before someone plans another hop.
func kubeletSkew(inv *inventory.Inventory, targetVersion string) ([]report.Finding, []report.Coverage) {
	var unsupported, atLimit, approaching, unreadable []string

	for _, node := range inv.Nodes {
		skew, ok := catalog.MinorSkew(node.KubeletVersion, targetVersion)
		if !ok {
			// A version we cannot read is not a version that is fine.
			unreadable = append(unreadable, fmt.Sprintf("%s (%s)", node.Name, dashIfEmpty(node.KubeletVersion)))
			continue
		}
		if skew <= 1 {
			continue
		}
		entry := fmt.Sprintf("Node %s (%s, skew %d)", node.Name, node.KubeletVersion, skew)
		switch {
		case skew > 3:
			unsupported = append(unsupported, entry)
		case skew == 3:
			atLimit = append(atLimit, entry)
		case skew == 2:
			approaching = append(approaching, entry)
		}
	}

	var findings []report.Finding
	add := func(nodes []string, severity catalog.Severity, title, recommendation string) {
		if len(nodes) == 0 {
			return
		}
		sort.Strings(nodes)
		findings = append(findings, report.Finding{
			ID:                report.NewID(nodeSkewRuleID, nodes[0]),
			RuleID:            nodeSkewRuleID,
			Title:             title,
			Recommendation:    recommendation,
			Category:          "RELIABILITY",
			Severity:          severity,
			ScoreImpact:       severity.ScoreImpact(),
			ResourceName:      collapse(nodes),
			ResourceType:      "Node",
			AffectedResources: cap50(nodes),
			AppliesAtVersion:  catalog.MinorOf(targetVersion),
			Evidence:          nodes,
		})
	}

	add(unsupported, catalog.SeverityHigh,
		"Kubelets would be more than 3 minor versions behind a "+targetVersion+" control plane, which is unsupported",
		"The kubelet may run at most 3 minor versions behind the API server. Upgrading the control plane to "+
			targetVersion+" puts these nodes outside that window. Upgrade the node groups first, or stage the control-plane upgrade.")
	add(atLimit, catalog.SeverityMedium,
		"Kubelets would sit exactly at the 3-minor skew limit on a "+targetVersion+" control plane",
		"Supported, but with no headroom: any further control-plane upgrade before these nodes are updated is out of policy. "+
			"Plan the node-group upgrade into this window.")
	add(approaching, catalog.SeverityLow,
		"Kubelets would be 2 minor versions behind a "+targetVersion+" control plane, so one more hop breaches the skew policy",
		"Within policy, so nothing breaks at "+targetVersion+". Upgrade the node groups as part of this cycle rather than letting the gap widen.")

	var coverage []report.Coverage
	if len(unreadable) > 0 {
		sort.Strings(unreadable)
		coverage = append(coverage, report.Coverage{
			Source: "node runtime", Scope: "kubelet version skew",
			State:         report.CoveragePartial,
			Reason:        "these nodes did not report a readable kubelet version, so their skew was not checked: " + strings.Join(unreadable, ", "),
			VerifyCommand: "kubectl get nodes -o wide",
		})
	}
	return findings, coverage
}

func dashIfEmpty(s string) string {
	if strings.TrimSpace(s) == "" {
		return "no version reported"
	}
	return s
}

// kubeProxySkew applies the same bands to kube-proxy, whose version comes from its DaemonSet
// image tag.
func kubeProxySkew(inv *inventory.Inventory, targetVersion string) []report.Finding {
	version := kubeProxyVersion(inv)
	if version == "" {
		return nil
	}
	skew, ok := catalog.MinorSkew(version, targetVersion)
	if !ok || skew < 2 {
		return nil
	}

	var severity catalog.Severity
	var detail string
	switch {
	case skew > 3:
		severity, detail = catalog.SeverityHigh, "more than 3 minor versions behind, which is unsupported"
	case skew == 3:
		severity, detail = catalog.SeverityMedium, "exactly at the 3-minor skew limit, with no headroom"
	default:
		severity, detail = catalog.SeverityLow, "2 minor versions behind, so one more hop breaches the skew policy"
	}

	return []report.Finding{{
		ID:     report.NewID(kubeProxySkewRuleID, "kube-proxy"),
		RuleID: kubeProxySkewRuleID,
		Title:  "kube-proxy would be " + detail + " on a " + targetVersion + " control plane",
		Recommendation: "kube-proxy follows the same version skew policy as the kubelet. Upgrade the kube-proxy DaemonSet " +
			"alongside the node groups. On a managed cluster this is usually an add-on upgrade rather than a manual change.",
		Category:         "RELIABILITY",
		Severity:         severity,
		ScoreImpact:      severity.ScoreImpact(),
		ResourceName:     "kube-proxy",
		ResourceType:     "DaemonSet",
		AppliesAtVersion: catalog.MinorOf(targetVersion),
		Evidence:         []string{fmt.Sprintf("kube-proxy image reports %s, skew %d", version, skew)},
	}}
}

// kubeProxyVersion reads the version from the kube-proxy DaemonSet's image tag.
func kubeProxyVersion(inv *inventory.Inventory) string {
	for _, w := range inv.Workloads {
		if w.Kind != "DaemonSet" || !strings.Contains(w.Name, "kube-proxy") {
			continue
		}
		for _, c := range append(append([]inventory.Container{}, w.Containers...), w.InitContainers...) {
			if tag := imageTag(c.Image); tag != "" && catalog.MinorKey(tag) != 0 {
				return tag
			}
		}
	}
	return ""
}

// imageTag returns an image reference's tag, ignoring digests and registry ports.
func imageTag(image string) string {
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at]
	}
	colon := strings.LastIndex(image, ":")
	if colon < 0 {
		return ""
	}
	// A colon after the last slash is a tag; before it, it is a registry port.
	if slash := strings.LastIndex(image, "/"); slash > colon {
		return ""
	}
	return image[colon+1:]
}

func notAssessed(clusterName, reason string) report.Finding {
	return report.Finding{
		ID:               report.NewID(notAssessedRuleID, clusterName+"|"+reason),
		RuleID:           notAssessedRuleID,
		Title:            "Node runtime checks could not run",
		Recommendation:   reason,
		Category:         "RELIABILITY",
		Severity:         catalog.SeverityInfo,
		ScoreImpact:      0,
		ResourceName:     clusterName,
		ResourceType:     "Cluster",
		EnforcementLevel: "advisory",
		Evidence:         []string{reason},
	}
}

// collapse renders a list as "first (+N more)" for the single-line resource column.
func collapse(items []string) string {
	if len(items) == 0 {
		return ""
	}
	if len(items) == 1 {
		return items[0]
	}
	return fmt.Sprintf("%s (+%d more)", items[0], len(items)-1)
}

func cap50(items []string) []string {
	if len(items) <= maxNamed {
		return items
	}
	return items[:maxNamed]
}

// MetricNames is every kubelet metric series the catalog's rules read, for the collector.
func MetricNames(rules []catalog.NodeRuntimeRule) []string {
	seen := map[string]bool{}
	var out []string
	for _, rule := range rules {
		if rule.Metric != nil && rule.Metric.Name != "" && !seen[rule.Metric.Name] {
			seen[rule.Metric.Name] = true
			out = append(out, rule.Metric.Name)
		}
	}
	sort.Strings(out)
	return out
}

// metricRules settles the rules whose evidence lives in the kubelet's /metrics endpoint.
//
// When the metrics could not be read the rule is still printed, as the advisory it would be
// without that evidence, and the gap is recorded beside it. A rule that goes quiet because
// its collector was refused is exactly the false clean this tool exists to prevent.
func metricRules(inv *inventory.Inventory, rules []catalog.NodeRuntimeRule, currentKey, targetKey int, targetVersion string) ([]report.Finding, []report.Coverage) {
	var findings []report.Finding
	var coverage []report.Coverage
	read := inv.Read(inventory.CollectorKubeletMetrics)

	for _, rule := range rules {
		removedKey := catalog.MinorKey(rule.RemovedInVersion)
		if removedKey == 0 || targetKey < removedKey {
			continue
		}
		metric := rule.Metric
		if !read {
			state := inv.Collected[inventory.CollectorKubeletMetrics]
			reason := state.Reason
			if reason == "" {
				reason = "kubelet metrics were not collected"
			}
			if currentKey == 0 || removedKey > currentKey {
				findings = append(findings, alwaysAdvisory([]catalog.NodeRuntimeRule{withoutMetric(rule)},
					currentKey, targetKey, targetVersion, inv.ClusterName)...)
			}
			coverage = append(coverage, report.Coverage{
				Source: "node runtime", Scope: metric.Name, State: report.CoverageUnavailable,
				Reason: reason, RulesSkipped: 1, VerifyCommand: state.VerifyCommand,
			})
			continue
		}

		var matched []string
		reported := 0
		for _, node := range inv.KubeletMetrics {
			if !node.Reachable {
				continue
			}
			samples, ok := node.Series[metric.Name]
			if !ok || len(samples) == 0 {
				continue
			}
			reported++
			for _, sample := range samples {
				if evidence, hit := metricMatches(metric, sample, targetKey); hit {
					matched = append(matched, fmt.Sprintf("Node %s (%s)", node.NodeName, evidence))
					break
				}
			}
		}
		if reported == 0 {
			reason := fmt.Sprintf("no kubelet reported %s (kubelets before 1.35 do not export it), so %s could not be checked",
				metric.Name, rule.RuleID)
			findings = append(findings, notAssessed(inv.ClusterName, reason))
			coverage = append(coverage, report.Coverage{
				Source: "node runtime", Scope: metric.Name, State: report.CoverageUnavailable,
				Reason: reason, RulesSkipped: 1,
				VerifyCommand: "kubectl get --raw /api/v1/nodes/<node>/proxy/metrics | grep " + metric.Name,
			})
			continue
		}
		state := report.CoverageComplete
		if inv.Collected[inventory.CollectorKubeletMetrics].Partial {
			state = report.CoveragePartial
		}
		coverage = append(coverage, report.Coverage{
			Source: "node runtime", Scope: metric.Name, State: state,
			Reason: inv.Collected[inventory.CollectorKubeletMetrics].Reason,
		})
		if len(matched) == 0 {
			continue
		}
		sort.Strings(matched)
		severity := rule.Severity
		if severity.Rank() == 0 {
			severity = catalog.SeverityCritical
		}
		findings = append(findings, report.Finding{
			ID:                report.NewID(rule.RuleID, matched[0]),
			RuleID:            rule.RuleID,
			Title:             rule.Title + " [target " + targetVersion + "]",
			Recommendation:    rule.Remediation,
			Category:          "RELIABILITY",
			Severity:          severity,
			ScoreImpact:       severity.ScoreImpact(),
			ResourceName:      collapse(matched),
			ResourceType:      "Node",
			AffectedResources: cap50(matched),
			AppliesAtVersion:  catalog.MinorOf(rule.RemovedInVersion),
			Evidence:          matched,
		})
	}
	return findings, coverage
}

// metricMatches decides one sample against a rule and returns what to print when it matches.
func metricMatches(m *catalog.MetricMatch, sample inventory.MetricSample, targetKey int) (string, bool) {
	switch m.Condition {
	case "valueEquals":
		want, err := strconv.ParseFloat(strings.TrimSpace(m.Value), 64)
		if err != nil || sample.Value != want {
			return "", false
		}
		return fmt.Sprintf("%s=%s", m.Name, strings.TrimSpace(m.Value)), true
	case "labelVersionAtMostTarget":
		version := sample.Labels[m.Label]
		key := catalog.MinorKey(version)
		if key == 0 || key > targetKey {
			return "", false
		}
		return fmt.Sprintf("%s{%s=%q}", m.Name, m.Label, version), true
	}
	return "", false
}

// withoutMetric is the rule as the advisory path sees it: an advisory is what a metric-backed
// rule falls back to when its evidence could not be read.
func withoutMetric(rule catalog.NodeRuntimeRule) catalog.NodeRuntimeRule {
	rule.Metric = nil
	no := false
	rule.Detectable = &no
	return rule
}
