// Package configbreaker finds control-plane and kubelet settings that a target Kubernetes
// version refuses to start with.
//
// These are the breaks nobody sees coming. A removed flag or a feature gate locked to its
// default does not fail a manifest review or a dry run: the component simply refuses to start
// after the upgrade, which on a control plane means the cluster does not come back.
//
// The catalog is large, and most of it is only checkable when the control plane runs as static
// pods inside the cluster. On EKS, GKE and AKS it does not, so several hundred rules genuinely
// cannot be evaluated. Those are counted and reported as unchecked. Staying silent about them
// would let a managed cluster read as though every rule had passed.
package configbreaker

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
	notAssessedRuleID             = "rtz-k8s-config-not-assessed"
	controlPlaneNotAssessedRuleID = "rtz-k8s-config-controlplane-not-assessed"
	kubeletNotAssessedRuleID      = "rtz-k8s-config-kubelet-not-assessed"

	sourceComponentFlag = "componentFlag"
	sourceKubeletConfig = "kubeletConfig"

	maxNamed = 50
)

// Analyze evaluates every detectable config-breaker rule against what was collected.
func Analyze(inv *inventory.Inventory, currentVersion, targetVersion string, rules []catalog.ConfigBreakerRule) ([]report.Finding, []report.Coverage) {
	targetKey := catalog.MinorKey(targetVersion)
	if targetKey == 0 {
		return nil, nil
	}

	var flagRules, kubeletRules []catalog.ConfigBreakerRule
	for _, r := range rules {
		if !r.IsDetectable() || len(r.Selectors) == 0 {
			continue
		}
		switch r.Source {
		case sourceComponentFlag:
			flagRules = append(flagRules, r)
		case sourceKubeletConfig:
			kubeletRules = append(kubeletRules, r)
		}
	}

	// Reachability, not mere presence: a kubelet we could not query tells us nothing, and
	// counting it as compliant is exactly the false clean this package guards against.
	var reachable []inventory.KubeletConfig
	for _, kc := range inv.KubeletConfigs {
		if kc.Reachable {
			reachable = append(reachable, kc)
		}
	}
	haveControlPlane := len(inv.ControlPlanePods) > 0
	haveKubelet := len(reachable) > 0

	var findings []report.Finding
	var coverage []report.Coverage

	if haveControlPlane {
		findings = append(findings, evaluateFlags(inv.ControlPlanePods, flagRules, targetKey, targetVersion)...)
		coverage = append(coverage, report.Coverage{
			Source: "control-plane flags", State: report.CoverageComplete,
			Scope: fmt.Sprintf("%d static pods", len(inv.ControlPlanePods)),
		})
	}
	if haveKubelet {
		findings = append(findings, evaluateKubelet(reachable, kubeletRules, targetKey, targetVersion)...)
		state, reason := report.CoverageComplete, ""
		if len(reachable) < len(inv.KubeletConfigs) {
			state = report.CoveragePartial
			reason = fmt.Sprintf("%d of %d kubelets answered, so these rules were checked against part of the fleet",
				len(reachable), len(inv.KubeletConfigs))
		}
		coverage = append(coverage, report.Coverage{
			Source: "kubelet configuration", State: state, Reason: reason,
			Scope: fmt.Sprintf("%d nodes", len(reachable)),
		})
	}

	notAssessed, notAssessedCoverage := gaps(inv, haveControlPlane, haveKubelet, len(flagRules), len(kubeletRules))
	findings = append(findings, notAssessed...)
	coverage = append(coverage, notAssessedCoverage...)

	sort.SliceStable(findings, func(i, j int) bool { return findings[i].RuleID < findings[j].RuleID })
	return findings, coverage
}

// evaluateFlags checks rules against control-plane static-pod arguments.
func evaluateFlags(pods []inventory.ControlPlanePod, rules []catalog.ConfigBreakerRule, targetKey int, targetVersion string) []report.Finding {
	var findings []report.Finding

	for _, rule := range rules {
		components := map[string]bool{}
		for _, c := range rule.Components() {
			components[c] = true
		}

		var matched []string
		for _, pod := range pods {
			if !components[pod.Component] {
				continue
			}
			if evidence := flagMatch(pod.Args, rule); evidence != "" {
				matched = append(matched, fmt.Sprintf("%s/%s: %s", pod.Namespace, pod.Name, evidence))
			}
		}
		if len(matched) == 0 {
			continue
		}
		if f := build(rule, targetKey, targetVersion, matched, "Pod"); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

// flagMatch returns the observed evidence when a rule's condition holds for these arguments.
func flagMatch(args []string, rule catalog.ConfigBreakerRule) string {
	switch rule.Condition {
	case "present":
		for _, selector := range rule.Selectors {
			for _, arg := range args {
				if arg == selector || strings.HasPrefix(arg, selector+"=") {
					return arg
				}
			}
		}
	case "featureGateList":
		for _, list := range gateLists(args, rule.Selectors) {
			for _, pair := range strings.Split(list, ",") {
				if gateName(pair) == rule.Value {
					return rule.Selectors[0] + " sets " + strings.TrimSpace(pair)
				}
			}
		}
	case "featureGateListValueEquals":
		want, wantValue, ok := strings.Cut(rule.Value, "=")
		if !ok {
			return ""
		}
		for _, list := range gateLists(args, rule.Selectors) {
			for _, pair := range strings.Split(list, ",") {
				name, value, found := strings.Cut(pair, "=")
				if !found {
					continue
				}
				if strings.TrimSpace(name) == want && strings.EqualFold(strings.TrimSpace(value), wantValue) {
					return rule.Selectors[0] + " sets " + strings.TrimSpace(pair)
				}
			}
		}
	case "equals":
		for _, selector := range rule.Selectors {
			for i, arg := range args {
				value, ok := flagValue(args, i, arg, selector)
				if !ok {
					continue
				}
				if valuesEqual(value, rule.Value) {
					return selector + "=" + value
				}
			}
		}
	}
	return ""
}

// gateLists returns the value of every feature-gate flag among the arguments.
//
// Both spellings are handled: kubeadm writes "--feature-gates=A=true,B=false" as one token,
// while a hand-written manifest may split the flag and its value across two.
func gateLists(args []string, selectors []string) []string {
	var out []string
	for _, selector := range selectors {
		for i, arg := range args {
			if value, ok := flagValue(args, i, arg, selector); ok {
				out = append(out, value)
			}
		}
	}
	return out
}

func flagValue(args []string, i int, arg, selector string) (string, bool) {
	if strings.HasPrefix(arg, selector+"=") {
		return arg[len(selector)+1:], true
	}
	if arg == selector && i+1 < len(args) {
		return args[i+1], true
	}
	return "", false
}

// gateName is the key half of a "Gate=value" entry.
//
// Compared exactly, never by prefix or substring: a gate named HPAContainerMetricsV2 shares a
// prefix with HPAContainerMetrics, and a loose match would report a break on a cluster that is
// fine.
func gateName(pair string) string {
	name, _, _ := strings.Cut(pair, "=")
	return strings.TrimSpace(name)
}

// evaluateKubelet checks rules against each node's live kubelet configuration.
func evaluateKubelet(configs []inventory.KubeletConfig, rules []catalog.ConfigBreakerRule, targetKey int, targetVersion string) []report.Finding {
	var findings []report.Finding

	for _, rule := range rules {
		var matched []string
		for _, cfg := range configs {
			if evidence := kubeletMatch(cfg.Config, rule); evidence != "" {
				matched = append(matched, fmt.Sprintf("Node %s: %s", cfg.NodeName, evidence))
			}
		}
		if len(matched) == 0 {
			continue
		}
		if f := build(rule, targetKey, targetVersion, matched, "Node"); f != nil {
			findings = append(findings, *f)
		}
	}
	return findings
}

// kubeletMatch returns the observed evidence when a rule's condition holds for this config.
func kubeletMatch(config map[string]any, rule catalog.ConfigBreakerRule) string {
	for _, selector := range rule.Selectors {
		field, present := resolve(config, selector)

		switch rule.Condition {
		case "present":
			if present {
				return fmt.Sprintf("%s is set to %v", selector, field)
			}
		case "absent":
			if !present {
				return selector + " is not set"
			}
		case "equals":
			// An absent field never satisfies equals. Treating "unset" as equal to the value
			// a rule names would fire on every cluster running the default.
			if !present {
				continue
			}
			if valuesEqual(scalar(field), rule.Value) {
				return fmt.Sprintf("%s is %v", selector, field)
			}
		case "featureGateMap":
			gates, ok := field.(map[string]any)
			if !ok || rule.Value == "" {
				continue
			}
			if value, has := gates[rule.Value]; has {
				return fmt.Sprintf("%s.%s is %v", selector, rule.Value, value)
			}
		case "featureGateMapValueEquals":
			gates, ok := field.(map[string]any)
			if !ok {
				continue
			}
			want, wantValue, found := strings.Cut(rule.Value, "=")
			if !found {
				continue
			}
			value, has := gates[want]
			if !has || value == nil {
				continue
			}
			// Only an explicit non-default setting breaks a locked gate. Presence alone is
			// fine here, unlike a removed gate, so the value has to be compared.
			if strings.EqualFold(strings.TrimSpace(scalar(value)), strings.TrimSpace(wantValue)) {
				return fmt.Sprintf("%s.%s is %v", selector, want, value)
			}
		}
	}
	return ""
}

// resolve walks a selector, which may be a bare field name or a dotted path.
func resolve(config map[string]any, selector string) (any, bool) {
	if !strings.Contains(selector, ".") {
		v, ok := config[selector]
		return v, ok && v != nil
	}
	var current any = config
	for _, part := range strings.Split(selector, ".") {
		obj, ok := current.(map[string]any)
		if !ok {
			return nil, false
		}
		current, ok = obj[part]
		if !ok || current == nil {
			return nil, false
		}
	}
	return current, true
}

// scalar renders a JSON value for comparison.
func scalar(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	default:
		return fmt.Sprintf("%v", t)
	}
}

// valuesEqual compares two settings, treating numerically equal values as equal so that a
// config saying 0 matches a rule written as 0.0.
func valuesEqual(actual, expected string) bool {
	if actual == "" || expected == "" {
		return false
	}
	if actual == expected {
		return true
	}
	a, errA := strconv.ParseFloat(actual, 64)
	b, errB := strconv.ParseFloat(expected, 64)
	return errA == nil && errB == nil && a == b
}

// build turns a matched rule into a finding, choosing between the breaking and the deprecation
// tier.
//
// A rule can bite in two stages: deprecated first at a lower severity, then fatal. Reporting
// only the fatal stage would leave a reader with no warning during the window where they could
// still act calmly.
func build(rule catalog.ConfigBreakerRule, targetKey int, targetVersion string, matched []string, resourceType string) *report.Finding {
	sort.Strings(matched)

	appliesKey := catalog.MinorKey(rule.AppliesFromVersion)
	deprecatedKey := catalog.MinorKey(rule.DeprecatedInVersion)

	ruleID := rule.RuleID
	severity := rule.Severity
	appliesAt := rule.AppliesFromVersion

	switch {
	case appliesKey != 0 && targetKey >= appliesKey:
		// The breaking tier; severity as the catalog states it.
	case deprecatedKey != 0 && rule.DeprecatedSeverity != "" && targetKey >= deprecatedKey:
		ruleID += "-deprecated"
		severity = rule.DeprecatedSeverity
		appliesAt = rule.DeprecatedInVersion
	default:
		return nil
	}

	if severity.Rank() == 0 {
		severity = catalog.SeverityCritical
	}

	return &report.Finding{
		ID:                report.NewID(ruleID, matched[0]),
		RuleID:            ruleID,
		Title:             rule.Title + " [target " + targetVersion + "]",
		Recommendation:    rule.Remediation,
		Category:          "RELIABILITY",
		Severity:          severity,
		ScoreImpact:       severity.ScoreImpact(),
		ResourceName:      collapse(matched),
		ResourceType:      resourceType,
		AffectedResources: capNamed(matched),
		AppliesAtVersion:  catalog.MinorOf(appliesAt),
		Evidence:          capNamed(matched),
	}
}

// gaps reports the rule families that could not be evaluated at all.
func gaps(inv *inventory.Inventory, haveControlPlane, haveKubelet bool, flagRules, kubeletRules int) ([]report.Finding, []report.Coverage) {
	var findings []report.Finding
	var coverage []report.Coverage

	controlPlaneReason := "no static control-plane pods were found. On EKS, GKE and AKS the provider " +
		"runs the API server, scheduler and controller manager outside the cluster, so their flags " +
		"cannot be read from here"
	if state, ok := inv.Collected[inventory.CollectorControlPlanePods]; ok && state.Reason != "" {
		controlPlaneReason = state.Reason
	}
	kubeletReason := "no node's kubelet configuration could be read"
	if state, ok := inv.Collected[inventory.CollectorKubeletConfig]; ok && state.Reason != "" {
		kubeletReason = state.Reason
	}

	switch {
	case !haveControlPlane && !haveKubelet:
		total := flagRules + kubeletRules
		reason := fmt.Sprintf("neither control-plane flags nor kubelet configuration could be read, "+
			"so none of the %d configuration rules were checked", total)
		findings = append(findings, notAssessedFinding(notAssessedRuleID, inv.ClusterName,
			"Configuration checks could not run", reason))
		coverage = append(coverage,
			report.Coverage{Source: "control-plane flags", State: report.CoverageUnavailable,
				Reason: controlPlaneReason, RulesSkipped: flagRules,
				VerifyCommand: "kubectl get pods -n kube-system -l tier=control-plane -o yaml"},
			report.Coverage{Source: "kubelet configuration", State: report.CoverageUnavailable,
				Reason: kubeletReason, RulesSkipped: kubeletRules,
				VerifyCommand: "kubectl get --raw /api/v1/nodes/<node>/proxy/configz"})

	case !haveControlPlane:
		reason := fmt.Sprintf("%s, so %d control-plane rules were not checked", controlPlaneReason, flagRules)
		findings = append(findings, notAssessedFinding(controlPlaneNotAssessedRuleID, inv.ClusterName,
			"Control-plane flag checks could not run", reason))
		coverage = append(coverage, report.Coverage{
			Source: "control-plane flags", State: report.CoverageUnavailable,
			Reason: controlPlaneReason, RulesSkipped: flagRules,
			VerifyCommand: "kubectl get pods -n kube-system -l tier=control-plane -o yaml",
		})

	case !haveKubelet:
		reason := fmt.Sprintf("%s, so %d kubelet rules were not checked", kubeletReason, kubeletRules)
		findings = append(findings, notAssessedFinding(kubeletNotAssessedRuleID, inv.ClusterName,
			"Kubelet configuration checks could not run", reason))
		coverage = append(coverage, report.Coverage{
			Source: "kubelet configuration", State: report.CoverageUnavailable,
			Reason: kubeletReason, RulesSkipped: kubeletRules,
			VerifyCommand: "kubectl get --raw /api/v1/nodes/<node>/proxy/configz",
		})
	}

	return findings, coverage
}

func notAssessedFinding(ruleID, clusterName, title, reason string) report.Finding {
	return report.Finding{
		ID:               report.NewID(ruleID, clusterName),
		RuleID:           ruleID,
		Title:            title,
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

func collapse(items []string) string {
	switch len(items) {
	case 0:
		return ""
	case 1:
		return items[0]
	default:
		return fmt.Sprintf("%s (+%d more)", items[0], len(items)-1)
	}
}

func capNamed(items []string) []string {
	if len(items) <= maxNamed {
		return items
	}
	return items[:maxNamed]
}
