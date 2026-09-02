package configbreaker

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func apiserver(args ...string) inventory.ControlPlanePod {
	return inventory.ControlPlanePod{
		Name: "kube-apiserver-node1", Namespace: "kube-system",
		Container: "kube-apiserver", Component: "kube-apiserver", Args: args,
	}
}

func kubelet(node string, config map[string]any) inventory.KubeletConfig {
	return inventory.KubeletConfig{NodeName: node, Reachable: true, Config: config}
}

func inv(pods []inventory.ControlPlanePod, configs []inventory.KubeletConfig) *inventory.Inventory {
	return &inventory.Inventory{
		ClusterName: "test", ControlPlanePods: pods, KubeletConfigs: configs,
		Collected: map[string]inventory.CollectionState{
			inventory.CollectorControlPlanePods: {OK: len(pods) > 0},
			inventory.CollectorKubeletConfig:    {OK: len(configs) > 0},
		},
	}
}

func gateRule(id, gate, appliesFrom string) catalog.ConfigBreakerRule {
	return catalog.ConfigBreakerRule{
		RuleID: id, Source: sourceComponentFlag, Component: "kube-apiserver",
		Selectors: []string{"--feature-gates"}, Condition: "featureGateList", Value: gate,
		AppliesFromVersion: appliesFrom, Severity: catalog.SeverityCritical,
		Title: "Feature gate " + gate + " was removed", Remediation: "Remove the gate.",
	}
}

func byRule(findings []report.Finding, ruleID string) *report.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

// A gate whose name merely contains another gate's name must not fire it. A loose match here
// would report a break on a cluster that is fine.
func TestFeatureGatePrefixCollisionNeverMatches(t *testing.T) {
	rule := gateRule("gate-hpa", "HPAContainerMetrics", "1.32")

	fired, _ := Analyze(inv([]inventory.ControlPlanePod{
		apiserver("kube-apiserver", "--feature-gates=HPAContainerMetricsV2=true"),
	}, nil), "1.31", "1.32", []catalog.ConfigBreakerRule{rule})
	if byRule(fired, "gate-hpa") != nil {
		t.Error("HPAContainerMetricsV2 must not match the rule for HPAContainerMetrics")
	}

	fired, _ = Analyze(inv([]inventory.ControlPlanePod{
		apiserver("kube-apiserver", "--feature-gates=HPAContainerMetrics=true,OtherGate=false"),
	}, nil), "1.31", "1.32", []catalog.ConfigBreakerRule{rule})
	if byRule(fired, "gate-hpa") == nil {
		t.Error("the exact gate name must match")
	}
}

func TestFeatureGateFlagInBothArgumentForms(t *testing.T) {
	rule := gateRule("gate-hpa", "HPAContainerMetrics", "1.32")
	for _, args := range [][]string{
		{"kube-apiserver", "--feature-gates=HPAContainerMetrics=true"},
		{"kube-apiserver", "--feature-gates", "HPAContainerMetrics=true"},
	} {
		fired, _ := Analyze(inv([]inventory.ControlPlanePod{apiserver(args...)}, nil),
			"1.31", "1.32", []catalog.ConfigBreakerRule{rule})
		if byRule(fired, "gate-hpa") == nil {
			t.Errorf("gate not matched in args form %v", args)
		}
	}
}

// A locked gate only breaks when explicitly set to the non-default value.
func TestLockedGateNeedsTheExplicitValue(t *testing.T) {
	rule := catalog.ConfigBreakerRule{
		RuleID: "gate-locked", Source: sourceComponentFlag, Component: "kube-apiserver",
		Selectors: []string{"--feature-gates"}, Condition: "featureGateListValueEquals",
		Value: "RetryGenerateName=false", AppliesFromVersion: "1.32",
		Severity: catalog.SeverityCritical, Title: "Gate locked", Remediation: "Remove it.",
	}
	fired, _ := Analyze(inv([]inventory.ControlPlanePod{
		apiserver("kube-apiserver", "--feature-gates=RetryGenerateName=true"),
	}, nil), "1.31", "1.32", []catalog.ConfigBreakerRule{rule})
	if byRule(fired, "gate-locked") != nil {
		t.Error("a gate set to the default value must not fire")
	}

	// Case-insensitive on the value: False and false are the same setting.
	fired, _ = Analyze(inv([]inventory.ControlPlanePod{
		apiserver("kube-apiserver", "--feature-gates=RetryGenerateName=False"),
	}, nil), "1.31", "1.32", []catalog.ConfigBreakerRule{rule})
	if byRule(fired, "gate-locked") == nil {
		t.Error("the explicit non-default value must fire regardless of case")
	}
}

// An unset field is not equal to anything. Treating it as a match would fire on every cluster
// running the default.
func TestAbsentKubeletFieldNeverSatisfiesEquals(t *testing.T) {
	rule := catalog.ConfigBreakerRule{
		RuleID: "kubelet-qps", Source: sourceKubeletConfig, Selectors: []string{"eventRecordQPS"},
		Condition: "equals", Value: "0", AppliesFromVersion: "1.37",
		Severity: catalog.SeverityMedium, Title: "Unlimited event QPS", Remediation: "Set a limit.",
	}
	fired, _ := Analyze(inv(nil, []inventory.KubeletConfig{kubelet("n1", map[string]any{"cgroupDriver": "systemd"})}),
		"1.36", "1.37", []catalog.ConfigBreakerRule{rule})
	if byRule(fired, "kubelet-qps") != nil {
		t.Error("an absent field must not satisfy equals")
	}

	fired, _ = Analyze(inv(nil, []inventory.KubeletConfig{kubelet("n1", map[string]any{"eventRecordQPS": float64(0)})}),
		"1.36", "1.37", []catalog.ConfigBreakerRule{rule})
	if byRule(fired, "kubelet-qps") == nil {
		t.Error("the set value must match, including across numeric formatting")
	}
}

func TestDottedSelectorResolves(t *testing.T) {
	rule := catalog.ConfigBreakerRule{
		RuleID: "swap", Source: sourceKubeletConfig, Selectors: []string{"memorySwap.swapBehavior"},
		Condition: "equals", Value: "UnlimitedSwap", AppliesFromVersion: "1.30",
		Severity: catalog.SeverityHigh, Title: "UnlimitedSwap dropped", Remediation: "Change it.",
	}
	config := map[string]any{"memorySwap": map[string]any{"swapBehavior": "UnlimitedSwap"}}
	fired, _ := Analyze(inv(nil, []inventory.KubeletConfig{kubelet("n1", config)}),
		"1.29", "1.30", []catalog.ConfigBreakerRule{rule})
	if byRule(fired, "swap") == nil {
		t.Error("a dotted selector must resolve through nested objects")
	}
}

// An unreachable kubelet proves nothing, so it must not be counted as compliant.
func TestUnreachableKubeletIsNotTreatedAsCompliant(t *testing.T) {
	i := &inventory.Inventory{
		ClusterName: "test",
		KubeletConfigs: []inventory.KubeletConfig{
			{NodeName: "n1", Reachable: false, Reason: "permission denied on nodes/proxy"},
		},
		Collected: map[string]inventory.CollectionState{
			inventory.CollectorKubeletConfig: {OK: false, Reason: "permission denied on nodes/proxy"},
		},
	}
	rule := catalog.ConfigBreakerRule{
		RuleID: "kubelet-runonce", Source: sourceKubeletConfig, Selectors: []string{"runOnce"},
		Condition: "present", AppliesFromVersion: "1.32", Severity: catalog.SeverityCritical,
		Title: "runOnce removed", Remediation: "Remove it.",
	}
	findings, coverage := Analyze(i, "1.31", "1.32", []catalog.ConfigBreakerRule{rule})
	if byRule(findings, kubeletNotAssessedRuleID) == nil && byRule(findings, notAssessedRuleID) == nil {
		t.Error("an unreachable kubelet must produce a not-assessed finding")
	}
	var sawUnavailable bool
	for _, c := range coverage {
		if c.State == report.CoverageUnavailable && c.RulesSkipped > 0 {
			sawUnavailable = true
		}
	}
	if !sawUnavailable {
		t.Errorf("expected an UNAVAILABLE coverage row with a skipped count, got %+v", coverage)
	}
}

// The managed-control-plane case: hundreds of rules genuinely cannot run, and the report has to
// say so with a number rather than staying silent.
func TestManagedControlPlaneReportsSkippedCount(t *testing.T) {
	rules := []catalog.ConfigBreakerRule{
		gateRule("gate-a", "GateA", "1.32"),
		gateRule("gate-b", "GateB", "1.32"),
		{RuleID: "kubelet-x", Source: sourceKubeletConfig, Selectors: []string{"runOnce"},
			Condition: "present", AppliesFromVersion: "1.32", Severity: catalog.SeverityCritical,
			Title: "x", Remediation: "y"},
	}
	i := inv(nil, []inventory.KubeletConfig{kubelet("n1", map[string]any{"cgroupDriver": "systemd"})})
	i.Collected[inventory.CollectorControlPlanePods] = inventory.CollectionState{
		OK:     false,
		Reason: "no static control-plane pods found, which is normal on a managed control plane",
	}

	findings, coverage := Analyze(i, "1.31", "1.32", rules)
	f := byRule(findings, controlPlaneNotAssessedRuleID)
	if f == nil {
		t.Fatal("expected a control-plane not-assessed finding")
	}
	if !strings.Contains(f.Recommendation, "2 control-plane rules were not checked") {
		t.Errorf("the count of unchecked rules must reach the reader: %q", f.Recommendation)
	}
	if f.ScoreImpact != 0 || f.Severity != catalog.SeverityInfo {
		t.Errorf("a coverage gap must not move the score, got %s/%d", f.Severity, f.ScoreImpact)
	}
	var row *report.Coverage
	for i := range coverage {
		if coverage[i].Source == "control-plane flags" {
			row = &coverage[i]
		}
	}
	if row == nil || row.State != report.CoverageUnavailable || row.RulesSkipped != 2 {
		t.Errorf("expected an UNAVAILABLE control-plane row with 2 skipped, got %+v", row)
	}
}

// A rule can bite twice: a soft warning first, then fatally.
func TestDeprecationTierUsesItsOwnRuleIdAndSeverity(t *testing.T) {
	rule := catalog.ConfigBreakerRule{
		RuleID: "flag-x", Source: sourceComponentFlag, Component: "kube-apiserver",
		Selectors: []string{"--concurrent-service-syncs"}, Condition: "present",
		DeprecatedInVersion: "1.31", AppliesFromVersion: "1.37",
		Severity: catalog.SeverityCritical, DeprecatedSeverity: catalog.SeverityLow,
		Title: "Flag removed", Remediation: "Remove it.",
	}
	pods := []inventory.ControlPlanePod{apiserver("kube-apiserver", "--concurrent-service-syncs=5")}

	findings, _ := Analyze(inv(pods, nil), "1.30", "1.32", []catalog.ConfigBreakerRule{rule})
	f := byRule(findings, "flag-x-deprecated")
	if f == nil {
		t.Fatal("expected the deprecation tier before the removal version")
	}
	if f.Severity != catalog.SeverityLow || f.AppliesAtVersion != "1.31" {
		t.Errorf("got %s at %s, want LOW at 1.31", f.Severity, f.AppliesAtVersion)
	}

	findings, _ = Analyze(inv(pods, nil), "1.36", "1.37", []catalog.ConfigBreakerRule{rule})
	f = byRule(findings, "flag-x")
	if f == nil || f.Severity != catalog.SeverityCritical {
		t.Errorf("expected the CRITICAL tier at the removal version, got %+v", f)
	}
}

func TestComponentSetMatching(t *testing.T) {
	rule := catalog.ConfigBreakerRule{
		RuleID: "multi", Source: sourceComponentFlag,
		Component: "kube-apiserver,kube-scheduler,kube-controller-manager",
		Selectors: []string{"--feature-gates"}, Condition: "featureGateList", Value: "SomeGate",
		AppliesFromVersion: "1.32", Severity: catalog.SeverityCritical, Title: "t", Remediation: "r",
	}
	pods := []inventory.ControlPlanePod{{
		Name: "kube-scheduler-node1", Namespace: "kube-system", Container: "kube-scheduler",
		Component: "kube-scheduler", Args: []string{"kube-scheduler", "--feature-gates=SomeGate=true"},
	}}
	findings, _ := Analyze(inv(pods, nil), "1.31", "1.32", []catalog.ConfigBreakerRule{rule})
	if byRule(findings, "multi") == nil {
		t.Error("a comma-separated component set must match any of its members")
	}
}

func TestRealCatalogRunsAgainstEmptyInventory(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	i := &inventory.Inventory{ClusterName: "test", Collected: map[string]inventory.CollectionState{}}
	findings, coverage := Analyze(i, "1.33", "1.34", cat.ConfigBreakers)

	if byRule(findings, notAssessedRuleID) == nil {
		t.Error("an empty inventory must produce the both-surfaces not-assessed finding")
	}
	var skipped int
	for _, c := range coverage {
		skipped += c.RulesSkipped
	}
	if skipped == 0 {
		t.Error("the coverage rows must account for the rules that did not run")
	}
	t.Logf("%d of %d catalog rules reported as unchecked", skipped, len(cat.ConfigBreakers))
}

func TestRealCatalogDetectsAKnownGate(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	pods := []inventory.ControlPlanePod{
		apiserver("kube-apiserver", "--feature-gates=HPAContainerMetrics=true"),
	}
	findings, _ := Analyze(inv(pods, nil), "1.31", "1.32", cat.ConfigBreakers)
	if byRule(findings, "rtz-k8s-gate-removed-hpa-container-metrics") == nil {
		t.Error("expected the removed HPAContainerMetrics gate to be detected from the real catalog")
	}
}
