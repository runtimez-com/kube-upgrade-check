package noderuntime

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func node(name, kubelet, runtime string) inventory.Node {
	return inventory.Node{
		Name: name, KubeletVersion: kubelet, ContainerRuntimeVersion: runtime,
		Status: map[string]any{"kubeletVersion": kubelet, "containerRuntimeVersion": runtime},
	}
}

func inv(nodes ...inventory.Node) *inventory.Inventory {
	return &inventory.Inventory{
		ClusterName: "test",
		Nodes:       nodes,
		Collected:   map[string]inventory.CollectionState{inventory.CollectorNodes: {OK: true}},
	}
}

func dockershimRule() catalog.NodeRuntimeRule {
	detectable := true
	return catalog.NodeRuntimeRule{
		RuleID: "rtz-k8s-node-dockershim-removed", StatusField: "containerRuntimeVersion",
		Condition: "startsWith", Value: "docker://", RemovedInVersion: "1.24",
		Severity: catalog.SeverityCritical, Title: "Dockershim removed", Remediation: "Move to containerd.",
		Detectable: &detectable,
	}
}

func undetectableRule(id, removedIn string) catalog.NodeRuntimeRule {
	detectable := false
	return catalog.NodeRuntimeRule{
		RuleID: id, RemovedInVersion: removedIn, Severity: catalog.SeverityHigh,
		Title: "Something node-level changes", Remediation: "Check your nodes.", Detectable: &detectable,
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

func TestDockershimDetected(t *testing.T) {
	findings, _ := Analyze(
		inv(node("n1", "v1.23.5", "docker://20.10.7"), node("n2", "v1.23.5", "containerd://1.6.6")),
		"1.23", "1.24", []catalog.NodeRuntimeRule{dockershimRule()})

	f := byRule(findings, "rtz-k8s-node-dockershim-removed")
	if f == nil {
		t.Fatal("dockershim not detected")
	}
	if f.Severity != catalog.SeverityCritical || f.ScoreImpact != 40 {
		t.Errorf("got %s/%d, want CRITICAL/40", f.Severity, f.ScoreImpact)
	}
	if len(f.AffectedResources) != 1 || !strings.Contains(f.AffectedResources[0], "n1") {
		t.Errorf("expected only n1 named, got %v", f.AffectedResources)
	}
}

// A field no node reports is a collection gap, not a clean result.
func TestNoNodeReportsFieldIsNotAssessedRatherThanClean(t *testing.T) {
	bare := node("n1", "v1.23.5", "")
	bare.Status = map[string]any{"kubeletVersion": "v1.23.5"}
	findings, coverage := Analyze(inv(bare), "1.23", "1.24", []catalog.NodeRuntimeRule{dockershimRule()})

	if byRule(findings, notAssessedRuleID) == nil {
		t.Error("expected a not-assessed finding when no node reported the field")
	}
	var unavailable bool
	for _, c := range coverage {
		if c.State == report.CoverageUnavailable {
			unavailable = true
		}
	}
	if !unavailable {
		t.Error("expected an UNAVAILABLE coverage row")
	}
}

func TestUndetectableRulesPrintAsInfoAndNeverScore(t *testing.T) {
	findings, _ := Analyze(inv(node("n1", "v1.34.1", "containerd://1.7.0")),
		"1.34", "1.35", []catalog.NodeRuntimeRule{undetectableRule("rtz-k8s-node-cgroupv1-fails-1.35", "1.35")})

	f := byRule(findings, "rtz-k8s-node-cgroupv1-fails-1.35")
	if f == nil {
		t.Fatal("an undetectable rule on the path must still be printed")
	}
	if f.Severity != catalog.SeverityInfo || f.ScoreImpact != 0 {
		t.Errorf("undetectable items must be INFO/0, got %s/%d", f.Severity, f.ScoreImpact)
	}
	if f.EnforcementLevel != "advisory" {
		t.Errorf("expected advisory enforcement, got %q", f.EnforcementLevel)
	}
	if len(f.Evidence) == 0 || !strings.Contains(f.Evidence[0], "could not be checked") {
		t.Errorf("an unverifiable item must say so: %v", f.Evidence)
	}
}

// A change already in effect on the running cluster is not part of this upgrade.
func TestUndetectableRuleAtOrBelowCurrentDoesNotFire(t *testing.T) {
	findings, _ := Analyze(inv(node("n1", "v1.35.1", "containerd://1.7.0")),
		"1.35", "1.36", []catalog.NodeRuntimeRule{undetectableRule("already-in-effect", "1.35")})
	if byRule(findings, "already-in-effect") != nil {
		t.Error("a rule at the current version must not fire")
	}
}

func TestKubeletSkewBands(t *testing.T) {
	cases := []struct {
		kubelet  string
		target   string
		severity catalog.Severity
		want     bool
	}{
		{"v1.34.1", "1.34", "", false},
		{"v1.33.1", "1.34", "", false},
		{"v1.32.1", "1.34", catalog.SeverityLow, true},
		{"v1.31.1", "1.34", catalog.SeverityMedium, true},
		{"v1.30.1", "1.34", catalog.SeverityHigh, true},
	}
	for _, tc := range cases {
		findings, _ := Analyze(inv(node("n1", tc.kubelet, "containerd://1.7.0")), "1.33", tc.target, nil)
		f := byRule(findings, nodeSkewRuleID)
		if !tc.want {
			if f != nil {
				t.Errorf("kubelet %s target %s: expected no skew finding, got %s", tc.kubelet, tc.target, f.Severity)
			}
			continue
		}
		if f == nil {
			t.Errorf("kubelet %s target %s: expected a %s skew finding", tc.kubelet, tc.target, tc.severity)
			continue
		}
		if f.Severity != tc.severity {
			t.Errorf("kubelet %s target %s: got %s, want %s", tc.kubelet, tc.target, f.Severity, tc.severity)
		}
	}
}

func TestKubeProxySkewFromImageTag(t *testing.T) {
	i := inv(node("n1", "v1.34.1", "containerd://1.7.0"))
	i.Collected[inventory.CollectorWorkloads] = inventory.CollectionState{OK: true}
	i.Workloads = []inventory.Workload{{
		Kind: "DaemonSet", Namespace: "kube-system", Name: "kube-proxy",
		Containers: []inventory.Container{{Name: "kube-proxy", Image: "registry.k8s.io/kube-proxy:v1.30.2"}},
	}}
	findings, _ := Analyze(i, "1.33", "1.34", nil)
	f := byRule(findings, kubeProxySkewRuleID)
	if f == nil {
		t.Fatal("expected a kube-proxy skew finding")
	}
	if f.Severity != catalog.SeverityHigh {
		t.Errorf("got %s, want HIGH for a 4-minor gap", f.Severity)
	}
}

func TestImageTagIgnoresRegistryPortsAndDigests(t *testing.T) {
	cases := map[string]string{
		"registry.k8s.io/kube-proxy:v1.30.2":         "v1.30.2",
		"localhost:5000/kube-proxy":                  "",
		"localhost:5000/kube-proxy:v1.29.0":          "v1.29.0",
		"registry.k8s.io/kube-proxy@sha256:abcd1234": "",
	}
	for image, want := range cases {
		if got := imageTag(image); got != want {
			t.Errorf("imageTag(%q) = %q, want %q", image, got, want)
		}
	}
}

func TestUnreadNodesReportNotAssessed(t *testing.T) {
	i := &inventory.Inventory{
		ClusterName: "test",
		Collected: map[string]inventory.CollectionState{
			inventory.CollectorNodes: {OK: false, Reason: "permission denied: nodes is forbidden"},
		},
	}
	findings, coverage := Analyze(i, "1.33", "1.34", []catalog.NodeRuntimeRule{dockershimRule()})
	f := byRule(findings, notAssessedRuleID)
	if f == nil {
		t.Fatal("expected a not-assessed finding when nodes could not be read")
	}
	if !strings.Contains(f.Recommendation, "forbidden") {
		t.Errorf("the reason should reach the reader: %q", f.Recommendation)
	}
	if len(coverage) == 0 || coverage[0].State != report.CoverageUnavailable {
		t.Error("expected an UNAVAILABLE coverage row")
	}
}

func TestRealCatalogRuns(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	findings, _ := Analyze(
		inv(node("n1", "v1.33.1", "containerd://1.7.0"), node("n2", "v1.33.1", "containerd://1.7.0")),
		"1.33", "1.35", cat.NodeRuntime)
	for _, f := range findings {
		if f.Severity == catalog.SeverityInfo && f.ScoreImpact != 0 {
			t.Errorf("%s is INFO but scores %d", f.RuleID, f.ScoreImpact)
		}
	}
	t.Logf("%d findings on the 1.33 to 1.35 hop", len(findings))
}

// A version we cannot read is not a version that is fine. Before this, an unparseable kubelet
// version was dropped exactly like a node already at the target.
func TestUnreadableKubeletVersionIsReportedNotIgnored(t *testing.T) {
	i := inv(node("n1", "", "containerd://1.7.0"), node("n2", "not-a-version", "containerd://1.7.0"))
	findings, coverage := Analyze(i, "1.33", "1.34", nil)

	if byRule(findings, nodeSkewRuleID) != nil {
		t.Error("an unreadable version must not produce a skew finding")
	}
	var row *report.Coverage
	for idx := range coverage {
		if coverage[idx].Scope == "kubelet version skew" {
			row = &coverage[idx]
		}
	}
	if row == nil || row.State == report.CoverageComplete {
		t.Fatalf("expected a non-complete coverage row for unreadable versions, got %+v", coverage)
	}
	if !strings.Contains(row.Reason, "n1") || !strings.Contains(row.Reason, "n2") {
		t.Errorf("both nodes should be named: %q", row.Reason)
	}
}

// Losing the workload list means the kube-proxy version cannot be read, which must not look the
// same as a cluster that does not run kube-proxy.
func TestMissingWorkloadsReportsKubeProxyGap(t *testing.T) {
	i := inv(node("n1", "v1.34.1", "containerd://1.7.0"))
	i.Collected[inventory.CollectorWorkloads] = inventory.CollectionState{OK: false, Reason: "forbidden"}

	_, coverage := Analyze(i, "1.33", "1.34", nil)
	var found bool
	for _, c := range coverage {
		if c.Scope == "kube-proxy version skew" && c.State == report.CoverageUnavailable {
			found = true
		}
	}
	if !found {
		t.Errorf("expected an UNAVAILABLE kube-proxy coverage row, got %+v", coverage)
	}
}

func metricInv(collected inventory.CollectionState, nodes ...inventory.KubeletMetrics) *inventory.Inventory {
	in := inv(node("n1", "v1.34.0", "containerd://1.7.0"), node("n2", "v1.34.0", "containerd://2.0.0"))
	in.KubeletMetrics = nodes
	in.Collected[inventory.CollectorKubeletMetrics] = collected
	return in
}

func cgroupRule() catalog.NodeRuntimeRule {
	r := undetectableRule("rtz-k8s-node-cgroupv1-fails-1.35", "1.35")
	r.Severity = catalog.SeverityCritical
	r.Metric = &catalog.MetricMatch{Name: "kubelet_cgroup_version", Condition: "valueEquals", Value: "1"}
	return r
}

func criRule() catalog.NodeRuntimeRule {
	r := undetectableRule("rtz-k8s-node-cri-losing-support", "1.36")
	r.Severity = catalog.SeverityCritical
	r.Metric = &catalog.MetricMatch{Name: "kubelet_cri_losing_support", Condition: "labelVersionAtMostTarget", Label: "version"}
	return r
}

func series(name string, value float64, labels map[string]string) map[string][]inventory.MetricSample {
	return map[string][]inventory.MetricSample{name: {{Labels: labels, Value: value}}}
}

// A cgroup v1 node is named from its own kubelet's gauge, a v2 node is left alone, and the
// check reports itself as complete.
func TestCgroupVersionFromKubeletMetrics(t *testing.T) {
	in := metricInv(inventory.CollectionState{OK: true},
		inventory.KubeletMetrics{NodeName: "n1", Reachable: true, Series: series("kubelet_cgroup_version", 1, nil)},
		inventory.KubeletMetrics{NodeName: "n2", Reachable: true, Series: series("kubelet_cgroup_version", 2, nil)},
	)
	findings, coverage := Analyze(in, "1.34", "1.35", []catalog.NodeRuntimeRule{cgroupRule()})
	f := byRule(findings, "rtz-k8s-node-cgroupv1-fails-1.35")
	if f == nil {
		t.Fatal("the cgroup v1 node must be reported")
	}
	if f.Severity != catalog.SeverityCritical || f.EnforcementLevel == "advisory" {
		t.Errorf("a settled rule is a break, got %+v", f)
	}
	if len(f.AffectedResources) != 1 || !strings.Contains(f.AffectedResources[0], "n1") {
		t.Errorf("only n1 runs cgroup v1: %v", f.AffectedResources)
	}
	var complete bool
	for _, c := range coverage {
		if c.Scope == "kubelet_cgroup_version" && c.State == report.CoverageComplete {
			complete = true
		}
	}
	if !complete {
		t.Errorf("a checked metric must be a complete coverage row: %+v", coverage)
	}
}

// The CRI gauge names the version at which support ends. It fires on an upgrade that reaches
// that version and not before.
func TestCRILosingSupportBoundByTarget(t *testing.T) {
	in := metricInv(inventory.CollectionState{OK: true},
		inventory.KubeletMetrics{NodeName: "n1", Reachable: true,
			Series: series("kubelet_cri_losing_support", 1, map[string]string{"version": "1.36"})},
	)
	findings, _ := Analyze(in, "1.34", "1.36", []catalog.NodeRuntimeRule{criRule()})
	if byRule(findings, "rtz-k8s-node-cri-losing-support") == nil {
		t.Fatal("a runtime losing support at 1.36 must fire for a 1.36 target")
	}
	findings, _ = Analyze(in, "1.34", "1.35", []catalog.NodeRuntimeRule{criRule()})
	if byRule(findings, "rtz-k8s-node-cri-losing-support") != nil {
		t.Error("the rule is not on the path to 1.35")
	}
	in2 := metricInv(inventory.CollectionState{OK: true},
		inventory.KubeletMetrics{NodeName: "n1", Reachable: true,
			Series: series("kubelet_cri_losing_support", 1, map[string]string{"version": "1.38"})},
	)
	findings, _ = Analyze(in2, "1.35", "1.36", []catalog.NodeRuntimeRule{criRule()})
	if byRule(findings, "rtz-k8s-node-cri-losing-support") != nil {
		t.Error("a runtime supported through 1.38 must not fire for a 1.36 target")
	}
}

// Refused metrics leave the rule as the advisory it would be without evidence, plus a gap.
// Silence here would be a clean report earned by a missing permission.
func TestUnreadableMetricsKeepTheAdvisoryAndRecordTheGap(t *testing.T) {
	in := metricInv(inventory.CollectionState{OK: false, Reason: "permission denied: nodes/proxy", VerifyCommand: "kubectl get --raw ..."})
	findings, coverage := Analyze(in, "1.34", "1.35", []catalog.NodeRuntimeRule{cgroupRule()})
	f := byRule(findings, "rtz-k8s-node-cgroupv1-fails-1.35")
	if f == nil || f.EnforcementLevel != "advisory" || f.Severity != catalog.SeverityInfo {
		t.Fatalf("want the advisory fallback, got %+v", f)
	}
	var gap bool
	for _, c := range coverage {
		if c.Scope == "kubelet_cgroup_version" && c.State == report.CoverageUnavailable && strings.Contains(c.Reason, "permission denied") {
			gap = true
		}
	}
	if !gap {
		t.Errorf("the refusal must be a coverage row: %+v", coverage)
	}
}

// Kubelets older than 1.35 do not export the gauge. No node reporting it is not a pass.
func TestMetricNotReportedIsNotAssessed(t *testing.T) {
	in := metricInv(inventory.CollectionState{OK: true},
		inventory.KubeletMetrics{NodeName: "n1", Reachable: true, Series: map[string][]inventory.MetricSample{}},
	)
	findings, coverage := Analyze(in, "1.33", "1.35", []catalog.NodeRuntimeRule{cgroupRule()})
	if byRule(findings, "rtz-k8s-node-cgroupv1-fails-1.35") != nil {
		t.Error("nothing reported the gauge, so nothing can fire")
	}
	if byRule(findings, notAssessedRuleID) == nil {
		t.Error("an unreported metric must be flagged as not assessed")
	}
	var gap bool
	for _, c := range coverage {
		if c.Scope == "kubelet_cgroup_version" && c.State == report.CoverageUnavailable {
			gap = true
		}
	}
	if !gap {
		t.Errorf("want an unavailable row: %+v", coverage)
	}
}

func TestMetricNamesComeFromTheCatalog(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	names := MetricNames(cat.NodeRuntime)
	if len(names) != 2 || names[0] != "kubelet_cgroup_version" || names[1] != "kubelet_cri_losing_support" {
		t.Errorf("names = %v", names)
	}
}
