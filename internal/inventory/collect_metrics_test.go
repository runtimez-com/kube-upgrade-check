package inventory

import "testing"

// The kubelet exposition mixes comments, histograms, and the two gauges a rule reads. Only the
// wanted series are kept, labels are parsed, and a line that does not parse is skipped rather
// than turned into a sample.
func TestParseMetricsKeepsOnlyWantedSeries(t *testing.T) {
	text := `# HELP kubelet_cgroup_version cgroup version on the hosts.
# TYPE kubelet_cgroup_version gauge
kubelet_cgroup_version 1
# TYPE kubelet_cri_losing_support gauge
kubelet_cri_losing_support{version="1.36"} 1
kubelet_runtime_operations_total{operation_type="version"} 42
kubelet_cri_losing_support{version="1.37"} garbage
kubelet_cgroup_version 2 1700000000
`
	got := parseMetrics(text, map[string]bool{"kubelet_cgroup_version": true, "kubelet_cri_losing_support": true})
	if len(got) != 2 {
		t.Fatalf("want 2 series, got %v", got)
	}
	if cg := got["kubelet_cgroup_version"]; len(cg) != 2 || cg[0].Value != 1 || cg[1].Value != 2 {
		t.Errorf("cgroup samples = %+v", cg)
	}
	cri := got["kubelet_cri_losing_support"]
	if len(cri) != 1 || cri[0].Labels["version"] != "1.36" || cri[0].Value != 1 {
		t.Errorf("cri samples = %+v (the unparseable line must be dropped)", cri)
	}
	if _, kept := got["kubelet_runtime_operations_total"]; kept {
		t.Error("an unwanted series must not be kept")
	}
}
