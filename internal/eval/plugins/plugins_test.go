package plugins

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func allRead() map[string]inventory.CollectionState {
	return map[string]inventory.CollectionState{
		inventory.CollectorWorkloads: {OK: true},
		inventory.CollectorPods:      {OK: true},
		inventory.CollectorStorage:   {OK: true},
	}
}

// gitRepo is the plugin that is disabled by default before it is formally removed, which is
// what BreakIn() exists to capture.
func gitRepoRule() catalog.VolumePluginRule {
	return catalog.VolumePluginRule{
		VolumeSourceKey: "gitRepo", DeprecatedIn: "1.11", RemovedIn: "1.36",
		DisabledByDefaultIn: "1.33", Replacement: "an init container that clones the repository",
		Severity: catalog.SeverityCritical, Remediation: "Replace the gitRepo volume with an init container.",
	}
}

func awsEBSRule() catalog.VolumePluginRule {
	return catalog.VolumePluginRule{
		VolumeSourceKey: "awsElasticBlockStore", DeprecatedIn: "1.19", RemovedIn: "1.27",
		Replacement: "the EBS CSI driver", Severity: catalog.SeverityCritical,
		Remediation: "Migrate to the EBS CSI driver before upgrading.",
		Provisioner: "kubernetes.io/aws-ebs", ReplacementCSIDriver: "ebs.csi.aws.com",
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

// A plugin disabled by default is already broken. Anchoring on formal removal would report it
// three minors too late.
func TestBreakInPrefersDisabledByDefault(t *testing.T) {
	inv := &inventory.Inventory{
		ClusterName: "test", Collected: allRead(),
		Workloads: []inventory.Workload{{
			Kind: "Deployment", Namespace: "app", Name: "web", VolumeKeys: []string{"gitRepo"},
		}},
	}
	findings, _ := Analyze(inv, "1.32", "1.33", []catalog.VolumePluginRule{gitRepoRule()})
	f := byRule(findings, "rtz-k8s-plugin-removed-gitRepo")
	if f == nil {
		t.Fatal("gitRepo must fire at 1.33, where it is disabled by default")
	}
	if f.Severity != catalog.SeverityCritical || f.AppliesAtVersion != "1.33" {
		t.Errorf("got %s at %s, want CRITICAL at 1.33", f.Severity, f.AppliesAtVersion)
	}
}

func TestBelowBreakVersionReportsDeprecatedNotBroken(t *testing.T) {
	inv := &inventory.Inventory{
		ClusterName: "test", Collected: allRead(),
		Workloads: []inventory.Workload{{Kind: "Deployment", Namespace: "app", Name: "web", VolumeKeys: []string{"gitRepo"}}},
	}
	findings, _ := Analyze(inv, "1.30", "1.31", []catalog.VolumePluginRule{gitRepoRule()})
	if byRule(findings, "rtz-k8s-plugin-removed-gitRepo") != nil {
		t.Error("must not report a break before the break version")
	}
	f := byRule(findings, "rtz-k8s-plugin-deprecated-gitRepo")
	if f == nil || f.Severity != catalog.SeverityMedium {
		t.Errorf("expected a MEDIUM deprecation finding, got %+v", f)
	}
}

// Past the break version the wording must describe a live failure, not upgrade preparation.
func TestAlreadyBrokenChangesTheWording(t *testing.T) {
	inv := &inventory.Inventory{
		ClusterName: "test", Collected: allRead(),
		Workloads: []inventory.Workload{{Kind: "Deployment", Namespace: "app", Name: "web", VolumeKeys: []string{"gitRepo"}}},
	}
	findings, _ := Analyze(inv, "1.34", "1.35", []catalog.VolumePluginRule{gitRepoRule()})
	f := byRule(findings, "rtz-k8s-plugin-removed-gitRepo")
	if f == nil {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(f.Recommendation, "not mounting now") {
		t.Errorf("an already-broken plugin should describe a live failure: %q", f.Recommendation)
	}
	if strings.Contains(f.Recommendation, "before upgrading") {
		t.Errorf("forward-looking prose must not survive on an already-broken plugin: %q", f.Recommendation)
	}
	// A plugin with no CSI replacement must fall back to the prose replacement, never print
	// an empty string where a driver name belongs.
	if strings.Contains(f.Recommendation, "Migrate them to .") {
		t.Errorf("empty replacement leaked into the prose: %q", f.Recommendation)
	}
}

func TestCSIReadinessReportsInstalledDriver(t *testing.T) {
	inv := &inventory.Inventory{
		ClusterName: "test", Collected: allRead(),
		PersistentVolumes: []inventory.PersistentVolume{{Name: "pv-1", SpecKeys: []string{"awsElasticBlockStore", "capacity"}}},
		CSIDrivers:        []string{"ebs.csi.aws.com"},
	}
	findings, _ := Analyze(inv, "1.26", "1.27", []catalog.VolumePluginRule{awsEBSRule()})
	f := byRule(findings, "rtz-k8s-plugin-removed-awsElasticBlockStore")
	if f == nil {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(f.Recommendation, "is installed on this cluster") {
		t.Errorf("should report the driver as present: %q", f.Recommendation)
	}
}

// Not reading CSIDrivers is different from reading them and finding none.
func TestUnknownCSIDriversSaysSoRatherThanAssumingAbsent(t *testing.T) {
	inv := &inventory.Inventory{
		ClusterName: "test",
		Collected: map[string]inventory.CollectionState{
			inventory.CollectorWorkloads: {OK: true},
			inventory.CollectorPods:      {OK: true},
			inventory.CollectorStorage:   {OK: false, Reason: "permission denied"},
		},
		Workloads: []inventory.Workload{{Kind: "Deployment", Namespace: "app", Name: "web", VolumeKeys: []string{"awsElasticBlockStore"}}},
	}
	findings, _ := Analyze(inv, "1.26", "1.27", []catalog.VolumePluginRule{awsEBSRule()})
	f := byRule(findings, "rtz-k8s-plugin-removed-awsElasticBlockStore")
	if f == nil {
		t.Fatal("expected a finding")
	}
	if !strings.Contains(f.Recommendation, "could not be checked") {
		t.Errorf("an unreadable driver list must be stated, not assumed: %q", f.Recommendation)
	}
}

func TestStorageClassCountsClaimsButNeverArguesFromZero(t *testing.T) {
	inv := &inventory.Inventory{
		ClusterName: "test", Collected: allRead(),
		StorageClasses: []inventory.StorageClass{{Name: "gp2", Provisioner: "kubernetes.io/aws-ebs"}},
		PVCs: []inventory.PVC{
			{Namespace: "a", Name: "c1", StorageClassName: "gp2"},
			{Namespace: "b", Name: "c2", StorageClassName: "gp2"},
		},
	}
	findings, _ := Analyze(inv, "1.26", "1.27", []catalog.VolumePluginRule{awsEBSRule()})
	f := byRule(findings, "rtz-k8s-plugin-removed-awsElasticBlockStore")
	if f == nil {
		t.Fatal("expected a StorageClass finding")
	}
	if !strings.Contains(f.Recommendation, "2 PersistentVolumeClaim(s)") {
		t.Errorf("expected the claim count: %q", f.Recommendation)
	}

	// With no claims observed, the finding must still fire and must not claim it is unused.
	inv.PVCs = nil
	findings, _ = Analyze(inv, "1.26", "1.27", []catalog.VolumePluginRule{awsEBSRule()})
	f = byRule(findings, "rtz-k8s-plugin-removed-awsElasticBlockStore")
	if f == nil {
		t.Fatal("a StorageClass with no observed claims must still be reported")
	}
	if strings.Contains(f.Recommendation, "0 PersistentVolumeClaim") {
		t.Errorf("a zero count must not be printed as evidence of disuse: %q", f.Recommendation)
	}
}

func TestNothingReadableReportsNotAssessed(t *testing.T) {
	inv := &inventory.Inventory{
		ClusterName: "test",
		Collected: map[string]inventory.CollectionState{
			inventory.CollectorWorkloads: {OK: false, Reason: "forbidden"},
			inventory.CollectorPods:      {OK: false, Reason: "forbidden"},
			inventory.CollectorStorage:   {OK: false, Reason: "forbidden"},
		},
	}
	findings, coverage := Analyze(inv, "1.26", "1.27", []catalog.VolumePluginRule{awsEBSRule()})
	if byRule(findings, notAssessedRuleID) == nil {
		t.Error("expected a not-assessed finding")
	}
	if len(coverage) == 0 || coverage[0].State != report.CoverageUnavailable || coverage[0].RulesSkipped != 1 {
		t.Errorf("expected an UNAVAILABLE coverage row naming the skipped count, got %+v", coverage)
	}
}

func TestRealCatalogRuns(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	inv := &inventory.Inventory{
		ClusterName: "test", Collected: allRead(),
		Workloads: []inventory.Workload{{
			Kind: "Deployment", Namespace: "app", Name: "web",
			VolumeKeys: []string{"configMap", "secret", "emptyDir"},
		}},
	}
	findings, _ := Analyze(inv, "1.33", "1.34", cat.VolumePlugins)
	// Ordinary volume types must never produce a finding; a false positive here would land on
	// nearly every workload in every cluster.
	if len(findings) != 0 {
		t.Errorf("configMap, secret and emptyDir must not be flagged, got %d findings: %+v", len(findings), findings)
	}
}
