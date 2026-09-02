package removedapi

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
	"github.com/runtimez-com/kube-upgrade-check/internal/source"
)

func realCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func byRule(findings []report.Finding, ruleID string) *report.Finding {
	for i := range findings {
		if findings[i].RuleID == ruleID {
			return &findings[i]
		}
	}
	return nil
}

func TestRemovedApiIsCriticalAndNamesTheObject(t *testing.T) {
	cat := realCatalog(t)
	usages := []inventory.APIUsage{{
		APIVersion: "extensions/v1beta1", Kind: "Ingress", Namespace: "shop", Name: "web",
		Tier: source.TierManagedFields, Manager: "helm", ObservedAt: "2024-03-02",
		Evidence: "helm last wrote this at extensions/v1beta1 on 2024-03-02",
	}}
	findings := Analyze(usages, "1.21", "1.22", cat)

	f := byRule(findings, "rtz-k8s-dep-extensions-ingress")
	if f == nil {
		t.Fatal("expected a finding for a removed Ingress API")
	}
	if f.Severity != catalog.SeverityCritical || f.ScoreImpact != 40 {
		t.Errorf("got %s/%d, want CRITICAL/40", f.Severity, f.ScoreImpact)
	}
	if len(f.AffectedResources) != 1 || f.AffectedResources[0] != "shop/web" {
		t.Errorf("the object must be named: %v", f.AffectedResources)
	}
	// The reader has to be able to tell how strong the claim is.
	if len(f.Tiers) == 0 || f.Tiers[0] != source.TierManagedFields {
		t.Errorf("the evidence tier must be reported: %v", f.Tiers)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "helm") {
		t.Errorf("the writer should be named in the evidence: %v", f.Evidence)
	}
}

// Deprecated is not removed: everything still works, so it must not read as critical.
func TestDeprecatedButNotYetRemovedIsHigh(t *testing.T) {
	cat := realCatalog(t)
	usages := []inventory.APIUsage{{
		APIVersion: "extensions/v1beta1", Kind: "Ingress", Namespace: "shop", Name: "web",
		Tier: source.TierManagedFields,
	}}
	findings := Analyze(usages, "1.14", "1.15", cat)
	f := byRule(findings, "rtz-k8s-dep-extensions-ingress")
	if f == nil {
		t.Fatal("expected a finding at the deprecation version")
	}
	if f.Severity != catalog.SeverityHigh {
		t.Errorf("got %s, want HIGH before the removal version", f.Severity)
	}
	if f.AppliesAtVersion != "1.14" {
		t.Errorf("should apply at the deprecation version, got %s", f.AppliesAtVersion)
	}
}

func TestNotYetDeprecatedDoesNotFire(t *testing.T) {
	cat := realCatalog(t)
	usages := []inventory.APIUsage{{
		APIVersion: "extensions/v1beta1", Kind: "Ingress", Name: "web", Tier: source.TierManagedFields,
	}}
	if findings := Analyze(usages, "1.12", "1.13", cat); len(findings) != 0 {
		t.Errorf("a rule whose deprecation is still ahead must not fire, got %+v", findings)
	}
}

// No evidence means no finding. It does not mean a clean bill of health, which is what the
// coverage rows exist to say.
func TestNoEvidenceProducesNoFindings(t *testing.T) {
	cat := realCatalog(t)
	if findings := Analyze(nil, "1.21", "1.22", cat); len(findings) != 0 {
		t.Errorf("expected no findings without evidence, got %+v", findings)
	}
}

// Evidence superseded by a later rewrite is a weaker claim, and the wording has to say so.
func TestStaleEvidenceIsDowngradedAndExplained(t *testing.T) {
	cat := realCatalog(t)
	usages := []inventory.APIUsage{{
		APIVersion: "extensions/v1beta1", Kind: "Ingress", Namespace: "shop", Name: "web",
		Tier: source.TierManagedFields, Stale: true,
	}}
	findings := Analyze(usages, "1.21", "1.22", cat)
	f := byRule(findings, "rtz-k8s-dep-extensions-ingress")
	if f == nil {
		t.Fatal("stale evidence must still produce a finding")
	}
	if f.Severity != catalog.SeverityHigh {
		t.Errorf("stale evidence should be downgraded from CRITICAL, got %s", f.Severity)
	}
	if !strings.Contains(f.Recommendation, "rewritten") {
		t.Errorf("the reader must be told why this is weaker: %q", f.Recommendation)
	}
}

// One object seen by two tiers is one problem, not two.
func TestMultipleTiersMergeIntoOneFinding(t *testing.T) {
	cat := realCatalog(t)
	usages := []inventory.APIUsage{
		{APIVersion: "extensions/v1beta1", Kind: "Ingress", Namespace: "shop", Name: "web",
			Tier: source.TierManagedFields, Evidence: "managed fields say so"},
		{APIVersion: "extensions/v1beta1", Kind: "Ingress", Namespace: "shop", Name: "web",
			Tier: source.TierLastApplied, Evidence: "the applied manifest says so"},
	}
	findings := Analyze(usages, "1.21", "1.22", cat)
	if len(findings) != 1 {
		t.Fatalf("expected the tiers to merge into one finding, got %d", len(findings))
	}
	if len(findings[0].Tiers) != 2 {
		t.Errorf("both tiers should be reported: %v", findings[0].Tiers)
	}
	if len(findings[0].AffectedResources) != 1 {
		t.Errorf("the object must not be counted twice: %v", findings[0].AffectedResources)
	}
}

// A metrics hit has no object attached, and the wording must not imply one.
func TestClusterWideEvidenceWithoutAnObject(t *testing.T) {
	cat := realCatalog(t)
	usages := []inventory.APIUsage{{
		APIVersion: "extensions/v1beta1", Kind: "Ingress", Tier: source.TierMetrics,
		Evidence: "the API server has served requests for extensions/v1beta1 ingresses",
	}}
	findings := Analyze(usages, "1.21", "1.22", cat)
	f := byRule(findings, "rtz-k8s-dep-extensions-ingress")
	if f == nil {
		t.Fatal("expected a finding from request evidence alone")
	}
	if len(f.AffectedResources) != 0 {
		t.Errorf("no object should be named when none was identified: %v", f.AffectedResources)
	}
	if !strings.Contains(f.Title, "still being requested") {
		t.Errorf("the title should reflect that no object was identified: %q", f.Title)
	}
}

func TestUnknownApiVersionIsIgnored(t *testing.T) {
	cat := realCatalog(t)
	usages := []inventory.APIUsage{{
		APIVersion: "example.com/v1", Kind: "Widget", Name: "w", Tier: source.TierManagedFields,
	}}
	if findings := Analyze(usages, "1.21", "1.22", cat); len(findings) != 0 {
		t.Errorf("an API the catalog says nothing about must not produce a finding, got %+v", findings)
	}
}

// "We scanned these and found no user" and "these are not present here at all" are different
// statements, and only one of them is evidence about the cluster.
func TestServedButUnusedDistinguishesAbsentFromClean(t *testing.T) {
	cat := realCatalog(t)

	none := ServedButUnused(map[string]bool{"apps/v1": true}, cat, "1.22")
	if !strings.Contains(none.Reason, "no longer serves") {
		t.Errorf("a cluster serving nothing removed should say so: %q", none.Reason)
	}

	some := ServedButUnused(map[string]bool{"extensions/v1beta1": true}, cat, "1.22")
	if !strings.Contains(some.Reason, "extensions/v1beta1") {
		t.Errorf("a still-served removed version should be named: %q", some.Reason)
	}
	// Serving a version is never evidence of use, so this may never be a finding.
	if some.State != report.CoverageComplete {
		t.Errorf("this is a coverage statement, not a gap: %+v", some)
	}
}
