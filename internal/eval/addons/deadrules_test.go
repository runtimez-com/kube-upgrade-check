package addons

import (
	"strings"
	"testing"
	"time"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

// Every shipped add-on catalog is rule-free and note-free: an add-on's breaking changes are
// release-note rules under k8s-rules/<addon>/, selected by the add-on's own hop, where the
// hosted product authors them. A rule creeping back into a catalog here would be evaluated by
// the predicate registry below and by nothing on the other side.
func TestShippedAddonCatalogsCarryNoEmbeddedRules(t *testing.T) {
	cat := realCatalog(t)
	sources := map[string]bool{}
	for _, r := range cat.GeneratedRules {
		sources[r.SourceID] = true
	}
	for _, a := range cat.Addons {
		if a.AddonID == "ingress-nginx" {
			// The one add-on not yet onboarded to the release-note pipeline.
			continue
		}
		if len(a.Rules) != 0 || len(a.UpgradeNotes) != 0 {
			t.Errorf("%s: %d embedded rules and %d notes; they belong under k8s-rules/%s/", a.AddonID, len(a.Rules), len(a.UpgradeNotes), a.AddonID)
		}
		if a.AddonID != "kube-proxy" && !sources[a.AddonID] {
			t.Errorf("%s: no k8s-rules/%s/ rule set is vendored", a.AddonID, a.AddonID)
		}
	}
}

// The embedded-rule path is kept for a catalog that still carries rules (ingress-nginx), so its
// predicates must stay implemented; the registry is what `catalog validate` checks against.
func syntheticAddon() catalog.Addon {
	return catalog.Addon{
		AddonID: "synthetic", DisplayName: "Synthetic",
		Detect:         catalog.AddonDetect{ImageSuffixes: []string{"karpenter/controller"}},
		SupportWindows: []catalog.SupportWindow{{Version: "1.0", MinK8s: "1.28", MaxK8s: "1.35"}},
		InventoryKinds: []string{"NodePool", "NodeClaim"},
		Rules: []catalog.AddonRule{{
			RuleID: "rtz-addon-synthetic-crd-lag", Kind: "crdAbsent", Severity: catalog.SeverityHigh,
			Params: map[string]any{"crdName": "capacitybuffers.autoscaling.x-k8s.io"},
			Title:  "CRD lag", Recommendation: "Install it.", Quote: "q", SourceURL: "https://example.invalid",
		}},
	}
}

// A rule that could not evaluate must leave a trace. Before this, an add-on whose custom
// resources were unreadable produced exactly the same output as one where every rule ran clean.
func TestDeclinedRulesBecomeCoverageRows(t *testing.T) {
	addons := []catalog.Addon{syntheticAddon()}
	inv := workloadInv(deployment("karpenter", "karpenter",
		"public.ecr.aws/karpenter/controller:1.1.0", nil))
	// CRDs deliberately unreadable, which is what a narrowly scoped Role produces.
	inv.Collected[inventory.CollectorCRDs] = inventory.CollectionState{
		OK: false, Reason: "permission denied listing customresourcedefinitions",
	}

	result := Analyze(inv, "1.30", "1.31", addons, now)

	var skippedRows int
	for _, c := range result.Coverage {
		if c.Source == "add-on rules" && c.State == report.CoverageUnavailable {
			skippedRows += c.RulesSkipped
			if strings.TrimSpace(c.Reason) == "" {
				t.Error("a skipped-rule row must say why")
			}
		}
	}
	if skippedRows == 0 {
		t.Errorf("rules that could not evaluate must be reported, got coverage %+v", result.Coverage)
	}
}

// The inverse: when everything is readable and nothing is wrong, no skipped rows appear.
func TestCleanEvaluationProducesNoSkippedRows(t *testing.T) {
	addons := []catalog.Addon{syntheticAddon()}
	inv := workloadInv(deployment("karpenter", "karpenter",
		"public.ecr.aws/karpenter/controller:1.1.0", nil))
	inv.Collected[inventory.CollectorCRDs] = inventory.CollectionState{OK: true}
	inv.CRDs = []inventory.CRD{
		{Name: "nodepools.karpenter.sh", ServedVersions: []string{"v1"}},
		{Name: "nodeclaims.karpenter.sh", ServedVersions: []string{"v1"}},
		{Name: "capacitybuffers.autoscaling.x-k8s.io", ServedVersions: []string{"v1"}},
	}
	inv.CRs["NodePool"] = nil
	inv.CRs["NodeClaim"] = nil

	result := Analyze(inv, "1.30", "1.31", addons, time.Now())
	for _, c := range result.Coverage {
		if c.Source == "add-on rules" {
			t.Errorf("a fully readable cluster should leave no skipped rules: %+v", c)
		}
	}
}
