package addons

import (
	"strings"
	"testing"
	"time"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/addons/predicates"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

// Three shipped rules scope their kind as "ConfigMap@namespace" or "Secret@namespace". The
// suffix tells the collector to stay in the add-on's namespace; it is not part of the kind. When
// predicates compared the raw string against collected data these rules matched nothing, so they
// passed validation, read as covered, and could never fire.
func TestScopedKindRulesCanFire(t *testing.T) {
	cat := realCatalog(t)
	registry := predicates.Registry()

	for _, tc := range []struct {
		addonID string
		ruleID  string
		rows    map[string][]predicates.Row
	}{
		{
			"coredns", "rtz-addon-coredns-proxy-plugin-removed",
			map[string][]predicates.Row{"ConfigMap": {{
				Kind: "ConfigMap", Namespace: "kube-system", Name: "coredns",
				Spec: map[string]any{"corednsPlugins": []any{"kubernetes", "proxy"}},
			}}},
		},
		{
			"coredns", "rtz-addon-coredns-federation-plugin-removed",
			map[string][]predicates.Row{"ConfigMap": {{
				Kind: "ConfigMap", Namespace: "kube-system", Name: "coredns",
				Spec: map[string]any{"corednsPlugins": []any{"kubernetes", "federation"}},
			}}},
		},
	} {
		addon, ok := cat.AddonByID(tc.addonID)
		if !ok {
			t.Fatalf("%s missing from the catalog", tc.addonID)
		}
		var rule *catalog.AddonRule
		for i := range addon.Rules {
			if addon.Rules[i].RuleID == tc.ruleID {
				rule = &addon.Rules[i]
			}
		}
		if rule == nil {
			t.Fatalf("%s missing from the catalog", tc.ruleID)
		}
		predicate, ok := registry[rule.Kind]
		if !ok {
			t.Fatalf("%s names an unimplemented predicate %q", tc.ruleID, rule.Kind)
		}
		got := predicate.Evaluate(predicates.Context{Rows: tc.rows}, rule.Params)
		if got.Outcome != predicates.Fired {
			t.Errorf("%s did not fire against data that violates it: outcome=%v reason=%q",
				tc.ruleID, got.Outcome, got.Reason)
		}
	}
}

// A rule that could not evaluate must leave a trace. Before this, an add-on whose custom
// resources were unreadable produced exactly the same output as one where every rule ran clean.
func TestDeclinedRulesBecomeCoverageRows(t *testing.T) {
	cat := realCatalog(t)
	inv := workloadInv(deployment("karpenter", "karpenter",
		"public.ecr.aws/karpenter/controller:1.1.0", nil))
	// CRDs deliberately unreadable, which is what a narrowly scoped Role produces.
	inv.Collected[inventory.CollectorCRDs] = inventory.CollectionState{
		OK: false, Reason: "permission denied listing customresourcedefinitions",
	}

	result := Analyze(inv, "1.30", "1.31", cat.Addons, now)

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
	cat := realCatalog(t)
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

	result := Analyze(inv, "1.30", "1.31", cat.Addons, time.Now())
	for _, c := range result.Coverage {
		if c.Source == "add-on rules" {
			t.Errorf("a fully readable cluster should leave no skipped rules: %+v", c)
		}
	}
}
