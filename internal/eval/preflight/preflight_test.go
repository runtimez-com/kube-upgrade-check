package preflight

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func allRead() *inventory.Inventory {
	return &inventory.Inventory{
		ClusterName: "test",
		Collected: map[string]inventory.CollectionState{
			inventory.CollectorNodes: {OK: true}, inventory.CollectorPods: {OK: true},
			inventory.CollectorPDBs: {OK: true}, inventory.CollectorWebhooks: {OK: true},
			inventory.CollectorCRDs: {OK: true}, inventory.CollectorAPIServices: {OK: true},
		},
	}
}

func byRule(findings []report.Finding, id string) *report.Finding {
	for i := range findings {
		if findings[i].RuleID == id {
			return &findings[i]
		}
	}
	return nil
}

func gapFor(coverage []report.Coverage, scope string) *report.Coverage {
	for i := range coverage {
		if coverage[i].Scope == scope && coverage[i].State == report.CoverageUnavailable {
			return &coverage[i]
		}
	}
	return nil
}

func TestSkippedMinorNamesTheHops(t *testing.T) {
	findings, _ := Analyze(allRead(), "v1.31.4", "1.34")
	f := byRule(findings, RuleSkippedMinor)
	if f == nil {
		t.Fatal("a three-minor jump must be reported")
	}
	if !strings.Contains(f.Recommendation, "1.31 → 1.32 → 1.33 → 1.34") {
		t.Errorf("hops missing: %s", f.Recommendation)
	}
	findings, _ = Analyze(allRead(), "v1.33.0", "1.34")
	if byRule(findings, RuleSkippedMinor) != nil {
		t.Error("one minor up is the normal case")
	}
}

func TestNodeNotReadyIsAFindingAndUnknownConditionsAreAGap(t *testing.T) {
	in := allRead()
	in.Nodes = []inventory.Node{
		{Name: "ok", Conditions: map[string]string{"Ready": "True"}},
		{Name: "gone", Conditions: map[string]string{"Ready": "Unknown"}},
	}
	findings, coverage := Analyze(in, "1.33", "1.34")
	f := byRule(findings, RuleNodeNotReady)
	if f == nil || len(f.AffectedResources) != 1 || !strings.Contains(f.AffectedResources[0], "gone") {
		t.Fatalf("want the one NotReady node, got %+v", f)
	}
	if gapFor(coverage, "node readiness") != nil {
		t.Error("conditions were read; no gap")
	}

	in.Nodes = []inventory.Node{{Name: "old-scan"}}
	_, coverage = Analyze(in, "1.33", "1.34")
	if gapFor(coverage, "node readiness") == nil {
		t.Error("nodes without collected conditions must be a gap, not a pass")
	}
}

func TestPDBWithZeroDisruptionsBlocksDrain(t *testing.T) {
	in := allRead()
	in.PDBs = []inventory.PDB{
		{Namespace: "a", Name: "tight", DisruptionsAllowed: 0, ExpectedPods: 2, CurrentHealthy: 2, DesiredHealthy: 2},
		{Namespace: "a", Name: "empty", DisruptionsAllowed: 0, ExpectedPods: 0},
		{Namespace: "a", Name: "fine", DisruptionsAllowed: 1, ExpectedPods: 3},
	}
	findings, _ := Analyze(in, "1.33", "1.34")
	f := byRule(findings, RulePDBBlocksDrain)
	if f == nil || len(f.AffectedResources) != 1 || !strings.HasPrefix(f.AffectedResources[0], "a/tight") {
		t.Fatalf("only the budget with pods under it blocks: %+v", f)
	}
}

func TestBarePodsAreMedium(t *testing.T) {
	in := allRead()
	in.StandalonePods = []inventory.Pod{{Namespace: "x", Name: "debug"}}
	findings, _ := Analyze(in, "1.33", "1.34")
	f := byRule(findings, RuleBarePods)
	if f == nil || f.Severity != catalog.SeverityMedium {
		t.Fatalf("want a MEDIUM bare-pod finding, got %+v", f)
	}
}

func TestWebhookBackendStatesSplitThreeWays(t *testing.T) {
	in := allRead()
	svc := func(name string) *inventory.ServiceRef { return &inventory.ServiceRef{Namespace: "ns", Name: name} }
	in.Webhooks = []inventory.Webhook{
		{Config: "policy", Kind: "ValidatingWebhookConfiguration", Name: "a", FailurePolicy: "Fail", Service: svc("down"),
			Backend: inventory.BackendState{Checked: true, Ready: false, Reason: "Service ns/down has no endpoints"}},
		{Config: "policy", Kind: "ValidatingWebhookConfiguration", Name: "b", FailurePolicy: "Fail", Service: svc("up"),
			Backend: inventory.BackendState{Checked: true, Ready: true}},
		{Config: "policy", Kind: "MutatingWebhookConfiguration", Name: "c", FailurePolicy: "Ignore", Service: svc("down"),
			Backend: inventory.BackendState{Checked: true, Ready: false}},
		{Config: "policy", Kind: "MutatingWebhookConfiguration", Name: "d", FailurePolicy: "Fail", Service: svc("unknown"),
			Backend: inventory.BackendState{Checked: false, Reason: "EndpointSlices for ns/unknown: permission denied"}},
	}
	findings, coverage := Analyze(in, "1.33", "1.34")
	down := byRule(findings, RuleWebhookBackendDown)
	if down == nil || down.Severity != catalog.SeverityCritical || len(down.AffectedResources) != 1 || !strings.Contains(down.AffectedResources[0], "policy/a") {
		t.Fatalf("the Fail-policy webhook with a dead backend is critical: %+v", down)
	}
	review := byRule(findings, RuleWebhookFailPolicy)
	if review == nil || review.Severity != catalog.SeverityLow || len(review.AffectedResources) != 1 || !strings.Contains(review.AffectedResources[0], "policy/b") {
		t.Fatalf("a healthy Fail-policy webhook is a low review item; an Ignore one is nothing: %+v", review)
	}
	var partial bool
	for _, c := range coverage {
		if c.Scope == "admission webhooks" && c.State == report.CoveragePartial && strings.Contains(c.Reason, "policy/d") {
			partial = true
		}
	}
	if !partial {
		t.Errorf("an unchecked backend is a partial row naming the webhook: %+v", coverage)
	}
}

func TestConversionWebhookDownIsCritical(t *testing.T) {
	in := allRead()
	in.CRDs = []inventory.CRD{
		{Name: "things.example.io", Conversion: &inventory.Conversion{Strategy: "Webhook",
			Service: &inventory.ServiceRef{Namespace: "ns", Name: "conv"},
			Backend: inventory.BackendState{Checked: true, Ready: false, Reason: "Service ns/conv does not exist"}}},
		{Name: "plain.example.io", Conversion: &inventory.Conversion{Strategy: "None"}},
	}
	findings, _ := Analyze(in, "1.33", "1.34")
	f := byRule(findings, RuleConversionBackendDown)
	if f == nil || f.Severity != catalog.SeverityCritical || len(f.AffectedResources) != 1 {
		t.Fatalf("want one critical conversion finding, got %+v", f)
	}
}

func TestAggregatedAPIUnavailable(t *testing.T) {
	in := allRead()
	in.APIServices = []inventory.APIService{
		{Name: "v1.", Local: true, Available: true},
		{Name: "v1beta1.metrics.k8s.io", Available: false, Reason: "MissingEndpoints: endpoints for service/metrics-server in \"kube-system\" have no addresses"},
		{Name: "v1.custom.io", Available: true},
	}
	findings, _ := Analyze(in, "1.33", "1.34")
	f := byRule(findings, RuleAPIServiceUnavailable)
	if f == nil || len(f.AffectedResources) != 1 || !strings.Contains(f.AffectedResources[0], "metrics.k8s.io") {
		t.Fatalf("want the one unavailable registration, got %+v", f)
	}
	if !strings.Contains(f.Evidence[0], "MissingEndpoints") {
		t.Errorf("the API server's own reason must be shown: %v", f.Evidence)
	}
}

// Every check that could not run is a printed gap. A scan with nothing collected must produce
// one row per check and no findings.
func TestNothingCollectedIsAllGaps(t *testing.T) {
	in := &inventory.Inventory{ClusterName: "test", Collected: map[string]inventory.CollectionState{}}
	findings, coverage := Analyze(in, "1.33", "1.34")
	if len(findings) != 0 {
		t.Errorf("nothing was read, nothing may fire: %+v", findings)
	}
	for _, scope := range []string{"node readiness", "disruption budgets", "bare pods", "admission webhooks", "CRD conversion webhooks", "aggregated APIs"} {
		if g := gapFor(coverage, scope); g == nil || g.VerifyCommand == "" {
			t.Errorf("%s must be an unavailable row with a command: %+v", scope, coverage)
		}
	}
}
