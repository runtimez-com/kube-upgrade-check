package generated

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func rule(id, version, kind string, d catalog.Detection) catalog.GeneratedRule {
	return catalog.GeneratedRule{
		RuleID: id, SourceID: "kubernetes", AppliesAtVersion: version, Severity: catalog.SeverityHigh,
		Title: "Rule " + id, Quote: "the note", Remediation: "Fix it.", Detection: d,
	}
}

func cat(rules ...catalog.GeneratedRule) *catalog.Catalog {
	return &catalog.Catalog{GeneratedRules: rules}
}

func inv() *inventory.Inventory {
	return &inventory.Inventory{
		ClusterName: "test",
		CRs:         map[string][]inventory.CustomResource{},
		CRUnread:    map[string]string{},
		CRNotServed: map[string]bool{},
		Collected:   map[string]inventory.CollectionState{inventory.CollectorNodes: {OK: true}},
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

// The Service externalIPs deprecation is the shape of most detectable rules: a top-level spec
// field on a built-in kind. It must name the objects and count them.
func TestSpecFieldPresentNamesTheObjects(t *testing.T) {
	r := rule("ext-ips", "1.36", "", catalog.Detection{Kind: catalog.DetectSpecFieldPresent, ObjectKind: "Service", Target: "externalIPs"})
	in := inv()
	in.CRs["Service"] = []inventory.CustomResource{
		{Kind: "Service", Namespace: "a", Name: "legacy", Spec: map[string]any{"externalIPs": []any{"10.0.0.1"}}},
		{Kind: "Service", Namespace: "a", Name: "clean", Spec: map[string]any{}},
	}
	findings, coverage := Analyze(in, nil, "1.35", "1.36", cat(r), nil)
	f := byRule(findings, "ext-ips")
	if f == nil {
		t.Fatal("expected the rule to fire")
	}
	if len(f.AffectedResources) != 1 || f.AffectedResources[0] != "a/legacy" {
		t.Errorf("affected = %v, want [a/legacy]", f.AffectedResources)
	}
	if f.Severity != catalog.SeverityHigh || f.EnforcementLevel == "advisory" {
		t.Errorf("a detectable hit is a break, got severity=%s level=%q", f.Severity, f.EnforcementLevel)
	}
	if f.Quote != "the note" {
		t.Error("the finding must carry the note it rests on")
	}
	if len(coverage) != 0 {
		t.Errorf("a kind that was read leaves no gap, got %+v", coverage)
	}
}

// A kind that is served but could not be listed is a printed gap, never a clean result.
func TestUnreadKindBecomesACoverageRow(t *testing.T) {
	r := rule("ext-ips", "1.36", "", catalog.Detection{Kind: catalog.DetectSpecFieldPresent, ObjectKind: "Service", Target: "externalIPs"})
	in := inv()
	in.CRUnread["Service"] = "permission denied: services is forbidden"
	findings, coverage := Analyze(in, nil, "1.35", "1.36", cat(r), nil)
	if byRule(findings, "ext-ips") != nil {
		t.Error("an unread kind must not fire")
	}
	if len(coverage) != 1 || coverage[0].State != report.CoverageUnavailable || coverage[0].RulesSkipped != 1 {
		t.Fatalf("want one unavailable row skipping 1 rule, got %+v", coverage)
	}
	if !strings.Contains(coverage[0].Reason, "permission denied") || coverage[0].VerifyCommand == "" {
		t.Errorf("the row must carry the reason and a command: %+v", coverage[0])
	}
}

// A kind the cluster does not serve cannot hold objects: the rule does not apply, and that is
// neither a finding nor a gap.
func TestNotServedKindIsNotAGap(t *testing.T) {
	r := rule("ctb", "1.37", "", catalog.Detection{Kind: catalog.DetectKindPresent, ObjectKind: "PodCertificateRequest"})
	in := inv()
	in.CRNotServed["PodCertificateRequest"] = true
	findings, coverage := Analyze(in, nil, "1.36", "1.37", cat(r), nil)
	if len(findings) != 0 || len(coverage) != 0 {
		t.Errorf("want nothing, got findings=%d coverage=%d", len(findings), len(coverage))
	}
}

// A kind nobody collected is a gap: absence of data is not absence of objects.
func TestNotCollectedKindIsAGap(t *testing.T) {
	r := rule("ctb", "1.37", "", catalog.Detection{Kind: catalog.DetectKindPresent, ObjectKind: "PodCertificateRequest"})
	_, coverage := Analyze(inv(), nil, "1.36", "1.37", cat(r), nil)
	if len(coverage) != 1 {
		t.Fatalf("want one gap, got %+v", coverage)
	}
}

// Release notes name labels by their short form; the finding must say which key matched.
func TestKeyMatchingModes(t *testing.T) {
	r := rule("lbl", "1.34", "", catalog.Detection{Kind: catalog.DetectLabelKeyPresent, ObjectKind: "Node", Target: "exclude-from-external-load-balancers"})
	in := inv()
	in.Nodes = []inventory.Node{{Name: "n1", Labels: map[string]string{"node.kubernetes.io/exclude-from-external-load-balancers": "true"}}}
	findings, _ := Analyze(in, nil, "1.33", "1.34", cat(r), nil)
	f := byRule(findings, "lbl")
	if f == nil {
		t.Fatal("short-form target must match the name part of a qualified key")
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "node.kubernetes.io/exclude-from-external-load-balancers") {
		t.Errorf("evidence must name the matched key: %v", f.Evidence)
	}

	if matchKey([]string{"foo/bar"}, "other/bar") != "" {
		t.Error("a qualified target is exact")
	}
	// A trailing star is a prefix on the name part: Istio's excludeOutbound* names two
	// annotations. Neither the other direction nor another domain may match.
	if matchKey([]string{"traffic.sidecar.istio.io/excludeOutboundPorts"}, "traffic.sidecar.istio.io/excludeOutbound*") != "traffic.sidecar.istio.io/excludeOutboundPorts" {
		t.Error("a trailing-star target must match the name-part prefix")
	}
	if matchKey([]string{"traffic.sidecar.istio.io/excludeInboundPorts", "other.io/excludeOutboundPorts"}, "traffic.sidecar.istio.io/excludeOutbound*") != "" {
		t.Error("a trailing-star target must not match another prefix or another domain")
	}
	if matchKey([]string{"container.apparmor.security.beta.kubernetes.io/app"}, "container.apparmor.security.beta.kubernetes.io/") == "" {
		t.Error("a trailing slash is a prefix family")
	}
}

// A NOT_DETECTABLE rule prints as an advisory: INFO, no score, the reason attached, and any
// hint about where to look.
func TestNotDetectableIsAnAdvisoryWithReasonAndHint(t *testing.T) {
	r := rule("adv", "1.36", "", catalog.Detection{Kind: catalog.DetectNotDetectable, Reason: "component configuration is not inventoried"})
	r.Scope = &catalog.ScopeHint{Kind: catalog.DetectKindPresent, ObjectKind: "Node"}
	in := inv()
	in.Nodes = []inventory.Node{{Name: "n1"}, {Name: "n2"}}
	findings, coverage := Analyze(in, nil, "1.35", "1.36", cat(r), nil)
	f := byRule(findings, "adv")
	if f == nil {
		t.Fatal("expected an advisory")
	}
	if f.Severity != catalog.SeverityInfo || f.ScoreImpact != 0 || f.EnforcementLevel != "advisory" {
		t.Errorf("advisory shape wrong: %+v", f)
	}
	if !strings.Contains(f.Recommendation, "component configuration is not inventoried") {
		t.Error("the reason it cannot be checked must reach the reader")
	}
	if len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "2 Node") {
		t.Errorf("hint must count the nodes: %v", f.Evidence)
	}
	if len(coverage) != 0 {
		t.Error("an advisory is not a gap")
	}
}

// The window is (current, target]: a rule for a version the cluster already runs is not part
// of this upgrade, and one past the target is not either.
func TestWindowIsExclusiveBelowInclusiveAbove(t *testing.T) {
	rules := cat(
		rule("old", "1.34", "", catalog.Detection{Kind: catalog.DetectNotDetectable, Reason: "x"}),
		rule("now", "1.35", "", catalog.Detection{Kind: catalog.DetectNotDetectable, Reason: "x"}),
		rule("next", "1.36", "", catalog.Detection{Kind: catalog.DetectNotDetectable, Reason: "x"}),
		rule("far", "1.37", "", catalog.Detection{Kind: catalog.DetectNotDetectable, Reason: "x"}),
	)
	findings, _ := Analyze(inv(), nil, "v1.35.2", "1.36", rules, nil)
	if byRule(findings, "old") != nil || byRule(findings, "now") != nil || byRule(findings, "far") != nil {
		t.Errorf("only the 1.36 rule is on the path, got %d findings", len(findings))
	}
	if byRule(findings, "next") == nil {
		t.Error("the 1.36 rule must be reported")
	}
}

// Managed fields say which manager still writes at a version. The evidence names it.
func TestAPIVersionInUseReadsManagedFields(t *testing.T) {
	r := rule("api", "1.37", "", catalog.Detection{Kind: catalog.DetectAPIVersionInUse, ObjectKind: "MutatingAdmissionPolicy", Target: "admissionregistration.k8s.io/v1alpha1"})
	in := inv()
	in.CRs["MutatingAdmissionPolicy"] = []inventory.CustomResource{
		{Kind: "MutatingAdmissionPolicy", Name: "old", WrittenAt: []string{"admissionregistration.k8s.io/v1alpha1"}, Managers: []string{"helm"}},
		{Kind: "MutatingAdmissionPolicy", Name: "new", WrittenAt: []string{"admissionregistration.k8s.io/v1beta1"}},
	}
	findings, _ := Analyze(in, nil, "1.36", "1.37", cat(r), nil)
	f := byRule(findings, "api")
	if f == nil {
		t.Fatal("expected the v1alpha1 writer to be found")
	}
	if len(f.AffectedResources) != 1 || f.AffectedResources[0] != "old" {
		t.Errorf("affected = %v", f.AffectedResources)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "by helm") {
		t.Errorf("evidence must name the manager: %v", f.Evidence)
	}
}

// When the removed-API catalog owns an apiVersion, the generated twin steps aside so one break
// is not printed twice. The static evaluator carries the per-object evidence.
func TestAPIVersionInUseDefersToTheRemovedAPICatalog(t *testing.T) {
	c := cat(rule("api", "1.37", "", catalog.Detection{Kind: catalog.DetectAPIVersionInUse, ObjectKind: "Workload", Target: "scheduling.k8s.io/v1alpha2"}))
	c.DeprecationRules = []catalog.DeprecationRule{{RuleID: "static", APIVersion: "scheduling.k8s.io/v1alpha2", Kind: "Workload", RemovedIn: "1.37"}}
	c.Reindex()
	in := inv()
	in.CRs["Workload"] = []inventory.CustomResource{{Kind: "Workload", Name: "w", WrittenAt: []string{"scheduling.k8s.io/v1alpha2"}}}
	findings, coverage := Analyze(in, nil, "1.36", "1.37", c, nil)
	if len(findings) != 0 || len(coverage) != 0 {
		t.Errorf("the static catalog owns this apiVersion; got findings=%d coverage=%d", len(findings), len(coverage))
	}
	if _, ok := Wants(c, "1.36", "1.37", nil)["Workload"]; ok {
		t.Error("nothing should be collected for a rule the static catalog owns")
	}
}

// A group-level rule with no kind cannot be enumerated here and says so, rather than clearing.
func TestGroupLevelRuleWithoutKindDeclines(t *testing.T) {
	r := rule("grp", "1.36", "", catalog.Detection{Kind: catalog.DetectAPIVersionInUse, Target: "apidiscovery.k8s.io/v2beta1"})
	_, coverage := Analyze(inv(), map[string]bool{}, "1.35", "1.36", cat(r), nil)
	if len(coverage) != 1 || !strings.Contains(coverage[0].VerifyCommand, "/apis/apidiscovery.k8s.io/v2beta1") {
		t.Fatalf("want a gap with the raw API path to check, got %+v", coverage)
	}
	_, coverage = Analyze(inv(), map[string]bool{"apidiscovery.k8s.io/v2beta1": false}, "1.35", "1.36", cat(r), nil)
	if len(coverage) != 0 {
		t.Error("a group-version the scan knows is not served has nothing to enumerate")
	}
}

// Wants keeps only the fields the rules read, so a Pod list is not a copy of every pod.
func TestWantsProjectsToTheFieldsRulesRead(t *testing.T) {
	c := cat(
		rule("a", "1.36", "", catalog.Detection{Kind: catalog.DetectSpecFieldPresent, ObjectKind: "Pod", Target: "resize"}),
		rule("b", "1.36", "", catalog.Detection{Kind: catalog.DetectSpecPathMatches, ObjectKind: "Pod", Target: "containers[].image", Value: "x"}),
		rule("c", "1.36", "", catalog.Detection{Kind: catalog.DetectKindPresent, ObjectKind: "ServiceCIDR"}),
		rule("d", "1.36", "", catalog.Detection{Kind: catalog.DetectLabelKeyPresent, ObjectKind: "Node", Target: "k"}),
	)
	w := Wants(c, "1.35", "1.36", nil)
	if got := w["Pod"].Keep; len(got) != 2 || got[0] != "resize" || got[1] != "containers" {
		t.Errorf("Pod projection = %v", got)
	}
	if p, ok := w["ServiceCIDR"]; !ok || p.Keep == nil || len(p.Keep) != 0 {
		t.Errorf("a presence rule wants metadata only: %+v", p)
	}
	if _, ok := w["Node"]; ok {
		t.Error("nodes come from the typed collector")
	}
}

func TestSpecPathMatchesWalksArrays(t *testing.T) {
	r := rule("path", "1.36", "", catalog.Detection{Kind: catalog.DetectSpecPathMatches, ObjectKind: "Pod", Target: "containers[].image", Value: `^registry\.k8s\.io/kube-proxy`})
	in := inv()
	in.CRs["Pod"] = []inventory.CustomResource{
		{Kind: "Pod", Namespace: "kube-system", Name: "kp", Spec: map[string]any{"containers": []any{map[string]any{"image": "registry.k8s.io/kube-proxy:v1.35.0"}}}},
		{Kind: "Pod", Namespace: "default", Name: "app", Spec: map[string]any{"containers": []any{map[string]any{"image": "nginx"}}}},
	}
	findings, _ := Analyze(in, nil, "1.35", "1.36", cat(r), nil)
	f := byRule(findings, "path")
	if f == nil || len(f.AffectedResources) != 1 || f.AffectedResources[0] != "kube-system/kp" {
		t.Fatalf("want kube-system/kp only, got %+v", f)
	}
}

// Every shipped rule must evaluate against an empty inventory without panicking, and the
// detectable ones must all surface as gaps there: nothing was read, so nothing may pass.
func TestRealCatalogAgainstAnEmptyInventory(t *testing.T) {
	c, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	in := inv()
	delete(in.Collected, inventory.CollectorNodes)
	findings, coverage := Analyze(in, map[string]bool{}, "1.31", "1.37", c, nil)
	advisories, breaks := 0, 0
	for _, f := range findings {
		if f.EnforcementLevel == "advisory" {
			advisories++
		} else {
			breaks++
		}
	}
	if breaks != 0 {
		t.Errorf("nothing was read, so nothing may fire as a break; got %d", breaks)
	}
	if advisories == 0 {
		t.Error("the NOT_DETECTABLE rules must still be reported as advisories")
	}
	skipped := 0
	for _, row := range coverage {
		skipped += row.RulesSkipped
	}
	if skipped == 0 {
		t.Error("every detectable rule must be accounted for as a gap when nothing was collected")
	}
	// Static-catalog handoffs are the only detectable rules allowed to vanish; count the rest.
	detectable, owned := 0, 0
	for _, r := range onPath(c, "1.31", "1.37", nil).rules {
		if r.Detection.Kind == catalog.DetectNotDetectable {
			continue
		}
		detectable++
		if r.Detection.Kind == catalog.DetectAPIVersionInUse && staticCatalogOwns(c, r.Detection) {
			owned++
		}
	}
	if skipped != detectable-owned {
		t.Errorf("gap rows account for %d rules, want %d detectable minus %d owned by the removed-API catalog",
			skipped, detectable, owned)
	}
}
