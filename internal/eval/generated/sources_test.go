package generated

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/addons"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func sourced(source, id, version string, d catalog.Detection) catalog.GeneratedRule {
	r := rule(id, version, "", d)
	r.SourceID = source
	r.RuleID = "rtz-" + source + "-" + version + "-" + id
	return r
}

func corednsHop(installed, required string) Hops {
	return Hops{"coredns": addons.Hop{AddonID: "coredns", InstalledVersion: installed, RequiredVersion: required, Reason: addons.HopCurrency}}
}

func advisoryRule(source, id, version string) catalog.GeneratedRule {
	return sourced(source, id, version, catalog.Detection{Kind: catalog.DetectNotDetectable, Reason: "prose"})
}

func coverageScope(coverage []report.Coverage, scope string) *report.Coverage {
	for i := range coverage {
		if coverage[i].Scope == scope {
			return &coverage[i]
		}
	}
	return nil
}

// An add-on's rule set is selected by the add-on's OWN version range, (installed, required] at
// minor precision, never by the Kubernetes one: CoreDNS and Kubernetes both number their minors
// 1.x, and a wrong-axis comparison would drop or match rules by coincidence.
func TestAddonRulesSelectOnTheAddonHop(t *testing.T) {
	c := cat(
		advisoryRule("coredns", "at-installed", "1.4"),
		advisoryRule("coredns", "first-past", "1.5"),
		advisoryRule("coredns", "last-in", "1.14"),
		advisoryRule("coredns", "beyond", "1.15"),
		advisoryRule("kubernetes", "k8s-in", "1.36"),
	)
	findings, _ := Analyze(inv(), nil, "1.35", "1.36", c, corednsHop("1.4.0", "1.14.7"))
	ids := map[string]bool{}
	for _, f := range findings {
		ids[f.RuleID] = true
	}
	want := []string{"rtz-coredns-1.5-first-past", "rtz-coredns-1.14-last-in", "rtz-kubernetes-1.36-k8s-in"}
	for _, id := range want {
		if !ids[id] {
			t.Errorf("%s must be on the path; got %v", id, ids)
		}
	}
	for _, id := range []string{"rtz-coredns-1.4-at-installed", "rtz-coredns-1.15-beyond"} {
		if ids[id] {
			t.Errorf("%s is outside (1.4, 1.14] and must not be evaluated", id)
		}
	}
	f := byRule(findings, "rtz-coredns-1.14-last-in")
	if f.RuleSource != "coredns" || f.AppliesAtVersion != "1.14" || !strings.Contains(f.Title, "[target coredns 1.14.7]") {
		t.Errorf("an add-on advisory names its source and the add-on's target: %+v", f)
	}
}

// Without a hop the add-on's rules are not evaluated, and that is stated on a coverage row
// rather than left as a silent absence. The Kubernetes rules are unaffected.
func TestAddonRulesWithoutAHopAreSkippedAndStated(t *testing.T) {
	c := cat(
		advisoryRule("coredns", "note", "1.9"),
		sourced("coredns", "detect", "1.9", catalog.Detection{Kind: catalog.DetectKindPresent, ObjectKind: "ConfigMap"}),
		advisoryRule("kubernetes", "k8s-in", "1.36"),
	)
	in := inv()
	in.CRs["ConfigMap"] = []inventory.CustomResource{{Kind: "ConfigMap", Namespace: "kube-system", Name: "coredns"}}
	findings, coverage := Analyze(in, nil, "1.35", "1.36", c, nil)
	if byRule(findings, "rtz-coredns-1.9-note") != nil || byRule(findings, "rtz-coredns-1.9-detect") != nil {
		t.Errorf("coredns rules must not run without a coredns hop: %+v", findings)
	}
	if byRule(findings, "rtz-kubernetes-1.36-k8s-in") == nil {
		t.Error("the kubernetes rule still runs on the kubernetes hop")
	}
	row := coverageScope(coverage, "coredns rules")
	if row == nil || row.State != report.CoverageComplete || !strings.Contains(row.Reason, "not evaluated") {
		t.Errorf("the skipped source must be stated as a complete-but-not-applicable row: %+v", coverage)
	}
	// Mutation guard: with the hop the same detect rule fires, so the skip is the hop's doing.
	findings, _ = Analyze(in, nil, "1.35", "1.36", c, corednsHop("1.8.0", "1.14.7"))
	if byRule(findings, "rtz-coredns-1.9-detect") == nil {
		t.Error("with a hop the coredns rule must fire")
	}
}

// kube-proxy's files are Kubernetes minors and ride the Kubernetes hop; the skew policy is
// always on, whatever the hop.
func TestKubeProxyRidesTheKubernetesHopAndSkewIsAlwaysOn(t *testing.T) {
	c := cat(
		advisoryRule("kube-proxy", "in", "1.36"),
		advisoryRule("kube-proxy", "out", "1.37"),
		advisoryRule("kubernetes-skew-policy", "policy", "0.0"),
	)
	findings, coverage := Analyze(inv(), nil, "1.35", "1.36", c, nil)
	if byRule(findings, "rtz-kube-proxy-1.36-in") == nil || byRule(findings, "rtz-kube-proxy-1.37-out") != nil {
		t.Errorf("kube-proxy selection wrong: %+v", findings)
	}
	if byRule(findings, "rtz-kubernetes-skew-policy-0.0-policy") == nil {
		t.Error("the skew policy is evaluated on every hop")
	}
	for _, row := range coverage {
		if strings.HasSuffix(row.Scope, " rules") {
			t.Errorf("no source was skipped, so no skip row: %+v", row)
		}
	}
}

// A rule switched off in the catalog stays listed there and is not evaluated here.
func TestDisabledRulesAreNotEvaluated(t *testing.T) {
	off := false
	r := advisoryRule("kubernetes", "off", "1.36")
	r.Enabled = &off
	findings, _ := Analyze(inv(), nil, "1.35", "1.36", cat(r), nil)
	if len(findings) != 0 {
		t.Errorf("a disabled rule must not be reported: %+v", findings)
	}
}

// A name-scoped rule reads ONE subject. The kind is served and read, but no row carries the
// name: the rule asks about that object's content, which an absent row cannot answer, so it
// declines. KIND_PRESENT is the exception, since its question is whether the object exists.
func TestAbsentNamedSubjectDeclinesExceptForKindPresent(t *testing.T) {
	content := sourced("kubernetes", "content", "1.36", catalog.Detection{Kind: catalog.DetectSpecPathMatches,
		ObjectKind: "ConfigMap", ObjectName: "^argocd-cm$", Target: "keys[]", Value: "^repositories$"})
	presence := sourced("kubernetes", "presence", "1.36", catalog.Detection{Kind: catalog.DetectKindPresent,
		ObjectKind: "ConfigMap", ObjectName: "^argocd-cm$"})
	in := inv()
	in.CRs["ConfigMap"] = []inventory.CustomResource{{Kind: "ConfigMap", Namespace: "argocd", Name: "argocd-rbac-cm",
		Spec: map[string]any{"keys": []any{"repositories"}}}}
	findings, coverage := Analyze(in, nil, "1.35", "1.36", cat(content, presence), nil)
	if len(findings) != 0 {
		t.Errorf("nothing named argocd-cm exists, so nothing fires: %+v", findings)
	}
	if len(coverage) != 1 || !strings.Contains(coverage[0].Reason, "absence is not clean") || coverage[0].RulesSkipped != 1 {
		t.Errorf("the content rule declines and the presence rule clears: %+v", coverage)
	}
	// With the subject present the same rule settles.
	in.CRs["ConfigMap"] = append(in.CRs["ConfigMap"], inventory.CustomResource{Kind: "ConfigMap", Namespace: "argocd",
		Name: "argocd-cm", Spec: map[string]any{"keys": []any{"repositories"}}})
	findings, coverage = Analyze(in, nil, "1.35", "1.36", cat(content, presence), nil)
	if len(coverage) != 0 || byRule(findings, "rtz-kubernetes-1.36-content") == nil {
		t.Errorf("with argocd-cm present the content rule fires: findings=%+v coverage=%+v", findings, coverage)
	}
	if f := byRule(findings, "rtz-kubernetes-1.36-content"); f != nil && (len(f.AffectedResources) != 1 || f.AffectedResources[0] != "argocd/argocd-cm") {
		t.Errorf("the name filter keeps the rule off argocd-rbac-cm: %v", f.AffectedResources)
	}
}

// A map at the end of a path reads as key=value per entry, which is the only way a rule can
// name a nodeSelector key, since those keys carry dots.
func TestMapLeavesReadAsKeyEqualsValue(t *testing.T) {
	r := sourced("karpenter", "sel", "1.3", catalog.Detection{Kind: catalog.DetectSpecPathMatches, ObjectKind: "Pod",
		Target: "nodeSelector", Value: `^karpenter\.sh/capacity-type=on-demand$`})
	in := inv()
	in.CRs["Pod"] = []inventory.CustomResource{
		{Kind: "Pod", Namespace: "a", Name: "hit", Spec: map[string]any{"nodeSelector": map[string]any{"karpenter.sh/capacity-type": "on-demand"}}},
		{Kind: "Pod", Namespace: "a", Name: "spot", Spec: map[string]any{"nodeSelector": map[string]any{"karpenter.sh/capacity-type": "spot"}}},
		{Kind: "Pod", Namespace: "a", Name: "none", Spec: map[string]any{}},
	}
	hops := Hops{"karpenter": addons.Hop{AddonID: "karpenter", InstalledVersion: "1.2.0", RequiredVersion: "1.4.0", Reason: addons.HopK8sSupport}}
	findings, _ := Analyze(in, nil, "1.35", "1.36", cat(r), hops)
	f := byRule(findings, "rtz-karpenter-1.3-sel")
	if f == nil || len(f.AffectedResources) != 1 || f.AffectedResources[0] != "a/hit" {
		t.Errorf("want a/hit only, got %+v", f)
	}
}

// A gate is a precondition on another kind. Not met: the rule clears even though its own
// detection matched. Met on the same single kind: the finding is narrowed to the objects that
// opened the gate. Unreadable: the rule declines.
func TestGateClearsNarrowsOrDeclines(t *testing.T) {
	r := sourced("karpenter", "raid", "1.1", catalog.Detection{Kind: catalog.DetectSpecFieldEquals, ObjectKind: "EC2NodeClass",
		Target: "instanceStorePolicy", Value: "RAID0"})
	r.Gate = &catalog.Gate{Kind: catalog.DetectSpecFieldEquals, ObjectKind: "EC2NodeClass", Target: "amiFamily", Value: "Bottlerocket",
		Reason: "only Bottlerocket nodes are affected"}
	hops := Hops{"karpenter": addons.Hop{AddonID: "karpenter", InstalledVersion: "1.0.0", RequiredVersion: "1.2.0", Reason: addons.HopK8sSupport}}
	in := inv()
	in.CRs["EC2NodeClass"] = []inventory.CustomResource{
		{Kind: "EC2NodeClass", Name: "br", Spec: map[string]any{"amiFamily": "Bottlerocket", "instanceStorePolicy": "RAID0"}},
		{Kind: "EC2NodeClass", Name: "al2", Spec: map[string]any{"amiFamily": "AL2", "instanceStorePolicy": "RAID0"}},
	}
	findings, _ := Analyze(in, nil, "1.35", "1.36", cat(r), hops)
	f := byRule(findings, "rtz-karpenter-1.1-raid")
	if f == nil || len(f.AffectedResources) != 1 || f.AffectedResources[0] != "br" {
		t.Fatalf("the finding must be narrowed to the Bottlerocket class: %+v", f)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "precondition met by 1 EC2NodeClass") {
		t.Errorf("evidence must say the gate opened: %v", f.Evidence)
	}
	// Nothing Bottlerocket: the detection alone would fire on al2, the gate clears it.
	in.CRs["EC2NodeClass"] = in.CRs["EC2NodeClass"][1:]
	findings, coverage := Analyze(in, nil, "1.35", "1.36", cat(r), hops)
	if len(findings) != 0 || len(coverage) != 0 {
		t.Errorf("gate not met must clear: findings=%+v coverage=%+v", findings, coverage)
	}
	// The gate's kind unreadable: the rule declines even though the kind is the detection's own.
	delete(in.CRs, "EC2NodeClass")
	in.CRUnread["EC2NodeClass"] = "forbidden"
	findings, coverage = Analyze(in, nil, "1.35", "1.36", cat(r), hops)
	if len(findings) != 0 || len(coverage) != 1 || coverage[0].RulesSkipped != 1 {
		t.Errorf("an unreadable gate is a decline: findings=%+v coverage=%+v", findings, coverage)
	}
}

// A deprecation and its later removal ship under one slug; a hop crossing both fires both on
// the same objects. One card, the removal's severity, naming the folded rule.
func TestDeprecationThenRemovalFoldsOntoOneFinding(t *testing.T) {
	d := catalog.Detection{Kind: catalog.DetectSpecPathMatches, ObjectKind: "ConfigMap", ObjectName: "coredns",
		Target: "corednsPlugins[]", Value: "^federation$"}
	deprecated := sourced("coredns", "federation-plugin-removed", "1.6", d)
	deprecated.Severity = catalog.SeverityMedium
	removed := sourced("coredns", "federation-plugin-removed", "1.7", d)
	removed.Severity = catalog.SeverityHigh
	// A third rule on the same objects but a DIFFERENT change must stay its own card.
	other := sourced("coredns", "proxy-plugin-removed", "1.7", catalog.Detection{Kind: catalog.DetectSpecPathMatches,
		ObjectKind: "ConfigMap", ObjectName: "coredns", Target: "corednsPlugins[]", Value: "^kubernetes$"})
	other.Quote = "a different note"
	in := inv()
	in.CRs["ConfigMap"] = []inventory.CustomResource{{Kind: "ConfigMap", Namespace: "kube-system", Name: "coredns",
		Spec: map[string]any{"corednsPlugins": []any{"kubernetes", "federation"}}}}
	findings, _ := Analyze(in, nil, "1.35", "1.36", cat(deprecated, removed, other), corednsHop("1.4.0", "1.14.7"))
	if len(findings) != 2 {
		t.Fatalf("want the removal card and the proxy card, got %d: %+v", len(findings), findings)
	}
	kept := byRule(findings, "rtz-coredns-1.7-federation-plugin-removed")
	if kept == nil || byRule(findings, "rtz-coredns-1.6-federation-plugin-removed") != nil {
		t.Fatalf("the HIGH removal card is retained and the MEDIUM deprecation folded: %+v", findings)
	}
	if !strings.Contains(strings.Join(kept.Evidence, " "), "rtz-coredns-1.6-federation-plugin-removed") {
		t.Errorf("the retained card names the folded rule: %v", kept.Evidence)
	}
	// Same quote, different slug, same objects also folds (an OR-split pair of one note).
	twinA := sourced("coredns", "csa-marker-a", "1.8", d)
	twinB := sourced("coredns", "csa-marker-b", "1.8", catalog.Detection{Kind: catalog.DetectSpecPathMatches,
		ObjectKind: "ConfigMap", ObjectName: "coredns", Target: "corednsPlugins[]", Value: "^kubernetes$"})
	twinA.Quote, twinB.Quote = "one note", "one note"
	findings, _ = Analyze(in, nil, "1.35", "1.36", cat(twinA, twinB), corednsHop("1.4.0", "1.14.7"))
	if len(findings) != 1 {
		t.Errorf("two rules quoting one note on the same objects are one finding: %+v", findings)
	}
}

// The skew policy: kubelets from nodes, kube-proxy from the kube-system DaemonSet's image tag.
// A cluster with no kube-proxy DaemonSet declines rather than clearing.
func TestVersionSkewReadsKubeletsAndKubeProxy(t *testing.T) {
	kubelet := sourced("kubernetes-skew-policy", "kubelet", "0.0", catalog.Detection{Kind: catalog.DetectVersionSkewExceeds, Target: "kubelet", Value: "3"})
	proxy := sourced("kubernetes-skew-policy", "proxy", "0.0", catalog.Detection{Kind: catalog.DetectVersionSkewExceeds, Target: "kube-proxy", Value: "3"})
	in := inv()
	in.Nodes = []inventory.Node{{Name: "old", KubeletVersion: "v1.31.2"}, {Name: "new", KubeletVersion: "v1.35.0"}}
	in.Collected[inventory.CollectorWorkloads] = inventory.CollectionState{OK: true}
	findings, coverage := Analyze(in, nil, "1.35", "1.36", cat(kubelet, proxy), nil)
	f := byRule(findings, "rtz-kubernetes-skew-policy-0.0-kubelet")
	if f == nil || len(f.AffectedResources) != 1 || !strings.HasPrefix(f.AffectedResources[0], "old (kubelet v1.31.2, 5 minors") {
		t.Errorf("the 1.31 kubelet is 5 minors behind 1.36: %+v", f)
	}
	if len(coverage) != 1 || !strings.Contains(coverage[0].Reason, "no kube-proxy DaemonSet") {
		t.Errorf("no kube-proxy DaemonSet is a decline, not a clear: %+v", coverage)
	}
	in.Workloads = []inventory.Workload{{Kind: "DaemonSet", Namespace: "kube-system", Name: "kube-proxy",
		Containers: []inventory.Container{{Name: "kube-proxy", Image: "registry.k8s.io/kube-proxy:v1.30.1"}}}}
	findings, coverage = Analyze(in, nil, "1.35", "1.36", cat(proxy), nil)
	if f := byRule(findings, "rtz-kubernetes-skew-policy-0.0-proxy"); f == nil || len(coverage) != 0 {
		t.Errorf("a 1.30 kube-proxy is 6 minors behind: findings=%+v coverage=%+v", findings, coverage)
	}
}

// A hint on a projected path names the candidates, and a hint whose kind was not read adds
// nothing rather than a false claim.
func TestHintsNameCandidatesFromProjectedRows(t *testing.T) {
	r := advisoryRule("coredns", "hosts-note", "1.14")
	r.Scope = &catalog.ScopeHint{Kind: catalog.DetectSpecPathMatches, ObjectKind: "ConfigMap", ObjectName: "coredns",
		Target: "corednsPlugins[]", Value: "^hosts$"}
	in := inv()
	in.CRs["ConfigMap"] = []inventory.CustomResource{
		{Kind: "ConfigMap", Namespace: "kube-system", Name: "coredns", Spec: map[string]any{"corednsPlugins": []any{"hosts", "kubernetes"}}},
		{Kind: "ConfigMap", Namespace: "kube-system", Name: "coredns-custom", Spec: map[string]any{"corednsPlugins": []any{"kubernetes"}}},
	}
	findings, _ := Analyze(in, nil, "1.35", "1.36", cat(r), corednsHop("1.4.0", "1.14.7"))
	f := byRule(findings, "rtz-coredns-1.14-hosts-note")
	if f == nil || len(f.Evidence) != 1 || !strings.Contains(f.Evidence[0], "1 ConfigMap object(s) to review: kube-system/coredns") {
		t.Errorf("the hint names the Corefile that uses hosts: %+v", f)
	}
	delete(in.CRs, "ConfigMap")
	findings, _ = Analyze(in, nil, "1.35", "1.36", cat(r), corednsHop("1.4.0", "1.14.7"))
	if f := byRule(findings, "rtz-coredns-1.14-hosts-note"); f == nil || len(f.Evidence) != 0 {
		t.Errorf("an unread hint kind adds no line: %+v", f)
	}
}

// Wants asks for hint and gate kinds too, and only for the rule sets on the path.
func TestWantsCoversHintsGatesAndOnlySelectedSources(t *testing.T) {
	hinted := advisoryRule("coredns", "h", "1.9")
	hinted.Scope = &catalog.ScopeHint{Kind: catalog.DetectSpecPathMatches, ObjectKind: "Deployment|DaemonSet", Target: "containers[].image", Value: "coredns"}
	gatedRule := sourced("karpenter", "g", "1.1", catalog.Detection{Kind: catalog.DetectSpecFieldEquals, ObjectKind: "EC2NodeClass", Target: "instanceStorePolicy", Value: "RAID0"})
	gatedRule.Gate = &catalog.Gate{Kind: catalog.DetectLabelKeyPresent, ObjectKind: "Secret", Target: "x", Reason: "r"}
	c := cat(hinted, gatedRule)
	w := Wants(c, "1.35", "1.36", corednsHop("1.4.0", "1.14.7"))
	if _, ok := w["Deployment"]; !ok {
		t.Errorf("the hint's kinds are collected: %v", w)
	}
	if _, ok := w["EC2NodeClass"]; ok {
		t.Errorf("karpenter has no hop, so its kinds are not collected: %v", w)
	}
	w = Wants(c, "1.35", "1.36", Hops{"karpenter": addons.Hop{AddonID: "karpenter", InstalledVersion: "1.0.0", RequiredVersion: "1.2.0"}})
	if _, ok := w["Secret"]; !ok {
		t.Errorf("the gate's kind is collected once the source is on the path: %v", w)
	}
	if _, ok := w["Deployment"]; ok {
		t.Errorf("coredns has no hop in this scan: %v", w)
	}
}

// The shipped CoreDNS corpus against a projected Corefile: the flagship removal fires on the
// ConfigMap that still uses federation, and nothing fires on a clean one.
func TestShippedCoreDNSRulesAgainstAProjectedCorefile(t *testing.T) {
	c, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	in := inv()
	in.Collected[inventory.CollectorWorkloads] = inventory.CollectionState{OK: true}
	in.CRs["ConfigMap"] = []inventory.CustomResource{{Kind: "ConfigMap", Namespace: "kube-system", Name: "coredns",
		Spec: map[string]any{
			"keys":           []any{"Corefile"},
			"corednsPlugins": []any{"errors", "health", "kubernetes", "federation", "forward"},
			"corednsPluginOptions": map[string]any{"kubernetes": []any{"pods", "resyncperiod", "upstream"},
				"federation": []any{"foo"}, "forward": []any{}, "errors": []any{}, "health": []any{}},
		}}}
	findings, _ := Analyze(in, nil, "1.35", "1.36", c, corednsHop("1.4.0", "1.14.7"))
	var fired []string
	for _, f := range findings {
		if f.RuleSource == "coredns" && f.EnforcementLevel != "advisory" {
			fired = append(fired, f.RuleID)
		}
	}
	joined := strings.Join(fired, " ")
	for _, want := range []string{"federation-plugin-removed", "resyncperiod", "upstream"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the shipped corpus must fire %s on this Corefile; fired: %v", want, fired)
		}
	}
	// The 1.6 deprecation and the 1.7 removal of federation are one finding.
	n := strings.Count(joined, "federation-plugin-removed")
	if n != 1 {
		t.Errorf("federation deprecation+removal must fold to one card, got %d: %v", n, fired)
	}
	in.CRs["ConfigMap"][0].Spec = map[string]any{"keys": []any{"Corefile"}, "corednsPlugins": []any{"errors", "kubernetes", "forward"},
		"corednsPluginOptions": map[string]any{"kubernetes": []any{"pods"}, "forward": []any{}, "errors": []any{}}}
	findings, _ = Analyze(in, nil, "1.35", "1.36", c, corednsHop("1.4.0", "1.14.7"))
	for _, f := range findings {
		if f.RuleSource == "coredns" && f.EnforcementLevel != "advisory" && f.ResourceType == "ConfigMap" {
			t.Errorf("a clean Corefile fires no ConfigMap rule: %s", f.RuleID)
		}
	}
}
