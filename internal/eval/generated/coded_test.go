package generated

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/addons"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
)

func karpenterHop() Hops {
	return Hops{"karpenter": addons.Hop{AddonID: "karpenter", InstalledVersion: "1.14.0", RequiredVersion: "1.15.1", Reason: addons.HopK8sSupport}}
}

func lbcHop(installed, required string) Hops {
	return Hops{"aws-load-balancer-controller": addons.Hop{AddonID: "aws-load-balancer-controller",
		InstalledVersion: installed, RequiredVersion: required, Reason: addons.HopCurrency}}
}

// nodeClass is an EC2NodeClass row as projectEC2NodeClass writes it.
func nodeClass(name, family, alias string, dns int, kubelet ...string) inventory.CustomResource {
	keys := []any{}
	for _, k := range kubelet {
		keys = append(keys, k)
	}
	return inventory.CustomResource{Kind: "EC2NodeClass", Name: name, Spec: map[string]any{
		"amiFamily": family, "amiAliasFamily": alias, "kubeletKeys": keys, "kubeletClusterDnsCount": dns}}
}

// `a|b`: a Bottlerocket pool picked by alias alone (amiFamily empty) opens the RAID0 gate, and
// only that pool is named.
func TestAlternativeFieldTargetMatchesEitherField(t *testing.T) {
	r := sourced("karpenter", "raid", "1.1", catalog.Detection{Kind: catalog.DetectSpecFieldEquals, ObjectKind: "EC2NodeClass",
		Target: "instanceStorePolicy", Value: "RAID0"})
	r.Gate = &catalog.Gate{Kind: catalog.DetectSpecFieldEquals, ObjectKind: "EC2NodeClass", Target: "amiFamily|amiAliasFamily",
		Value: "Bottlerocket", Reason: "only Bottlerocket nodes are affected"}
	hops := Hops{"karpenter": addons.Hop{AddonID: "karpenter", InstalledVersion: "1.0.0", RequiredVersion: "1.2.0", Reason: addons.HopK8sSupport}}
	in := inv()
	in.CRs["EC2NodeClass"] = []inventory.CustomResource{
		{Kind: "EC2NodeClass", Name: "br-alias", Spec: map[string]any{"amiFamily": "", "amiAliasFamily": "bottlerocket", "instanceStorePolicy": "RAID0"}},
		{Kind: "EC2NodeClass", Name: "al2023", Spec: map[string]any{"amiFamily": "", "amiAliasFamily": "al2023", "instanceStorePolicy": "RAID0"}},
	}
	findings, _ := Analyze(in, nil, "1.35", "1.36", cat(r), hops)
	f := byRule(findings, "rtz-karpenter-1.1-raid")
	if f == nil || len(f.AffectedResources) != 1 || f.AffectedResources[0] != "br-alias" {
		t.Fatalf("the alias-only Bottlerocket class must open the gate and be the only one named: %+v", f)
	}
	// The plain field still answers on its own.
	in.CRs["EC2NodeClass"] = []inventory.CustomResource{
		{Kind: "EC2NodeClass", Name: "br", Spec: map[string]any{"amiFamily": "Bottlerocket", "amiAliasFamily": "", "instanceStorePolicy": "RAID0"}},
	}
	findings, _ = Analyze(in, nil, "1.35", "1.36", cat(r), hops)
	if f := byRule(findings, "rtz-karpenter-1.1-raid"); f == nil || f.AffectedResources[0] != "br" {
		t.Fatalf("amiFamily must still open the gate: %+v", f)
	}
	// And Wants keeps both fields when a projection is in play.
	if keep := Wants(cat(r), "1.35", "1.36", hops)["EC2NodeClass"].Keep; !contains(keep, "amiFamily") || !contains(keep, "amiAliasFamily") {
		t.Errorf("both alternatives must be kept: %v", keep)
	}
}

func TestKarpenterKubeletCodedCheck(t *testing.T) {
	cases := []struct {
		name string
		spec map[string]any
		want []string // nil = unjudged
	}{
		{"bottlerocket by alias, unmapped field and podsPerCore", nodeClass("x", "", "bottlerocket", 0, "podsPerCore", "maxPods", "cpuManagerPolicy").Spec,
			[]string{"AMI family bottlerocket: spec.kubelet sets cpuManagerPolicy, podsPerCore, which this family does not apply"}},
		{"amiFamily wins over the alias", nodeClass("x", "AL2023", "bottlerocket", 0, "cpuManagerPolicy").Spec, []string{}},
		{"two clusterDNS entries on AL2", nodeClass("x", "AL2", "", 2, "clusterDNS").Spec,
			[]string{"AMI family al2: spec.kubelet.clusterDNS has 2 entries; this family accepts one"}},
		{"one clusterDNS entry is fine", nodeClass("x", "AL2", "", 1, "clusterDNS", "maxPods").Spec, []string{}},
		{"custom is never judged wrong", nodeClass("x", "Custom", "", 0, "cpuManagerPolicy").Spec, []string{}},
		{"no family named", nodeClass("x", "", "", 0, "cpuManagerPolicy").Spec, []string{}},
		{"no kubelet keys", nodeClass("x", "Bottlerocket", "", 0).Spec, []string{}},
		{"row without kubeletKeys is unjudged", map[string]any{"amiFamily": "Bottlerocket"}, nil},
	}
	for _, tc := range cases {
		got := karpenterKubeletUnsupported(tc.spec)
		if (got == nil) != (tc.want == nil) || strings.Join(got, "|") != strings.Join(tc.want, "|") {
			t.Errorf("%s: got %#v, want %#v", tc.name, got, tc.want)
		}
	}
}

// The SHIPPED 1.15 rule, not a look-alike: it loads, fires on the broken class only, and declines
// on rows the projection could not judge.
func TestShippedKarpenterKubeletRule(t *testing.T) {
	c, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	var shipped []catalog.GeneratedRule
	for _, r := range c.GeneratedRules {
		if r.Detection.Kind == catalog.DetectCodedCheck && r.Detection.Target == "karpenter-kubelet-fields-unsupported" {
			shipped = append(shipped, r)
		}
	}
	if len(shipped) != 1 || shipped[0].SourceID != "karpenter" || shipped[0].AppliesAtVersion != "1.15" {
		t.Fatalf("want the one karpenter 1.15 coded rule, got %+v", shipped)
	}
	in := inv()
	in.CRs["EC2NodeClass"] = []inventory.CustomResource{
		nodeClass("br", "", "bottlerocket", 0, "podsPerCore"),
		nodeClass("al2023", "", "al2023", 3, "clusterDNS", "cpuManagerPolicy"),
	}
	findings, coverage := Analyze(in, nil, "1.35", "1.36", cat(shipped...), karpenterHop())
	f := byRule(findings, shipped[0].RuleID)
	if f == nil || len(f.AffectedResources) != 1 || f.AffectedResources[0] != "br" || len(coverage) != 0 {
		t.Fatalf("want br only: %+v coverage=%+v", f, coverage)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "br: AMI family bottlerocket: spec.kubelet sets podsPerCore") {
		t.Errorf("evidence must say what is wrong: %v", f.Evidence)
	}
	in.CRs["EC2NodeClass"] = []inventory.CustomResource{{Kind: "EC2NodeClass", Name: "old", Spec: map[string]any{"amiFamily": "Bottlerocket"}}}
	findings, coverage = Analyze(in, nil, "1.35", "1.36", cat(shipped...), karpenterHop())
	if byRule(findings, shipped[0].RuleID) != nil || len(coverage) != 1 || !strings.Contains(coverage[0].Reason, "lack the fields") {
		t.Errorf("an unjudged row is a decline, never clean: findings=%+v coverage=%+v", findings, coverage)
	}
}

func controller(name string, args ...string) inventory.CustomResource {
	c := map[string]any{"name": "controller", "image": "602401143452.dkr.ecr.us-west-2.amazonaws.com/amazon/aws-load-balancer-controller:v2.13.0"}
	if args != nil {
		list := []any{}
		for _, a := range args {
			list = append(list, a)
		}
		c["args"] = list
	}
	return inventory.CustomResource{Kind: "Deployment", Namespace: "kube-system", Name: name, Spec: map[string]any{"containers": []any{c}}}
}

func TestSpecPathNoneMatches(t *testing.T) {
	r := sourced("aws-load-balancer-controller", "endpointslices", "2.14", catalog.Detection{Kind: catalog.DetectSpecPathNoneMatches,
		ObjectKind: "Deployment", ObjectImage: "/aws-load-balancer-controller", Target: "containers[].args[]|containers[].command[]",
		Value: "^--enable-endpoint-slices(=|$)"})
	hops := lbcHop("2.13.0", "2.14.1")
	run := func(rows ...inventory.CustomResource) (bool, int, string) {
		in := inv()
		in.CRs["Deployment"] = rows
		findings, coverage := Analyze(in, nil, "1.35", "1.36", cat(r), hops)
		reason := ""
		if len(coverage) > 0 {
			reason = coverage[0].Reason
		}
		return byRule(findings, r.RuleID) != nil, len(coverage), reason
	}
	other := inventory.CustomResource{Kind: "Deployment", Namespace: "app", Name: "web", Spec: map[string]any{
		"containers": []any{map[string]any{"name": "web", "image": "nginx:1.27", "args": []any{"--x"}}}}}
	if fired, gaps, _ := run(controller("aws-load-balancer-controller", "--cluster-name=c"), other); !fired || gaps != 0 {
		t.Errorf("the controller without the flag must fire (and the app Deployment is not its subject)")
	}
	if fired, gaps, _ := run(controller("aws-load-balancer-controller", "--cluster-name=c", "--enable-endpoint-slices=false")); fired || gaps != 0 {
		t.Errorf("the flag set must clear")
	}
	if fired, gaps, why := run(controller("aws-load-balancer-controller")); fired || gaps != 1 || !strings.Contains(why, "not in the collected projection") {
		t.Errorf("no args and no command is unresolved, a gap rather than clean or a hit: %v", why)
	}
	if fired, gaps, why := run(other); fired || gaps != 1 || !strings.Contains(why, "absence is not clean") {
		t.Errorf("no controller Deployment in the scan must decline: %v", why)
	}
	// A CRD's schema fields: a missing field fires; a CRD carrying it clears.
	crdRule := sourced("aws-load-balancer-controller", "crd", "3.6", catalog.Detection{Kind: catalog.DetectSpecPathNoneMatches,
		ObjectKind: "CustomResourceDefinition", ObjectName: `^(targetgroupbindings\.elbv2\.k8s\.aws)$`, Target: "crdSpecFields[]",
		Value: "^(registerTargetsWithPodAvailabilityZone)$"})
	crd := func(fields ...string) inventory.CRD {
		props := map[string]any{}
		for _, f := range fields {
			props[f] = map[string]any{"type": "string"}
		}
		return inventory.CRD{Name: "targetgroupbindings.elbv2.k8s.aws", Spec: map[string]any{"group": "elbv2.k8s.aws",
			"versions": []any{map[string]any{"name": "v1beta1", "served": true, "storage": true, "schema": map[string]any{
				"openAPIV3Schema": map[string]any{"properties": map[string]any{"spec": map[string]any{"properties": props}}}}}}}}
	}
	in := inv()
	in.Collected[inventory.CollectorCRDs] = inventory.CollectionState{OK: true}
	in.CRDs = []inventory.CRD{crd("serviceRef", "targetGroupARN")}
	findings, _ := Analyze(in, nil, "1.35", "1.36", cat(crdRule), lbcHop("3.5.0", "3.6.2"))
	if f := byRule(findings, crdRule.RuleID); f == nil || f.AffectedResources[0] != "targetgroupbindings.elbv2.k8s.aws" {
		t.Errorf("a CRD lacking the field must fire: %+v", findings)
	}
	in.CRDs = []inventory.CRD{crd("serviceRef", "registerTargetsWithPodAvailabilityZone")}
	if findings, coverage := Analyze(in, nil, "1.35", "1.36", cat(crdRule), lbcHop("3.5.0", "3.6.2")); len(findings) != 0 || len(coverage) != 0 {
		t.Errorf("an updated CRD must clear: %+v %+v", findings, coverage)
	}
}

func TestRequiresInstalledSinceFloors(t *testing.T) {
	r := advisoryRule("traefik", "encoded", "3.6")
	r.IntroducedIn = []string{"2.11.35", "3.6.7"}
	r.RequiresInstalledSince = []string{"2.11.32", "3.6.4"}
	cases := []struct {
		installed, required string
		want                bool
	}{
		{"v3.6.5", "3.6.9", true},   // carries what the change reverts
		{"v3.6.2", "3.6.9", false},  // below the floor: never had it
		{"v3.5.4", "3.6.9", false},  // a line with no floor never had it
		{"v2.11.33", "3.6.9", true}, // floor met on the older line
		{"latest", "3.6.9", true},   // unreadable installed version keeps the rule
	}
	for _, tc := range cases {
		if got := inAddonHop(r, tc.installed, tc.required); got != tc.want {
			t.Errorf("installed %s → %s: got %v, want %v", tc.installed, tc.required, got, tc.want)
		}
	}
}

// A per-rule alwaysOn reaches every hop of its add-on, but still needs the add-on resolved.
func TestAlwaysOnRuleIgnoresTheHopWindowButNeedsTheAddon(t *testing.T) {
	r := advisoryRule("aws-load-balancer-controller", "deprecated", "2.4")
	r.AlwaysOn = true
	plain := advisoryRule("aws-load-balancer-controller", "plain", "2.4")
	sel := onPath(cat(r, plain), "1.35", "1.36", lbcHop("3.5.0", "3.6.2"))
	if len(sel.rules) != 1 || sel.rules[0].RuleID != r.RuleID {
		t.Errorf("only the alwaysOn rule rides a 3.5 → 3.6 hop: %+v", sel.rules)
	}
	if sel := onPath(cat(r), "1.35", "1.36", Hops{}); len(sel.rules) != 0 || len(sel.skipped) != 1 {
		t.Errorf("no hop for the add-on: nothing selected, the source stated: %+v", sel)
	}
}
