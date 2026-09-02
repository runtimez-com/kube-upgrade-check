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

var now = time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)

func workloadInv(workloads ...inventory.Workload) *inventory.Inventory {
	return &inventory.Inventory{
		ClusterName: "test", Workloads: workloads,
		CRs: map[string][]inventory.CustomResource{},
		Collected: map[string]inventory.CollectionState{
			inventory.CollectorWorkloads: {OK: true},
		},
	}
}

func deployment(namespace, name, image string, labels map[string]string) inventory.Workload {
	return inventory.Workload{
		Kind: "Deployment", Namespace: namespace, Name: name, Labels: labels,
		Containers: []inventory.Container{{Name: "main", Image: image}},
	}
}

func realCatalog(t *testing.T) *catalog.Catalog {
	t.Helper()
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	return cat
}

func statusOf(result Result, addonID string) *report.AddonStatus {
	for i := range result.Addons {
		if result.Addons[i].AddonID == addonID {
			return &result.Addons[i]
		}
	}
	return nil
}

func hasRule(result Result, ruleID string) bool {
	for _, f := range result.Findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestDetectionMatchesRepositorySuffix(t *testing.T) {
	cat := realCatalog(t)
	cases := []struct {
		image string
		want  bool
	}{
		{"public.ecr.aws/karpenter/controller:1.0.5", true},
		{"my-registry.internal/mirror/karpenter/controller:1.0.5", true},
		{"public.ecr.aws/karpenter/controller@sha256:abc123", true},
		{"public.ecr.aws/something/else:1.0.5", false},
	}
	for _, tc := range cases {
		result := Analyze(workloadInv(deployment("karpenter", "karpenter", tc.image, nil)),
			"1.30", "1.31", cat.Addons, now)
		got := statusOf(result, "karpenter") != nil
		if got != tc.want {
			t.Errorf("image %q: detected=%v, want %v", tc.image, got, tc.want)
		}
	}
}

// The vendor publishes both a series row and a patch row that widened the ceiling. The more
// specific row has to win, or every earlier patch silently inherits a version it never supported.
func TestMoreSpecificSupportWindowWins(t *testing.T) {
	windows := []catalog.SupportWindow{
		{Version: "1.0", MinK8s: "1.25", MaxK8s: "1.30"},
		{Version: "1.0.5", MinK8s: "1.25", MaxK8s: "1.31"},
	}
	verdict, window, _ := evaluateWindows(windows, "1.0.5", "1.31")
	if verdict != VerdictSupported || window.MaxK8s != "1.31" {
		t.Errorf("1.0.5 should match its own row: %s / %+v", verdict, window)
	}
	verdict, window, fix := evaluateWindows(windows, "1.0.3", "1.31")
	if verdict != VerdictAboveMax || window.MaxK8s != "1.30" {
		t.Errorf("1.0.3 should fall back to the series row: %s / %+v", verdict, window)
	}
	if fix != "1.0.5" {
		t.Errorf("expected the minimum covering version 1.0.5, got %q", fix)
	}
}

// A prefix must be compared component-wise: "1.1" is not a prefix of "1.13.0".
func TestSeriesPrefixDoesNotMatchAcrossMinors(t *testing.T) {
	windows := []catalog.SupportWindow{{Version: "1.1", MinK8s: "1.25", MaxK8s: "1.28"}}
	if verdict, _, _ := evaluateWindows(windows, "1.13.0", "1.27"); verdict != VerdictVersionNotInCatalog {
		t.Errorf("1.13.0 must not match the 1.1 row, got %s", verdict)
	}
}

// The gate exists so a version predating the concern is never accused of it.
func TestVersionFloorGate(t *testing.T) {
	rule := catalog.AddonRule{AppliesWhenVersionAtLeast: "1.0"}
	if gateAllows(rule, "0.37.0") {
		t.Error("a version below the floor must not be judged by the rule")
	}
	if !gateAllows(rule, "1.0.5") {
		t.Error("a version at or above the floor must be judged")
	}
	if gateAllows(rule, "") {
		t.Error("an unreadable version must not satisfy a floor")
	}
}

// A ceiling gate needs the version provably below it. An unreadable version fails both gates,
// because firing on it would be an accusation with nothing behind it.
func TestVersionCeilingGateRequiresProof(t *testing.T) {
	rule := catalog.AddonRule{AppliesWhenVersionBelow: "1.12.0"}
	if !gateAllows(rule, "1.10.0") {
		t.Error("a version below the ceiling must fire")
	}
	if gateAllows(rule, "1.12.0") {
		t.Error("a version at the ceiling must not fire")
	}
	if gateAllows(rule, "") {
		t.Error("an unreadable version must not satisfy a ceiling gate")
	}
}

// A version older than the concern must not inherit a later version's rule.
func TestKarpenterBelowTheFloorIsNotAccused(t *testing.T) {
	cat := realCatalog(t)
	inv := workloadInv(deployment("karpenter", "karpenter",
		"public.ecr.aws/karpenter/controller:0.37.0", nil))
	inv.CRs["NodePool"] = nil
	inv.CRs["NodeClaim"] = nil
	inv.Collected[inventory.CollectorCRDs] = inventory.CollectionState{OK: true}
	inv.CRDs = []inventory.CRD{{Name: "nodepools.karpenter.sh", ServedVersions: []string{"v1beta1"}}}

	result := Analyze(inv, "1.29", "1.30", cat.Addons, now)
	if hasRule(result, "rtz-addon-karpenter-v1beta1-served") {
		t.Error("a 0.3x install, where v1beta1 is the native API, must not be flagged for serving it")
	}
}

// Two quirks in the same table: a patch release with a higher ceiling than its series, and a
// first patch with a lower ceiling than the ones after it.
func TestIngressNginxCeilingQuirks(t *testing.T) {
	cat := realCatalog(t)
	addon, ok := cat.AddonByID("ingress-nginx")
	if !ok {
		t.Skip("ingress-nginx not in the catalog")
	}
	cases := []struct {
		version   string
		targetK8s string
		want      string
	}{
		{"1.9.6", "1.29", VerdictSupported},
		{"1.9.0", "1.29", VerdictAboveMax},
		{"1.10.0", "1.30", VerdictAboveMax},
		{"1.10.1", "1.30", VerdictSupported},
	}
	for _, tc := range cases {
		got, window, _ := evaluateWindows(addon.SupportWindows, tc.version, tc.targetK8s)
		if got != tc.want {
			max := ""
			if window != nil {
				max = window.MaxK8s
			}
			t.Errorf("ingress-nginx %s against k8s %s: got %s (ceiling %s), want %s",
				tc.version, tc.targetK8s, got, max, tc.want)
		}
	}
}

// An add-on with no published matrix must say so, and must still show its upgrade notes.
func TestNoVendorDataStillRendersNotes(t *testing.T) {
	cat := realCatalog(t)
	addon, ok := cat.AddonByID("coredns")
	if !ok {
		t.Skip("coredns not in the catalog")
	}
	if len(addon.SupportWindows) != 0 {
		t.Skip("coredns now publishes support windows")
	}

	verdict, _, _ := evaluateWindows(addon.SupportWindows, "1.11.1", "1.34")
	if verdict != VerdictNoVendorData {
		t.Errorf("got %s, want NO_VENDOR_DATA", verdict)
	}
	// Without the latest-known-version fallback there is no version anchor and the notes would
	// silently never render, on exactly the add-on whose notes matter most.
	if notes := notesOnPath(addon, "1.9.0"); len(notes) == 0 {
		t.Error("upgrade notes must still render for an add-on with no support windows")
	}
}

func TestUnresolvedVersionIsItsOwnState(t *testing.T) {
	cat := realCatalog(t)
	inv := workloadInv(deployment("karpenter", "karpenter",
		"public.ecr.aws/karpenter/controller@sha256:deadbeef", nil))
	result := Analyze(inv, "1.30", "1.31", cat.Addons, now)

	status := statusOf(result, "karpenter")
	if status == nil {
		t.Fatal("a digest-pinned add-on must still be detected")
	}
	if status.Verdict != VerdictVersionUnresolved {
		t.Errorf("got %s, want VERSION_UNRESOLVED", status.Verdict)
	}
	var found bool
	for _, f := range result.Findings {
		if strings.Contains(f.Title, "version could not be determined") {
			found = true
		}
	}
	if !found {
		t.Error("an unresolvable version must be reported, not passed over")
	}
}

func TestVersionFromLabelWhenTagIsUnusable(t *testing.T) {
	cat := realCatalog(t)
	inv := workloadInv(deployment("karpenter", "karpenter",
		"public.ecr.aws/karpenter/controller@sha256:deadbeef",
		map[string]string{"app.kubernetes.io/version": "1.0.5"}))
	result := Analyze(inv, "1.30", "1.31", cat.Addons, now)

	status := statusOf(result, "karpenter")
	if status == nil || status.InstalledVersion != "1.0.5" || status.VersionSource != "label" {
		t.Errorf("expected the version to come from the label, got %+v", status)
	}
}

// Detecting nothing is a real answer and must not be dressed up as a gap.
func TestNoAddonsDetectedIsComplete(t *testing.T) {
	cat := realCatalog(t)
	result := Analyze(workloadInv(deployment("app", "web", "nginx:1.25", nil)), "1.33", "1.34", cat.Addons, now)
	if len(result.Addons) != 0 || len(result.Findings) != 0 {
		t.Errorf("expected nothing detected, got %+v", result.Addons)
	}
	if len(result.Coverage) != 1 || result.Coverage[0].State != report.CoverageComplete {
		t.Errorf("expected COMPLETE coverage, got %+v", result.Coverage)
	}
}

// Not reading workloads means no add-on could be detected, which is not the same as none.
func TestUnreadWorkloadsReportsUnavailable(t *testing.T) {
	cat := realCatalog(t)
	inv := &inventory.Inventory{
		ClusterName: "test", CRs: map[string][]inventory.CustomResource{},
		Collected: map[string]inventory.CollectionState{
			inventory.CollectorWorkloads: {OK: false, Reason: "permission denied listing deployments"},
		},
	}
	result := Analyze(inv, "1.33", "1.34", cat.Addons, now)
	if len(result.Coverage) != 1 || result.Coverage[0].State != report.CoverageUnavailable {
		t.Fatalf("expected an UNAVAILABLE coverage row, got %+v", result.Coverage)
	}
	if !strings.Contains(result.Coverage[0].Reason, "permission denied") {
		t.Errorf("the reason must reach the reader: %q", result.Coverage[0].Reason)
	}
}

// A stale hand-transcribed table lowers confidence without hiding findings.
func TestStaleCatalogDowngradesCoverageButKeepsFindings(t *testing.T) {
	cat := realCatalog(t)
	inv := workloadInv(deployment("karpenter", "karpenter",
		"public.ecr.aws/karpenter/controller:1.0.5", nil))

	future := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	result := Analyze(inv, "1.30", "1.34", cat.Addons, future)

	if status := statusOf(result, "karpenter"); status == nil || !status.Stale {
		t.Error("a long-unverified catalog must be marked stale")
	}
	if len(result.Coverage) == 0 || result.Coverage[0].State != report.CoveragePartial {
		t.Errorf("stale data should downgrade coverage to PARTIAL, got %+v", result.Coverage)
	}
	var supportFinding bool
	for _, f := range result.Findings {
		if strings.HasSuffix(f.RuleID, "-support") {
			supportFinding = true
		}
	}
	if !supportFinding {
		t.Error("findings must never be suppressed for catalog age")
	}
}

func TestRuleFindingCarriesTheVendorQuoteAndSource(t *testing.T) {
	cat := realCatalog(t)
	inv := workloadInv(
		deployment("ingress-nginx", "ingress-nginx-controller",
			"registry.k8s.io/ingress-nginx/controller:v1.10.0", nil))
	inv.Collected[inventory.CollectorIngresses] = inventory.CollectionState{OK: true}
	inv.Ingresses = []inventory.Ingress{{
		Namespace: "shop", Name: "web",
		AnnotationKeys: []string{"nginx.ingress.kubernetes.io/configuration-snippet"},
	}}

	result := Analyze(inv, "1.28", "1.29", cat.Addons, now)
	for _, f := range result.Findings {
		if f.RuleID != "rtz-addon-ingress-nginx-snippet-annotations" {
			continue
		}
		if f.Quote == "" || f.SourceURL == "" {
			t.Errorf("a finding must carry the vendor's words and where they came from: %+v", f)
		}
		if !strings.Contains(f.Recommendation, "shop/web") {
			t.Errorf("the affected object must be named: %q", f.Recommendation)
		}
		return
	}
	t.Error("expected the snippet-annotation rule to fire for a 1.10.0 install")
}

func TestEveryCatalogRuleNamesAnImplementedPredicate(t *testing.T) {
	cat := realCatalog(t)
	// A rule naming a predicate nobody implemented would ship as a check that silently never
	// fires, which is indistinguishable in the output from a check that passed.
	unknown := 0
	registry := predicates.Registry()
	if len(registry) == 0 {
		t.Fatal("no predicates registered")
	}
	for _, addon := range cat.Addons {
		for _, rule := range addon.Rules {
			if _, ok := registry[rule.Kind]; !ok {
				t.Errorf("%s rule %s names unimplemented predicate %q", addon.AddonID, rule.RuleID, rule.Kind)
				unknown++
			}
		}
	}
	if unknown > 0 {
		t.Errorf("%d catalog rules would silently never fire", unknown)
	}
}

// A vendor saying "supported from here on" leaves the ceiling empty. Treating an absent bound as
// unparseable would flip a genuinely supported add-on into an unknown.
func TestOpenEndedSupportWindows(t *testing.T) {
	cases := []struct {
		name    string
		windows []catalog.SupportWindow
		version string
		target  string
		want    string
	}{
		{"no ceiling, target above floor",
			[]catalog.SupportWindow{{Version: "2.0", MinK8s: "1.28", MaxK8s: ""}}, "2.0.1", "1.34", VerdictSupported},
		{"no ceiling, target below floor",
			[]catalog.SupportWindow{{Version: "2.0", MinK8s: "1.30", MaxK8s: ""}}, "2.0.1", "1.29", VerdictBelowMin},
		{"no floor, target below ceiling",
			[]catalog.SupportWindow{{Version: "2.0", MinK8s: "", MaxK8s: "1.34"}}, "2.0.1", "1.30", VerdictSupported},
		{"no floor, target above ceiling",
			[]catalog.SupportWindow{{Version: "2.0", MinK8s: "", MaxK8s: "1.30"}}, "2.0.1", "1.34", VerdictAboveMax},
		{"neither bound is usable",
			[]catalog.SupportWindow{{Version: "2.0", MinK8s: "", MaxK8s: ""}}, "2.0.1", "1.34", VerdictVersionNotInCatalog},
	}
	for _, tc := range cases {
		got, _, _ := evaluateWindows(tc.windows, tc.version, tc.target)
		if got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}
