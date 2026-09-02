package predicates

import (
	"strings"
	"testing"
)

func TestRegistryCoversEveryKind(t *testing.T) {
	want := []string{
		"crdAbsent", "crdServedVersion", "crFieldAbsent", "crdFlagSet",
		"crSelectorFormat", "crAnnotationKey", "crSpecListContains",
	}
	reg := Registry()
	if len(reg) != len(want) {
		t.Errorf("registry has %d predicates, want %d", len(reg), len(want))
	}
	for _, kind := range want {
		p, ok := reg[kind]
		if !ok {
			t.Errorf("%s is not registered", kind)
			continue
		}
		if p.Kind() != kind {
			t.Errorf("%s registered under the wrong key: %s", p.Kind(), kind)
		}
	}
}

func assertOutcome(t *testing.T, got Result, want Outcome, context string) {
	t.Helper()
	if got.Outcome != want {
		t.Errorf("%s: got %s, want %s (evidence %q, reason %q)",
			context, name(got.Outcome), name(want), got.Evidence, got.Reason)
	}
	// A declined outcome is only useful if it says why; a reader who is told a check did not
	// run and not told why cannot do anything about it.
	if got.Outcome == Declined && strings.TrimSpace(got.Reason) == "" {
		t.Errorf("%s: declined with no reason", context)
	}
}

func name(o Outcome) string {
	switch o {
	case Fired:
		return "Fired"
	case Clear:
		return "Clear"
	default:
		return "Declined"
	}
}

// The distinction the whole package exists to preserve: unreadable data is not a clean result.
func TestUnreadableDataDeclinesRatherThanClears(t *testing.T) {
	cases := []struct {
		name      string
		predicate Predicate
		ctx       Context
		params    map[string]any
	}{
		{
			"crdAbsent with no CRD list", crdAbsent{}, Context{Label: "thing"},
			map[string]any{"crdName": "widgets.example.com"},
		},
		{
			"crdServedVersion with no CRD list", crdServedVersion{}, Context{},
			map[string]any{"crdNames": []any{"a.example.com"}, "servedVersion": "v1beta1"},
		},
		{
			"crdFlagSet with no CRD list", crdFlagSet{}, Context{},
			map[string]any{"crdName": "a.example.com", "anyOfFlags": []any{"f"}},
		},
		{
			"crAnnotationKey on an unread kind", crAnnotationKey{}, Context{Rows: map[string][]Row{}},
			map[string]any{"crKind": "Ingress", "annotationKeyPattern": "^x$"},
		},
		{
			"crSpecListContains on an unread kind", crSpecListContains{}, Context{Rows: map[string][]Row{}},
			map[string]any{"crKind": "ConfigMap", "field": "plugins", "anyOf": []any{"proxy"}},
		},
		{
			"crFieldAbsent on an unread kind", crFieldAbsent{}, Context{Rows: map[string][]Row{}},
			map[string]any{"crKinds": []any{"NodePool"}, "field": "ref", "requiredKeys": []any{"group"}},
		},
		{
			"crSelectorFormat on an unread kind", crSelectorFormat{}, Context{Rows: map[string][]Row{}},
			map[string]any{"crKinds": []any{"ApplicationSet"}, "field": "selector", "expectedPattern": "^x$"},
		},
	}
	for _, tc := range cases {
		assertOutcome(t, tc.predicate.Evaluate(tc.ctx, tc.params), Declined, tc.name)
	}
}

// Read and found nothing is a real answer, and must not be confused with the above.
func TestReadButEmptyIsClear(t *testing.T) {
	ctx := Context{Rows: map[string][]Row{"Ingress": {}}}
	assertOutcome(t, crAnnotationKey{}.Evaluate(ctx,
		map[string]any{"crKind": "Ingress", "annotationKeyPattern": "^x$"}), Clear, "empty Ingress list")

	crdCtx := Context{CRDNames: map[string]bool{"other.example.com": true}}
	assertOutcome(t, crdAbsent{}.Evaluate(crdCtx,
		map[string]any{"crdName": "other.example.com"}), Clear, "CRD present")
}

// A catalog writes a shared core kind as "ConfigMap@namespace" to scope the read. That suffix is
// an instruction to the collector, not part of the kind, and three shipped rules were inert
// because predicates compared the raw string against collected data.
func TestScopedKindSuffixIsStrippedBeforeMatching(t *testing.T) {
	ctx := Context{Rows: map[string][]Row{"ConfigMap": {{
		Kind: "ConfigMap", Namespace: "kube-system", Name: "coredns",
		Spec: map[string]any{"corednsPlugins": []any{"kubernetes", "proxy"}},
	}}}}
	got := crSpecListContains{}.Evaluate(ctx, map[string]any{
		"crKind": "ConfigMap@namespace", "field": "corednsPlugins", "anyOf": []any{"proxy"},
	})
	assertOutcome(t, got, Fired, "scoped kind")
	if !strings.Contains(got.Evidence, "kube-system/coredns") {
		t.Errorf("the offending object must be named: %q", got.Evidence)
	}

	if NormalizeKind("ConfigMap@namespace") != "ConfigMap" || NormalizeKind("Ingress") != "Ingress" {
		t.Error("NormalizeKind must strip the scope suffix and leave a bare kind alone")
	}
}

func TestCrdServedVersionNamesOnlyTheServingCRDs(t *testing.T) {
	ctx := Context{CRDServedVersions: map[string]map[string]bool{
		"nodepools.karpenter.sh":  {"v1": true, "v1beta1": true},
		"nodeclaims.karpenter.sh": {"v1": true},
	}}
	got := crdServedVersion{}.Evaluate(ctx, map[string]any{
		"crdNames":      []any{"nodepools.karpenter.sh", "nodeclaims.karpenter.sh"},
		"servedVersion": "v1beta1",
	})
	assertOutcome(t, got, Fired, "served version")
	if !strings.Contains(got.Evidence, "nodepools.karpenter.sh") || strings.Contains(got.Evidence, "nodeclaims") {
		t.Errorf("only the serving CRD should be named: %q", got.Evidence)
	}
}

// A flag that is absent is unknown, and unknown is neither true nor false.
func TestCrdFlagSetDistinguishesUnknownFromFalse(t *testing.T) {
	params := map[string]any{
		"crdName":    "applicationsets.argoproj.io",
		"anyOfFlags": []any{"lastAppliedConfigurationPresent", "clientSideApplyManager"},
	}
	base := Context{CRDNames: map[string]bool{"applicationsets.argoproj.io": true}}

	assertOutcome(t, crdFlagSet{}.Evaluate(base, params), Declined, "no flag collected")

	base.CRDFlags = map[string]map[string]bool{
		"applicationsets.argoproj.io": {"lastAppliedConfigurationPresent": false, "clientSideApplyManager": false},
	}
	assertOutcome(t, crdFlagSet{}.Evaluate(base, params), Clear, "flags collected and false")

	base.CRDFlags["applicationsets.argoproj.io"]["lastAppliedConfigurationPresent"] = true
	assertOutcome(t, crdFlagSet{}.Evaluate(base, params), Fired, "flag present and true")
}

// Annotation values can hold arbitrary configuration and must never reach a finding.
func TestCrAnnotationKeyReportsKeysNeverValues(t *testing.T) {
	ctx := Context{Rows: map[string][]Row{"Ingress": {
		{Kind: "Ingress", Namespace: "shop", Name: "web", AnnotationKeys: []string{
			"nginx.ingress.kubernetes.io/configuration-snippet", "kubernetes.io/ingress.class",
		}},
	}}}
	got := crAnnotationKey{}.Evaluate(ctx, map[string]any{
		"crKind":               "Ingress",
		"annotationKeyPattern": `^nginx\.ingress\.kubernetes\.io/(configuration|server|stream)-snippet$`,
	})
	assertOutcome(t, got, Fired, "snippet annotation")
	if !strings.Contains(got.Evidence, "shop/web") || !strings.Contains(got.Evidence, "configuration-snippet") {
		t.Errorf("object and key must be named: %q", got.Evidence)
	}
	if strings.Contains(got.Evidence, "ingress.class") {
		t.Errorf("a non-matching key must not appear: %q", got.Evidence)
	}
}

// A pattern the catalog wrote wrong is our bug, not the cluster's.
func TestBadPatternDeclines(t *testing.T) {
	ctx := Context{Rows: map[string][]Row{"Ingress": {{Name: "web", AnnotationKeys: []string{"a"}}}}}
	assertOutcome(t, crAnnotationKey{}.Evaluate(ctx,
		map[string]any{"crKind": "Ingress", "annotationKeyPattern": "([unclosed"}), Declined, "bad pattern")
}

// An absent field is a collection gap on that object; present and empty is genuinely clean.
func TestCrSpecListContainsSkipsAbsentFields(t *testing.T) {
	params := map[string]any{"crKind": "ConfigMap", "field": "corednsPlugins", "anyOf": []any{"federation", "proxy"}}
	ctx := Context{Rows: map[string][]Row{"ConfigMap": {
		{Kind: "ConfigMap", Namespace: "kube-system", Name: "coredns", Spec: map[string]any{}},
	}}}
	assertOutcome(t, crSpecListContains{}.Evaluate(ctx, params), Clear, "absent field")

	ctx.Rows["ConfigMap"][0].Spec["corednsPlugins"] = []any{"kubernetes", "forward"}
	assertOutcome(t, crSpecListContains{}.Evaluate(ctx, params), Clear, "populated, no match")

	ctx.Rows["ConfigMap"][0].Spec["corednsPlugins"] = []any{"kubernetes", "federation"}
	assertOutcome(t, crSpecListContains{}.Evaluate(ctx, params), Fired, "populated, matching")
}

// Grouping by kind stops one misconfigured parent reading as hundreds of problems.
func TestCrFieldAbsentGroupsByKind(t *testing.T) {
	rows := map[string][]Row{
		"NodePool":  {{Kind: "NodePool", Name: "default", Spec: map[string]any{"nodeClassRef": map[string]any{"name": "x"}}}},
		"NodeClaim": {},
	}
	for i := 0; i < 3; i++ {
		rows["NodeClaim"] = append(rows["NodeClaim"], Row{
			Kind: "NodeClaim", Name: "claim" + string(rune('a'+i)),
			Spec: map[string]any{"nodeClassRef": map[string]any{"name": "x"}},
		})
	}
	got := crFieldAbsent{}.Evaluate(Context{Rows: rows}, map[string]any{
		"crKinds": []any{"NodePool", "NodeClaim"}, "field": "nodeClassRef",
		"requiredKeys": []any{"group", "kind"},
	})
	assertOutcome(t, got, Fired, "missing fields")
	if !strings.Contains(got.Evidence, "1 NodePool") || !strings.Contains(got.Evidence, "3 NodeClaims") {
		t.Errorf("counts must be reported per kind: %q", got.Evidence)
	}
}

// One unread kind declines the whole rule: a partial answer must not carry a complete one's
// confidence.
func TestCrFieldAbsentDeclinesWhenAnyKindIsUnread(t *testing.T) {
	got := crFieldAbsent{}.Evaluate(
		Context{Rows: map[string][]Row{
			"NodePool": {{Kind: "NodePool", Name: "default", Spec: map[string]any{"nodeClassRef": map[string]any{}}}},
		}},
		map[string]any{"crKinds": []any{"NodePool", "NodeClaim"}, "field": "nodeClassRef", "requiredKeys": []any{"group"}})
	assertOutcome(t, got, Declined, "one kind unread")
}

// Demanding that N kinds be readable and then examining only the first makes the rest a
// precondition for an answer they never inform.
func TestCrSelectorFormatScansEveryDeclaredKind(t *testing.T) {
	ctx := Context{Rows: map[string][]Row{
		"ApplicationSet": {{Kind: "ApplicationSet", Name: "clean", Spec: map[string]any{
			"selector": map[string]any{"new.format": "x"}}}},
		"Secret": {{Kind: "Secret", Namespace: "argocd", Name: "cluster", Spec: map[string]any{
			"selector": map[string]any{"old-style": "x"}}}},
	}}
	got := crSelectorFormat{}.Evaluate(ctx, map[string]any{
		"crKinds": []any{"ApplicationSet", "Secret@namespace"}, "field": "selector",
		"expectedPattern": `^new\..*$`,
	})
	assertOutcome(t, got, Fired, "violation on the second kind")
	if !strings.Contains(got.Evidence, "cluster") {
		t.Errorf("the offending object on the second kind must be named: %q", got.Evidence)
	}
}

func TestCrSelectorFormatGate(t *testing.T) {
	ctx := Context{
		Rows: map[string][]Row{"Application": {
			{Kind: "Application", Name: "app", Spec: map[string]any{"selector": map[string]any{"old-style": "x"}}},
		}},
		Labels: map[string][]Row{"Deployment": {{Kind: "Deployment", Name: "argocd", Labels: map[string]string{"app": "argocd"}}}},
	}
	params := map[string]any{
		"crKinds": []any{"Application"}, "field": "selector", "expectedPattern": `^new\..*$`,
		"gateKind": "Deployment", "gateLabel": "app", "gateLabelEquals": "argocd",
	}
	assertOutcome(t, crSelectorFormat{}.Evaluate(ctx, params), Fired, "gate satisfied")

	params["gateLabelEquals"] = "something-else"
	assertOutcome(t, crSelectorFormat{}.Evaluate(ctx, params), Clear, "gate not satisfied")
}

func TestNamedListCollapsesPastTheLimit(t *testing.T) {
	set := map[string]bool{}
	for i := 0; i < maxNamed+5; i++ {
		set[string(rune('a'+i))] = true
	}
	if got := namedList(set); !strings.Contains(got, "+5 more") {
		t.Errorf("expected the overflow count, got %q", got)
	}
}
