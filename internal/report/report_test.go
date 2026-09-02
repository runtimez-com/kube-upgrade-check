package report

import (
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
)

// --strict is derived from this function, so anything it gets wrong is a gate that does not fire.
func TestStatusFor(t *testing.T) {
	cases := []struct {
		name     string
		coverage []Coverage
		want     ScanStatus
	}{
		{"everything ran", []Coverage{{State: CoverageComplete}, {State: CoverageComplete}}, ScanComplete},
		{"one gap", []Coverage{{State: CoverageComplete}, {State: CoverageUnavailable}}, ScanPartial},
		{"one partial", []Coverage{{State: CoverageComplete}, {State: CoveragePartial}}, ScanPartial},
		{"nothing ran", []Coverage{{State: CoverageUnavailable}, {State: CoverageUnavailable}}, ScanInsufficientData},
		// No rows at all means nothing reported a gap, which is the complete case. It is also
		// the shape a scan takes if coverage reporting ever regresses, which is why every
		// collector now emits a row unconditionally.
		{"no rows", nil, ScanComplete},
	}
	for _, tc := range cases {
		if got := StatusFor(tc.coverage); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.name, got, tc.want)
		}
	}
}

// An unstable report cannot be diffed, and diffing two runs is how anyone verifies a fix.
func TestSortIsStableAndSeverityFirst(t *testing.T) {
	findings := []Finding{
		{RuleID: "b", Severity: catalog.SeverityLow},
		{RuleID: "a", Severity: catalog.SeverityCritical},
		{RuleID: "c", Severity: catalog.SeverityHigh},
		{RuleID: "a", Severity: catalog.SeverityCritical, ResourceName: "z"},
		{RuleID: "a", Severity: catalog.SeverityCritical, ResourceName: "a"},
	}
	Sort(findings)

	if findings[0].Severity != catalog.SeverityCritical || findings[len(findings)-1].Severity != catalog.SeverityLow {
		t.Fatalf("severity must order first: %+v", findings)
	}
	// Within one severity and rule, resource name breaks the tie so runs are reproducible.
	if findings[0].ResourceName != "" || findings[1].ResourceName != "a" || findings[2].ResourceName != "z" {
		t.Errorf("ties must break deterministically: %+v", findings[:3])
	}
}

func TestCountBySeverity(t *testing.T) {
	got := CountBySeverity([]Finding{
		{Severity: catalog.SeverityCritical}, {Severity: catalog.SeverityCritical},
		{Severity: catalog.SeverityInfo},
	})
	if got["CRITICAL"] != 2 || got["INFO"] != 1 {
		t.Errorf("unexpected counts: %+v", got)
	}
}

// The same finding must carry the same id in this tool and in the hosted product, so the two can
// be compared directly.
func TestNewIDIsDeterministicAndDistinguishing(t *testing.T) {
	a := NewID("rtz-k8s-dep-extensions-ingress", "shop/web")
	if a != NewID("rtz-k8s-dep-extensions-ingress", "shop/web") {
		t.Error("the same inputs must produce the same id")
	}
	if a == NewID("rtz-k8s-dep-extensions-ingress", "shop/api") {
		t.Error("different resources must produce different ids")
	}
	if a == NewID("other-rule", "shop/web") {
		t.Error("different rules must produce different ids")
	}
}

func TestCoverageOK(t *testing.T) {
	if !(Coverage{State: CoverageComplete}).OK() {
		t.Error("a complete row is the only one that counts as having run")
	}
	for _, state := range []CoverageState{CoveragePartial, CoverageUnavailable} {
		if (Coverage{State: state}).OK() {
			t.Errorf("%s must not count as a completed check", state)
		}
	}
}
