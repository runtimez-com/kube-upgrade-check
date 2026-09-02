package advisory

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
)

func rules() []catalog.AdvisoryRule {
	return []catalog.AdvisoryRule{
		{RuleID: "a-131", Version: "1.31", Title: "Old change", Remediation: "Do a thing.", VerifyCommand: "kubectl get x"},
		{RuleID: "a-133", Version: "1.33", Title: "Current change", Remediation: "Do a thing."},
		{RuleID: "a-134", Version: "1.34", Title: "On the path", Remediation: "Do a thing.", VerifyCommand: "kubectl get y"},
		{RuleID: "a-136", Version: "1.36", Title: "Beyond target", Remediation: "Do a thing."},
	}
}

func ids(t *testing.T, current, target string) []string {
	t.Helper()
	var out []string
	for _, f := range Analyze(current, target, "test-cluster", rules()) {
		out = append(out, f.RuleID)
	}
	return out
}

func TestWindowIsExclusiveAtTheBottom(t *testing.T) {
	got := ids(t, "1.33", "1.35")
	want := []string{"a-134"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("got %v, want %v", got, want)
	}
}

// A change that landed in the version the cluster already runs is not part of this upgrade.
// Reporting it buries the items that are.
func TestAdvisoryAtCurrentVersionDoesNotFire(t *testing.T) {
	for _, id := range ids(t, "1.33", "1.34") {
		if id == "a-133" {
			t.Fatal("an advisory at the current version must not fire")
		}
	}
}

func TestBeyondTargetDoesNotFire(t *testing.T) {
	for _, id := range ids(t, "1.33", "1.34") {
		if id == "a-136" {
			t.Fatal("an advisory past the target must not fire")
		}
	}
}

// Uncertainty widens the window rather than dropping findings.
func TestUnparseableCurrentWidensTheWindow(t *testing.T) {
	got := ids(t, "", "1.35")
	if len(got) != 3 {
		t.Errorf("expected every rule up to the target, got %v", got)
	}
}

func TestUnparseableTargetYieldsNothing(t *testing.T) {
	if got := Analyze("1.33", "not-a-version", "c", rules()); len(got) != 0 {
		t.Errorf("expected no findings for an unparseable target, got %d", len(got))
	}
}

func TestFindingShape(t *testing.T) {
	findings := Analyze("1.33", "1.34", "test-cluster", rules())
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(findings))
	}
	f := findings[0]
	if f.Severity != catalog.SeverityInfo || f.ScoreImpact != 0 {
		t.Errorf("advisories must be INFO with no score impact, got %s/%d", f.Severity, f.ScoreImpact)
	}
	if f.EnforcementLevel != "advisory" || f.ResourceType != "Cluster" || f.ResourceName != "test-cluster" {
		t.Errorf("unexpected finding shape: %+v", f)
	}
	if f.VerifyCommand != "kubectl get y" {
		t.Errorf("verify command not carried structurally: %q", f.VerifyCommand)
	}
	// The command must be readable in the prose too, for anyone reading the terminal rather
	// than parsing JSON.
	if !strings.Contains(f.Recommendation, "Check with: kubectl get y") {
		t.Errorf("verify command missing from recommendation: %q", f.Recommendation)
	}
	if !strings.Contains(f.Title, "[target 1.34]") {
		t.Errorf("title should name the target: %q", f.Title)
	}
}

func TestRealCatalogRuns(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	findings := Analyze("1.33", "1.35", "prod", cat.Advisories)
	for _, f := range findings {
		if f.ScoreImpact != 0 || f.Severity != catalog.SeverityInfo {
			t.Fatalf("catalog advisory %s is not INFO/0: %s/%d", f.RuleID, f.Severity, f.ScoreImpact)
		}
	}
	t.Logf("%d advisories on the 1.33 to 1.35 path", len(findings))
}
