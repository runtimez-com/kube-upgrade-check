package render

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func sample() report.Result {
	return report.Result{
		Cluster: "prod-eu", Provider: "EKS", CurrentVersion: "v1.33.13-eks-a1b2",
		TargetVersion: "1.34", NodeCount: 1, Score: 61, RiskLevel: "HIGH",
		Support: report.Support{
			StandardSupportEnd: "2026-11-23", VendorManaged: true, DataSourced: true,
			CostWarning: "EKS extended support is about $0.60 per cluster per hour",
		},
		Findings: []report.Finding{
			{
				RuleID: "rtz-addon-ingress-nginx-support", Title: "Ingress-NGINX v1.13.3 does not support Kubernetes 1.34",
				Severity: catalog.SeverityHigh, ScoreImpact: 20, ResourceName: "DaemonSet/ingress/controller",
				Evidence: []string{"Detected Ingress-NGINX v1.13.3 from DaemonSet/ingress/controller"},
			},
			{
				RuleID: "rtz-k8s-advisory-metric-rename", Title: "Metric labels were renamed",
				Severity: catalog.SeverityInfo, EnforcementLevel: "advisory",
				VerifyCommand: "kubectl get prometheusrules -A",
			},
			{
				RuleID: "rtz-k8s-config-controlplane-not-assessed", Title: "Control-plane flag checks could not run",
				Severity: catalog.SeverityInfo, EnforcementLevel: "advisory",
			},
		},
		Coverage: []report.Coverage{
			{Source: "removed APIs", Scope: "Ingress", State: report.CoverageComplete},
			{Source: "control-plane flags", State: report.CoverageUnavailable,
				Reason: "no static control-plane pods were found", RulesSkipped: 276,
				VerifyCommand: "kubectl get pods -n kube-system -l tier=control-plane"},
		},
		ScanStatus: report.ScanPartial, CheckedAt: time.Now().UTC(),
	}
}

func renderWith(t *testing.T, format Format, r report.Result) string {
	t.Helper()
	var buf bytes.Buffer
	if err := (&Printer{Out: &buf, Format: format}).Print(r); err != nil {
		t.Fatal(err)
	}
	return buf.String()
}

// The headline must answer "what is wrong", not "what did you see".
func TestBreakLeadsWithTheProblem(t *testing.T) {
	out := renderWith(t, FormatTable, sample())
	if !strings.Contains(out, "does not support Kubernetes 1.34") {
		t.Errorf("the break should state the problem:\n%s", out)
	}
	// The raw observation is supporting detail, never the headline.
	if strings.Contains(firstLineAfter(out, "HIGH"), "Detected") {
		t.Errorf("the break line should not lead with raw observation:\n%s", out)
	}
	// The rule id has to be present so it can be looked up or suppressed.
	if !strings.Contains(out, "rtz-addon-ingress-nginx-support") {
		t.Errorf("the rule id must appear:\n%s", out)
	}
}

// A coverage gap belongs in one place, with its reason and its check command.
func TestCoverageGapsAreNotAlsoListedAsAdvisories(t *testing.T) {
	out := renderWith(t, FormatTable, sample())
	if strings.Count(out, "rtz-k8s-config-controlplane-not-assessed") != 0 {
		t.Errorf("a not-assessed finding must not appear in the finding lists:\n%s", out)
	}
	if !strings.Contains(out, "276 rules not checked") {
		t.Errorf("the gap must be reported with its rule count:\n%s", out)
	}
	if !strings.Contains(out, "kubectl get pods") {
		t.Errorf("the gap must tell the reader how to check it:\n%s", out)
	}
}

// The most dangerous output this tool can produce is an empty break list that reads as a clean
// bill of health when half the checks never ran.
func TestEmptyBreakListWarnsWhenCoverageIsIncomplete(t *testing.T) {
	r := sample()
	r.Findings = nil
	out := renderWith(t, FormatTable, r)
	if !strings.Contains(out, "Nothing found that this upgrade breaks") {
		t.Fatalf("expected an empty break section:\n%s", out)
	}
	if !strings.Contains(out, "Some checks could not run") {
		t.Errorf("an incomplete scan must qualify an empty result:\n%s", out)
	}

	r.ScanStatus = report.ScanComplete
	r.Coverage = []report.Coverage{{Source: "removed APIs", State: report.CoverageComplete}}
	out = renderWith(t, FormatTable, r)
	if strings.Contains(out, "Some checks could not run") {
		t.Errorf("a complete scan must not add the qualifier:\n%s", out)
	}
}

func TestAddonVerdictsReadAsSentences(t *testing.T) {
	cases := map[string]string{
		"SUPPORTED":              "supported",
		"ABOVE_MAX":              "does not support the target",
		"NO_VENDOR_DATA":         "publishes no compatibility matrix",
		"VERSION_UNRESOLVED":     "could not be determined",
		"VERSION_NOT_IN_CATALOG": "not in the vendor's table",
	}
	for verdict, want := range cases {
		got := addonVerdict(report.AddonStatus{Verdict: verdict, MaxK8s: "1.33"})
		if !strings.Contains(got, want) {
			t.Errorf("%s rendered as %q, want it to contain %q", verdict, got, want)
		}
	}
}

// Both machine formats must name fields identically, or one scan produces two vocabularies.
func TestJSONAndYAMLAgreeOnFieldNames(t *testing.T) {
	jsonOut := renderWith(t, FormatJSON, sample())
	yamlOut := renderWith(t, FormatYAML, sample())

	var decoded map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v", err)
	}
	for _, key := range []string{"currentVersion", "targetVersion", "scanStatus", "riskLevel", "findingCountsBySeverity"} {
		if _, ok := decoded[key]; !ok {
			t.Errorf("JSON is missing %q", key)
		}
		if !strings.Contains(yamlOut, key+":") {
			t.Errorf("YAML is missing %q", key)
		}
	}
}

// Machine output carries no decoration; a pipeline parses it.
func TestStructuredOutputIsPureData(t *testing.T) {
	out := renderWith(t, FormatJSON, sample())
	if strings.Contains(out, productLink) {
		t.Error("the product link must not appear in machine-readable output")
	}
	if strings.Contains(out, "COULD NOT SEE") {
		t.Error("section headings must not appear in machine-readable output")
	}
}

func TestParseFormat(t *testing.T) {
	for _, ok := range []string{"", "table", "wide", "json", "yaml", "JSON"} {
		if _, err := ParseFormat(ok); err != nil {
			t.Errorf("ParseFormat(%q) failed: %v", ok, err)
		}
	}
	if _, err := ParseFormat("toml"); err == nil {
		t.Error("an unknown format must be rejected")
	}
}

func TestPluralize(t *testing.T) {
	if got := pluralize(1, "node"); got != "1 node" {
		t.Errorf("got %q", got)
	}
	if got := pluralize(3, "node"); got != "3 nodes" {
		t.Errorf("got %q", got)
	}
}

func lineContaining(out, needle string) string {
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, needle) {
			return line
		}
	}
	return ""
}

func firstLineAfter(out, needle string) string {
	lines := strings.Split(out, "\n")
	for i, line := range lines {
		if strings.Contains(line, needle) && i+1 < len(lines) {
			return line
		}
	}
	return ""
}

// A restricted account produces the same denial for many resource types. Thirty near-identical
// lines bury the gaps that are specific, and make one permission problem look like thirty.
func TestRepeatedGapsAreGroupedByReason(t *testing.T) {
	r := sample()
	r.Coverage = []report.Coverage{
		{Source: "removed APIs", Scope: "Lease", State: report.CoverageUnavailable,
			Reason:        "listing this resource type is not permitted for this account",
			VerifyCommand: "kubectl get lease -A"},
		{Source: "removed APIs", Scope: "CSINode", State: report.CoverageUnavailable,
			Reason:        "listing this resource type is not permitted for this account",
			VerifyCommand: "kubectl get csinode -A"},
		{Source: "removed APIs", Scope: "Role", State: report.CoverageUnavailable,
			Reason:        "listing this resource type is not permitted for this account",
			VerifyCommand: "kubectl get role -A"},
		{Source: "kubelet configuration", State: report.CoverageUnavailable,
			Reason: "no node's kubelet configuration could be read", RulesSkipped: 93,
			VerifyCommand: "kubectl get --raw /api/v1/nodes/<node>/proxy/configz"},
	}
	out := renderWith(t, FormatTable, r)

	if !strings.Contains(out, "COULD NOT SEE (2)") {
		t.Errorf("three identical denials plus one other should group into two entries:\n%s", out)
	}
	// The affected types must still be named, or grouping would hide what was skipped.
	if !strings.Contains(out, "affects: CSINode, Lease, Role") {
		t.Errorf("grouped scopes must be listed and sorted:\n%s", out)
	}
	// A gap with one member keeps its command, because that command is still exactly right.
	if !strings.Contains(out, "kubectl get --raw") {
		t.Errorf("a single-scope gap must keep its check command:\n%s", out)
	}
	if strings.Contains(out, "kubectl get lease -A") {
		t.Errorf("one of many per-scope commands must not be presented as the fix:\n%s", out)
	}
}

// Rule counts have to survive grouping, or a report understates what went unchecked.
func TestGroupingSumsSkippedRuleCounts(t *testing.T) {
	gaps := groupGaps([]report.Coverage{
		{Source: "control-plane flags", Reason: "no static pods", RulesSkipped: 200},
		{Source: "control-plane flags", Reason: "no static pods", RulesSkipped: 76},
	})
	if len(gaps) != 1 {
		t.Fatalf("expected one group, got %d", len(gaps))
	}
	if gaps[0].rulesSkipped != 276 {
		t.Errorf("skipped counts must add up, got %d", gaps[0].rulesSkipped)
	}
}

// A vendor who publishes nothing and an add-on we know is too old are different facts, and the
// marker has to say which. One alarm for both overstates what we know.
func TestAddonMarkerSeparatesUnknownFromBroken(t *testing.T) {
	st := style{color: false, width: defaultWidth}
	cases := map[string]string{
		"SUPPORTED":              "ok",
		"ABOVE_MAX":              "!!",
		"BELOW_MIN":              "!!",
		"NO_VENDOR_DATA":         "??",
		"VERSION_UNRESOLVED":     "??",
		"VERSION_NOT_IN_CATALOG": "??",
	}
	for verdict, want := range cases {
		if got := addonMarker(st, verdict); got != want {
			t.Errorf("%s marked %q, want %q", verdict, got, want)
		}
	}
}
