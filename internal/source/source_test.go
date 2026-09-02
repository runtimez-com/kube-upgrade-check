package source

import (
	"strings"
	"testing"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func object(namespace, name string, managed []metav1.ManagedFieldsEntry, annotations map[string]string) *metav1.PartialObjectMetadata {
	return &metav1.PartialObjectMetadata{ObjectMeta: metav1.ObjectMeta{
		Namespace: namespace, Name: name, ManagedFields: managed, Annotations: annotations,
	}}
}

func at(day string) *metav1.Time {
	d, err := time.Parse("2006-01-02", day)
	if err != nil {
		panic(err)
	}
	t := metav1.NewTime(d)
	return &t
}

func ingressTarget() target {
	return target{
		kind:            "Ingress",
		removedVersions: map[string]bool{"extensions/v1beta1": true},
		replacement:     "networking.k8s.io/v1",
	}
}

// The strongest evidence available: a named client wrote these fields at a removed version and
// nothing has rewritten them since.
func TestManagedFieldsNamesTheWriterAndTheDate(t *testing.T) {
	obj := object("shop", "web", []metav1.ManagedFieldsEntry{
		{Manager: "helm", Operation: metav1.ManagedFieldsOperationUpdate,
			APIVersion: "extensions/v1beta1", Time: at("2024-03-02")},
	}, nil)

	got := fromManagedFields(obj, ingressTarget())
	if len(got) != 1 {
		t.Fatalf("expected one usage, got %d", len(got))
	}
	if got[0].Manager != "helm" || got[0].ObservedAt != "2024-03-02" {
		t.Errorf("writer and date must be carried: %+v", got[0])
	}
	if got[0].Stale {
		t.Error("with no newer write this is not stale")
	}
	if !strings.Contains(got[0].Evidence, "helm") {
		t.Errorf("evidence should name the writer: %q", got[0].Evidence)
	}
}

// A later write at the current version means the object has been rewritten and the old entry is
// a leftover. Still reported, but as a weaker claim.
func TestNewerWriteAtTheCurrentVersionMarksEvidenceStale(t *testing.T) {
	obj := object("shop", "web", []metav1.ManagedFieldsEntry{
		{Manager: "helm", APIVersion: "extensions/v1beta1", Time: at("2024-03-02")},
		{Manager: "helm", APIVersion: "networking.k8s.io/v1", Time: at("2025-06-01")},
	}, nil)

	got := fromManagedFields(obj, ingressTarget())
	if len(got) != 1 || !got[0].Stale {
		t.Errorf("a later write at the current version should mark the old entry stale: %+v", got)
	}
}

func TestManagedFieldsIgnoresCurrentVersions(t *testing.T) {
	obj := object("shop", "web", []metav1.ManagedFieldsEntry{
		{Manager: "kubectl", APIVersion: "networking.k8s.io/v1", Time: at("2025-06-01")},
	}, nil)
	if got := fromManagedFields(obj, ingressTarget()); len(got) != 0 {
		t.Errorf("an object written at the current version is not evidence: %+v", got)
	}
}

func TestLastAppliedReadsTheSubmittedVersion(t *testing.T) {
	obj := object("shop", "web", nil, map[string]string{
		"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"extensions/v1beta1","kind":"Ingress"}`,
	})
	got := fromLastApplied(obj, ingressTarget())
	if len(got) != 1 || got[0].APIVersion != "extensions/v1beta1" || got[0].Tier != TierLastApplied {
		t.Errorf("unexpected usage: %+v", got)
	}

	current := object("shop", "web", nil, map[string]string{
		"kubectl.kubernetes.io/last-applied-configuration": `{"apiVersion":"networking.k8s.io/v1","kind":"Ingress"}`,
	})
	if got := fromLastApplied(current, ingressTarget()); len(got) != 0 {
		t.Errorf("a current version in the annotation is not evidence: %+v", got)
	}
	if got := fromLastApplied(object("shop", "web", nil, nil), ingressTarget()); len(got) != 0 {
		t.Errorf("no annotation means no evidence: %+v", got)
	}
}

func TestAPIVersionOf(t *testing.T) {
	cases := map[string]string{
		`{"apiVersion":"apps/v1","kind":"Deployment"}`: "apps/v1",
		`{"kind":"Deployment","apiVersion":"apps/v1"}`: "apps/v1",
		`{"apiVersion": "apps/v1"}`:                    "apps/v1",
		`{"kind":"Deployment"}`:                        "",
		`not json at all`:                              "",
	}
	for manifest, want := range cases {
		if got := apiVersionOf(manifest); got != want {
			t.Errorf("apiVersionOf(%q) = %q, want %q", manifest, got, want)
		}
	}
}

// The metric labels name the lowercase plural; the catalog is keyed by kind. Getting this wrong
// made the whole tier dead while it reported itself complete.
func TestMetricLabels(t *testing.T) {
	line := `apiserver_requested_deprecated_apis{group="networking.k8s.io",removed_release="1.22",` +
		`resource="ingresses",subresource="",version="v1beta1"} 1`
	group, version, resource := metricLabels(line)
	if group != "networking.k8s.io" || version != "v1beta1" || resource != "ingresses" {
		t.Errorf("got group=%q version=%q resource=%q", group, version, resource)
	}

	if g, v, r := metricLabels("apiserver_requested_deprecated_apis 1"); g != "" || v != "" || r != "" {
		t.Errorf("a line with no labels must yield nothing, got %q %q %q", g, v, r)
	}
}

// Rows the object tier could not scan must leave a trace, folded by reason so one cause does not
// print a line per rule.
func TestUnscannableCoverageGroupsByReason(t *testing.T) {
	got := unscannableCoverage([]unscannableRule{
		{kind: "PodSecurityPolicy", apiVersion: "policy/v1beta1", reason: "not served"},
		{kind: "PodSchedulingContext", apiVersion: "resource.k8s.io/v1alpha2", reason: "not served"},
		{kind: "TokenReview", apiVersion: "authentication.k8s.io/v1beta1", reason: "not listable"},
	})
	if len(got) != 2 {
		t.Fatalf("expected two groups, got %d: %+v", len(got), got)
	}
	for _, c := range got {
		if c.State != report.CoverageUnavailable || c.RulesSkipped == 0 {
			t.Errorf("each group must be an unavailable row with a count: %+v", c)
		}
	}
	if unscannableCoverage(nil) != nil {
		t.Error("no unscannable rules means no rows")
	}
}

func TestResourceForHandlesIrregularPlurals(t *testing.T) {
	cases := map[string]string{
		"Deployment":        "deployments",
		"Ingress":           "ingresses",
		"NetworkPolicy":     "networkpolicies",
		"PodSecurityPolicy": "podsecuritypolicies",
		"FlowSchema":        "flowschemas",
	}
	for kind, want := range cases {
		if got := resourceFor(kind); got != want {
			t.Errorf("resourceFor(%q) = %q, want %q", kind, got, want)
		}
	}
}
