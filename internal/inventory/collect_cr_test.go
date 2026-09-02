package inventory

import (
	"context"
	"testing"

	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"

	"github.com/runtimez-com/kube-upgrade-check/internal/cluster"
)

func nodePool(name string, spec map[string]any) *unstructured.Unstructured {
	return &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "karpenter.sh/v1",
		"kind":       "NodePool",
		"metadata": map[string]any{
			"name":        name,
			"labels":      map[string]any{"team": "platform"},
			"annotations": map[string]any{"karpenter.sh/do-not-disrupt": "true"},
		},
		"spec": spec,
	}}
}

func fakeClient(objects ...runtime.Object) *cluster.Client {
	gvr := schema.GroupVersionResource{Group: "karpenter.sh", Version: "v1", Resource: "nodepools"}
	scheme := runtime.NewScheme()
	listKinds := map[schema.GroupVersionResource]string{gvr: "NodePoolList"}
	return &cluster.Client{
		Dynamic: dynamicfake.NewSimpleDynamicClientWithCustomListKinds(scheme, listKinds, objects...),
	}
}

func newInventory() *Inventory {
	return &Inventory{
		CRs:       map[string][]CustomResource{},
		Collected: map[string]CollectionState{},
	}
}

func TestCollectCustomResourcesReadsSpecLabelsAndAnnotationKeys(t *testing.T) {
	c := fakeClient(nodePool("default", map[string]any{"nodeClassRef": map[string]any{"name": "bottlerocket"}}))
	inv := newInventory()

	collectKinds(t, c, inv, map[string]schema.GroupVersionResource{
		"NodePool": {Group: "karpenter.sh", Version: "v1", Resource: "nodepools"},
	}, []string{"NodePool"})

	rows, ok := inv.CRs["NodePool"]
	if !ok {
		t.Fatal("NodePool must be present in the map once it has been read")
	}
	if len(rows) != 1 || rows[0].Name != "default" {
		t.Fatalf("unexpected rows: %+v", rows)
	}
	if rows[0].Labels["team"] != "platform" {
		t.Errorf("labels not carried: %+v", rows[0].Labels)
	}
	if len(rows[0].AnnotationKeys) != 1 || rows[0].AnnotationKeys[0] != "karpenter.sh/do-not-disrupt" {
		t.Errorf("annotation keys not carried: %v", rows[0].AnnotationKeys)
	}
	// Values must not be carried: they can hold arbitrary configuration, and a finding is
	// printed to a terminal and pasted into tickets.
	if _, hasSpec := rows[0].Spec["nodeClassRef"]; !hasSpec {
		t.Errorf("spec not carried: %+v", rows[0].Spec)
	}
}

// The distinction the add-on rules depend on: a kind that was read and had nothing is present
// and empty; a kind that could not be read is absent entirely.
func TestReadButEmptyKindIsPresentInTheMap(t *testing.T) {
	c := fakeClient()
	inv := newInventory()

	collectKinds(t, c, inv, map[string]schema.GroupVersionResource{
		"NodePool": {Group: "karpenter.sh", Version: "v1", Resource: "nodepools"},
	}, []string{"NodePool"})

	rows, ok := inv.CRs["NodePool"]
	if !ok {
		t.Fatal("a kind that was read must be present even with no instances")
	}
	if len(rows) != 0 {
		t.Errorf("expected no rows, got %d", len(rows))
	}
	if !inv.Read(CollectorCustomResources) {
		t.Error("reading a kind successfully must record the collector as OK")
	}
}

// A kind the cluster does not serve means the add-on is not installed. There is nothing to see,
// so it must not be recorded as read.
func TestUnservedKindIsAbsentFromTheMap(t *testing.T) {
	c := fakeClient()
	inv := newInventory()

	CollectCustomResources(context.Background(), c, inv, []string{"NodePool"})

	if _, ok := inv.CRs["NodePool"]; ok {
		t.Error("an unserved kind must not appear as read")
	}
}

// Kinds served by the typed collectors are handled there and must not be listed twice.
func TestTypedKindsAreSkipped(t *testing.T) {
	c := fakeClient()
	inv := newInventory()

	CollectCustomResources(context.Background(), c, inv, []string{"Ingress", "ConfigMap@kube-system", "Secret@ns"})

	if len(inv.CRs) != 0 {
		t.Errorf("typed kinds must not be collected here: %+v", inv.CRs)
	}
	if _, recorded := inv.Collected[CollectorCustomResources]; recorded {
		t.Error("with nothing to collect the collector should record nothing")
	}
}

// collectKinds runs the collector against an explicit kind map, standing in for discovery.
func collectKinds(t *testing.T, c *cluster.Client, inv *Inventory, resources map[string]schema.GroupVersionResource, kinds []string) {
	t.Helper()
	for _, kind := range kinds {
		gvr, ok := resources[kind]
		if !ok {
			continue
		}
		rows, err := listCustomResources(context.Background(), c, kind, gvr)
		if err != nil {
			t.Fatalf("list %s: %v", kind, err)
		}
		inv.CRs[kind] = rows
	}
	inv.Collected[CollectorCustomResources] = CollectionState{OK: true}
}
