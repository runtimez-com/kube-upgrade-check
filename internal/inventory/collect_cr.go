package inventory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/runtimez-com/kube-upgrade-check/internal/cluster"
)

// CollectorCustomResources is the collector name for add-on custom resources.
const CollectorCustomResources = "custom resources"

// CollectCustomResources reads instances of the kinds add-on catalogs ask about.
//
// Which kinds those are is decided by the catalog, not by this code, so a new add-on brings its
// own inventory needs with it. Kinds are resolved through discovery rather than guessed: the
// plural form of a custom kind is declared by whoever wrote the CRD and cannot be derived
// reliably from the kind name.
//
// A kind that could not be read is left ABSENT from the map. That distinction is the whole
// point: an add-on rule must decline on a kind it could not see, rather than report it clean.
func CollectCustomResources(ctx context.Context, c *cluster.Client, inv *Inventory, kinds []string) {
	wanted := map[string]bool{}
	for _, declared := range kinds {
		kind, _, _ := strings.Cut(declared, "@")
		// These come from the typed collectors, which have already run.
		switch kind {
		case "", "Ingress", "ConfigMap", "Secret":
			continue
		}
		wanted[kind] = true
	}
	if len(wanted) == 0 {
		return
	}
	// This is exported and takes any Inventory, including one a caller built themselves for a
	// recorded scan or a manifest directory. Writing into a nil map panics, and a scanner that
	// crashes on an unusual input is worse than one that reports nothing.
	if inv.CRs == nil {
		inv.CRs = map[string][]CustomResource{}
	}
	if inv.Collected == nil {
		inv.Collected = map[string]CollectionState{}
	}

	resources, err := c.ResourcesByKind()
	if err != nil {
		inv.Collected[CollectorCustomResources] = CollectionState{
			OK:     false,
			Reason: "the cluster's list of API resources could not be read, so add-on custom resources were not collected",
		}
		return
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		limiter  = make(chan struct{}, 4)
		failures []string
		read     int
	)

	for kind := range wanted {
		gvr, ok := resources[kind]
		if !ok {
			// The kind is not served here, which usually means the add-on is not installed.
			// Not an error, and not something to report: there is nothing to see.
			continue
		}
		wg.Add(1)
		go func(kind string, gvr schema.GroupVersionResource) {
			defer wg.Done()
			limiter <- struct{}{}
			defer func() { <-limiter }()

			rows, err := listCustomResources(ctx, c, kind, gvr)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				failures = append(failures, fmt.Sprintf("%s (%s)", kind, explain(err)))
				return
			}
			// Assigned even when empty: present-and-empty means read and found nothing, which
			// is a different fact from absent.
			inv.CRs[kind] = rows
			read++
		}(kind, gvr)
	}
	wg.Wait()

	sort.Strings(failures)
	switch {
	case len(failures) == 0:
		inv.Collected[CollectorCustomResources] = CollectionState{OK: true}
	case read == 0:
		inv.Collected[CollectorCustomResources] = CollectionState{
			OK:     false,
			Reason: "no add-on custom resources could be read: " + strings.Join(failures, ", "),
		}
	default:
		inv.Collected[CollectorCustomResources] = CollectionState{
			OK:      true,
			Partial: true,
			Reason:  "some add-on custom resources could not be read: " + strings.Join(failures, ", "),
		}
	}
}

func listCustomResources(ctx context.Context, c *cluster.Client, kind string, gvr schema.GroupVersionResource) ([]CustomResource, error) {
	var out []CustomResource
	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Dynamic.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			item := list.Items[i]
			cr := CustomResource{
				Kind:      kind,
				Namespace: item.GetNamespace(),
				Name:      item.GetName(),
				Labels:    item.GetLabels(),
			}
			// Annotation keys only. Values on these objects can carry arbitrary configuration,
			// and a finding is printed to a terminal and pasted into tickets.
			for key := range item.GetAnnotations() {
				cr.AnnotationKeys = append(cr.AnnotationKeys, key)
			}
			sort.Strings(cr.AnnotationKeys)
			if spec, ok := item.Object["spec"].(map[string]any); ok {
				cr.Spec = spec
			}
			out = append(out, cr)
		}
		return list.GetContinue(), nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
