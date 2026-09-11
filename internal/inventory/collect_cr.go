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

// Collector names for the two dynamic-client collectors.
const (
	// CollectorCustomResources is the collector name for add-on custom resources.
	CollectorCustomResources = "custom resources"
	// CollectorRuleObjects is the collector name for the objects release-note rules read.
	CollectorRuleObjects = "rule objects"
)

// Projection limits what is kept from each object of a kind.
//
// Keep names the top-level keys of spec and status to retain. A nil *Projection keeps the whole
// spec, which is the add-on convention and fine for a handful of custom resources. A cluster-wide
// list of Pods or Services with everything kept would be a copy of the cluster in memory, and
// the rules that read those kinds ask about one or two fields.
type Projection struct {
	Keep []string
}

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
	wanted := map[string]*Projection{}
	for _, declared := range kinds {
		kind, _, _ := strings.Cut(declared, "@")
		// These come from the typed collectors, which have already run.
		switch kind {
		case "", "Ingress", "ConfigMap", "Secret":
			continue
		}
		wanted[kind] = nil
	}
	collectByKind(ctx, c, inv, wanted, CollectorCustomResources, "add-on custom resources")
}

// CollectRuleObjects reads the objects release-note rules decide on, keeping only the fields
// those rules read. A kind already collected in full by the add-on collector is not read twice.
func CollectRuleObjects(ctx context.Context, c *cluster.Client, inv *Inventory, wants map[string]Projection) {
	wanted := map[string]*Projection{}
	for kind, projection := range wants {
		// Nodes and CRDs come from the typed collectors, which keep more than a raw list would.
		if kind == "" || kind == "Node" || kind == "CustomResourceDefinition" {
			continue
		}
		if inv.CRs != nil {
			if _, done := inv.CRs[kind]; done {
				continue
			}
		}
		p := projection
		wanted[kind] = &p
	}
	collectByKind(ctx, c, inv, wanted, CollectorRuleObjects, "objects for release-note rules")
}

func collectByKind(ctx context.Context, c *cluster.Client, inv *Inventory, wanted map[string]*Projection, collector, what string) {
	if len(wanted) == 0 {
		return
	}
	// This is exported and takes any Inventory, including one a caller built themselves for a
	// recorded scan or a manifest directory. Writing into a nil map panics, and a scanner that
	// crashes on an unusual input is worse than one that reports nothing.
	if inv.CRs == nil {
		inv.CRs = map[string][]CustomResource{}
	}
	if inv.CRUnread == nil {
		inv.CRUnread = map[string]string{}
	}
	if inv.CRNotServed == nil {
		inv.CRNotServed = map[string]bool{}
	}
	if inv.Collected == nil {
		inv.Collected = map[string]CollectionState{}
	}

	resources, err := c.ResourcesByKind()
	if err != nil {
		reason := "the cluster's list of API resources could not be read, so " + what + " were not collected"
		for kind := range wanted {
			inv.CRUnread[kind] = reason
		}
		inv.Collected[collector] = CollectionState{OK: false, Reason: reason}
		return
	}

	var (
		mu       sync.Mutex
		wg       sync.WaitGroup
		limiter  = make(chan struct{}, 4)
		failures []string
		read     int
	)
	for kind, projection := range wanted {
		gvr, ok := resources[kind]
		if !ok {
			// The kind is not served here, which usually means the add-on is not installed or
			// the API has not reached this cluster's version. Not an error, and not a gap: there
			// is nothing to see. Recorded so a rule can tell this apart from a failed read.
			inv.CRNotServed[kind] = true
			continue
		}
		wg.Add(1)
		go func(kind string, gvr schema.GroupVersionResource, projection *Projection) {
			defer wg.Done()
			limiter <- struct{}{}
			defer func() { <-limiter }()
			rows, err := listCustomResources(ctx, c, kind, gvr, projection)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				inv.CRUnread[kind] = explain(err)
				failures = append(failures, fmt.Sprintf("%s (%s)", kind, explain(err)))
				return
			}
			// Assigned even when empty: present-and-empty means read and found nothing, which
			// is a different fact from absent.
			inv.CRs[kind] = rows
			read++
		}(kind, gvr, projection)
	}
	wg.Wait()

	sort.Strings(failures)
	switch {
	case len(failures) == 0:
		inv.Collected[collector] = CollectionState{OK: true}
	case read == 0:
		inv.Collected[collector] = CollectionState{
			OK:     false,
			Reason: "no " + what + " could be read: " + strings.Join(failures, ", "),
		}
	default:
		inv.Collected[collector] = CollectionState{
			OK:      true,
			Partial: true,
			Reason:  "some " + what + " could not be read: " + strings.Join(failures, ", "),
		}
	}
}

func listCustomResources(ctx context.Context, c *cluster.Client, kind string, gvr schema.GroupVersionResource, projection *Projection) ([]CustomResource, error) {
	var out []CustomResource
	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Dynamic.Resource(gvr).Namespace(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			item := list.Items[i]
			cr := CustomResource{
				Kind:       kind,
				Namespace:  item.GetNamespace(),
				Name:       item.GetName(),
				Labels:     item.GetLabels(),
				APIVersion: item.GetAPIVersion(),
			}
			// Annotation keys only. Values on these objects can carry arbitrary configuration,
			// and a finding is printed to a terminal and pasted into tickets.
			for key := range item.GetAnnotations() {
				cr.AnnotationKeys = append(cr.AnnotationKeys, key)
			}
			sort.Strings(cr.AnnotationKeys)
			seenVersion, seenManager := map[string]bool{}, map[string]bool{}
			for _, entry := range item.GetManagedFields() {
				if entry.APIVersion != "" && !seenVersion[entry.APIVersion] {
					seenVersion[entry.APIVersion] = true
					cr.WrittenAt = append(cr.WrittenAt, entry.APIVersion)
				}
				if entry.Manager != "" && !seenManager[entry.Manager] {
					seenManager[entry.Manager] = true
					cr.Managers = append(cr.Managers, entry.Manager)
				}
			}
			sort.Strings(cr.WrittenAt)
			sort.Strings(cr.Managers)
			// Kinds the rules read through a derived view (a workload's pod template, a
			// ConfigMap's key names, an issuer's configured blocks) are projected the way the
			// hosted product's agent projects them; the rest keep the raw keys asked for.
			cr.Spec = projectSpec(kind, item.Object, projection)
			if status, ok := item.Object["status"].(map[string]any); ok {
				cr.Status = project(status, projection)
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

// project keeps the whole map when there is no projection, and only the named top-level keys
// otherwise. The result is never nil for a non-nil input, so "read and found nothing at those
// keys" stays distinguishable from "the object has no such section".
func project(m map[string]any, projection *Projection) map[string]any {
	if projection == nil {
		return m
	}
	out := make(map[string]any, len(projection.Keep))
	for _, key := range projection.Keep {
		if v, ok := m[key]; ok {
			out[key] = v
		}
	}
	return out
}
