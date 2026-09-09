package inventory

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/runtimez-com/kube-upgrade-check/internal/cluster"
)

// Collector names for the operational preflight reads.
const (
	CollectorPDBs        = "pod disruption budgets"
	CollectorWebhooks    = "admission webhooks"
	CollectorAPIServices = "aggregated API services"
)

// PDB is what a PodDisruptionBudget currently allows. A budget with no disruptions left and
// pods under it stops a drain until something changes.
type PDB struct {
	Namespace          string
	Name               string
	DisruptionsAllowed int32
	ExpectedPods       int32
	CurrentHealthy     int32
	DesiredHealthy     int32
}

// Webhook is one admission webhook and where it points.
type Webhook struct {
	Config        string // the configuration object's name
	Kind          string // ValidatingWebhookConfiguration | MutatingWebhookConfiguration
	Name          string // the webhook's own name within the configuration
	FailurePolicy string // Fail | Ignore; empty in the object means Fail
	Service       *ServiceRef
	URL           bool // an external URL, which nothing in the cluster can vouch for
	Backend       BackendState
}

// ServiceRef names a Service a webhook calls.
type ServiceRef struct {
	Namespace string
	Name      string
}

// BackendState is whether a Service has something ready behind it. Checked is false when the
// question could not be answered, which must never be read as either yes or no.
type BackendState struct {
	Checked bool
	Ready   bool
	Reason  string
}

// APIService is one aggregated API registration and whether the API server can reach it.
type APIService struct {
	Name      string
	Group     string
	Version   string
	Local     bool // served by the API server itself; nothing to reach
	Available bool
	Reason    string
	Service   *ServiceRef
}

var apiServiceGVR = schema.GroupVersionResource{
	Group: "apiregistration.k8s.io", Version: "v1", Resource: "apiservices",
}

// CollectPreflight reads the objects the operational preflight checks decide on: disruption
// budgets, admission webhooks, aggregated API services, and the CRD conversion webhooks the CRD
// collector already saw. It then asks, once per Service, whether anything ready stands behind
// each webhook, because a Fail-policy webhook with no backend blocks the API operations an
// upgrade needs.
func CollectPreflight(ctx context.Context, c *cluster.Client, inv *Inventory) {
	if inv.Collected == nil {
		inv.Collected = map[string]CollectionState{}
	}
	var mu sync.Mutex
	var wg sync.WaitGroup
	record := func(name string, err error) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			inv.Collected[name] = CollectionState{OK: false, Reason: explain(err), VerifyCommand: verifyFor(name)}
			return
		}
		inv.Collected[name] = CollectionState{OK: true}
	}

	wg.Add(3)
	go func() {
		defer wg.Done()
		pdbs, err := collectPDBs(ctx, c)
		mu.Lock()
		inv.PDBs = pdbs
		mu.Unlock()
		record(CollectorPDBs, err)
	}()
	go func() {
		defer wg.Done()
		hooks, err := collectWebhooks(ctx, c)
		mu.Lock()
		inv.Webhooks = hooks
		mu.Unlock()
		record(CollectorWebhooks, err)
	}()
	go func() {
		defer wg.Done()
		services, err := collectAPIServices(ctx, c)
		mu.Lock()
		inv.APIServices = services
		mu.Unlock()
		record(CollectorAPIServices, err)
	}()
	wg.Wait()

	// Conversion webhooks come from the CRD spec the CRD collector kept.
	for i := range inv.CRDs {
		inv.CRDs[i].Conversion = conversionOf(inv.CRDs[i].Spec)
	}

	// One readiness question per distinct Service, whoever asks it.
	backends := map[ServiceRef]BackendState{}
	ask := func(ref *ServiceRef) BackendState {
		if ref == nil {
			return BackendState{}
		}
		if state, ok := backends[*ref]; ok {
			return state
		}
		state := backendState(ctx, c, *ref)
		backends[*ref] = state
		return state
	}
	unchecked := 0
	for i := range inv.Webhooks {
		if inv.Webhooks[i].Service != nil {
			inv.Webhooks[i].Backend = ask(inv.Webhooks[i].Service)
			if !inv.Webhooks[i].Backend.Checked {
				unchecked++
			}
		}
	}
	for i := range inv.CRDs {
		if conv := inv.CRDs[i].Conversion; conv != nil && conv.Service != nil {
			conv.Backend = ask(conv.Service)
		}
	}
	if unchecked > 0 && inv.Read(CollectorWebhooks) {
		state := inv.Collected[CollectorWebhooks]
		state.Partial = true
		state.Reason = fmt.Sprintf("%d webhook backend(s) could not be checked for ready endpoints", unchecked)
		state.VerifyCommand = "kubectl get endpointslices -A -l kubernetes.io/service-name=<service>"
		inv.Collected[CollectorWebhooks] = state
	}
}

func verifyFor(collector string) string {
	switch collector {
	case CollectorPDBs:
		return "kubectl get pdb -A"
	case CollectorWebhooks:
		return "kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations"
	case CollectorAPIServices:
		return "kubectl get apiservices"
	}
	return ""
}

func collectPDBs(ctx context.Context, c *cluster.Client) ([]PDB, error) {
	var out []PDB
	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.PolicyV1().PodDisruptionBudgets(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for _, p := range list.Items {
			out = append(out, PDB{
				Namespace: p.Namespace, Name: p.Name,
				DisruptionsAllowed: p.Status.DisruptionsAllowed, ExpectedPods: p.Status.ExpectedPods,
				CurrentHealthy: p.Status.CurrentHealthy, DesiredHealthy: p.Status.DesiredHealthy,
			})
		}
		return list.Continue, nil
	})
	return out, err
}

func collectWebhooks(ctx context.Context, c *cluster.Client) ([]Webhook, error) {
	var out []Webhook
	admission := c.Clientset.AdmissionregistrationV1()
	validating, err := admission.ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, cfg := range validating.Items {
		for _, h := range cfg.Webhooks {
			w := Webhook{Config: cfg.Name, Kind: "ValidatingWebhookConfiguration", Name: h.Name, FailurePolicy: "Fail"}
			if h.FailurePolicy != nil {
				w.FailurePolicy = string(*h.FailurePolicy)
			}
			if h.ClientConfig.Service != nil {
				w.Service = &ServiceRef{Namespace: h.ClientConfig.Service.Namespace, Name: h.ClientConfig.Service.Name}
			} else if h.ClientConfig.URL != nil {
				w.URL = true
			}
			out = append(out, w)
		}
	}
	mutating, err := admission.MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}
	for _, cfg := range mutating.Items {
		for _, h := range cfg.Webhooks {
			w := Webhook{Config: cfg.Name, Kind: "MutatingWebhookConfiguration", Name: h.Name, FailurePolicy: "Fail"}
			if h.FailurePolicy != nil {
				w.FailurePolicy = string(*h.FailurePolicy)
			}
			if h.ClientConfig.Service != nil {
				w.Service = &ServiceRef{Namespace: h.ClientConfig.Service.Namespace, Name: h.ClientConfig.Service.Name}
			} else if h.ClientConfig.URL != nil {
				w.URL = true
			}
			out = append(out, w)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Config != out[j].Config {
			return out[i].Config < out[j].Config
		}
		return out[i].Name < out[j].Name
	})
	return out, nil
}

// collectAPIServices reads apiregistration.k8s.io through the dynamic client: the typed
// aggregator client is a separate module, and the three fields read here do not justify it.
func collectAPIServices(ctx context.Context, c *cluster.Client) ([]APIService, error) {
	var out []APIService
	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Dynamic.Resource(apiServiceGVR).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			obj := list.Items[i].Object
			spec, _ := obj["spec"].(map[string]any)
			status, _ := obj["status"].(map[string]any)
			s := APIService{Name: list.Items[i].GetName()}
			s.Group, _ = spec["group"].(string)
			s.Version, _ = spec["version"].(string)
			if svc, ok := spec["service"].(map[string]any); ok && svc != nil {
				ns, _ := svc["namespace"].(string)
				name, _ := svc["name"].(string)
				s.Service = &ServiceRef{Namespace: ns, Name: name}
			} else {
				s.Local = true
			}
			s.Available, s.Reason = conditionOf(status, "Available")
			out = append(out, s)
		}
		return list.GetContinue(), nil
	})
	return out, err
}

// conditionOf reads one condition from an unstructured status. Absent reads as not met, with
// a reason that says so rather than an empty string that looks like a clean bill.
func conditionOf(status map[string]any, condType string) (bool, string) {
	conditions, _ := status["conditions"].([]any)
	for _, raw := range conditions {
		cond, _ := raw.(map[string]any)
		if t, _ := cond["type"].(string); t != condType {
			continue
		}
		st, _ := cond["status"].(string)
		reason, _ := cond["reason"].(string)
		msg, _ := cond["message"].(string)
		text := strings.TrimSpace(strings.Join([]string{reason, msg}, ": "))
		return st == "True", strings.Trim(text, ": ")
	}
	return false, "no " + condType + " condition reported"
}

// Conversion is a CRD's webhook conversion, if it uses one.
type Conversion struct {
	Strategy string
	Service  *ServiceRef
	Backend  BackendState
}

func conversionOf(spec map[string]any) *Conversion {
	conv, _ := spec["conversion"].(map[string]any)
	if conv == nil {
		return nil
	}
	strategy, _ := conv["strategy"].(string)
	out := &Conversion{Strategy: strategy}
	if strategy != "Webhook" {
		return out
	}
	webhook, _ := conv["webhook"].(map[string]any)
	client, _ := webhook["clientConfig"].(map[string]any)
	if svc, ok := client["service"].(map[string]any); ok && svc != nil {
		ns, _ := svc["namespace"].(string)
		name, _ := svc["name"].(string)
		out.Service = &ServiceRef{Namespace: ns, Name: name}
	}
	return out
}

// backendState asks whether a Service exists and has a ready endpoint. EndpointSlices are
// read by the service-name label, so this is one small list per Service, not a cluster-wide
// one. An endpoint whose ready condition is unset counts as ready, which is what the API
// documents for that field.
func backendState(ctx context.Context, c *cluster.Client, ref ServiceRef) BackendState {
	if _, err := c.Clientset.CoreV1().Services(ref.Namespace).Get(ctx, ref.Name, metav1.GetOptions{}); err != nil {
		if apierrors.IsNotFound(err) {
			return BackendState{Checked: true, Ready: false, Reason: "Service " + ref.Namespace + "/" + ref.Name + " does not exist"}
		}
		return BackendState{Checked: false, Reason: "Service " + ref.Namespace + "/" + ref.Name + ": " + explain(err)}
	}
	slices, err := c.Clientset.DiscoveryV1().EndpointSlices(ref.Namespace).List(ctx, metav1.ListOptions{
		LabelSelector: "kubernetes.io/service-name=" + ref.Name,
	})
	if err != nil {
		return BackendState{Checked: false, Reason: "EndpointSlices for " + ref.Namespace + "/" + ref.Name + ": " + explain(err)}
	}
	total := 0
	for _, slice := range slices.Items {
		for _, ep := range slice.Endpoints {
			total++
			if ep.Conditions.Ready == nil || *ep.Conditions.Ready {
				return BackendState{Checked: true, Ready: true}
			}
		}
	}
	if total == 0 {
		return BackendState{Checked: true, Ready: false, Reason: "Service " + ref.Namespace + "/" + ref.Name + " has no endpoints"}
	}
	return BackendState{Checked: true, Ready: false, Reason: fmt.Sprintf("Service %s/%s has %d endpoint(s), none ready", ref.Namespace, ref.Name, total)}
}
