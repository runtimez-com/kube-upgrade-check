package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	"github.com/runtimez-com/kube-upgrade-check/internal/cluster"
)

// Collector names, used as the keys of Inventory.Collected and as the source names on
// coverage rows. They are exported because the report prints them back to the reader.
const (
	CollectorNodes            = "nodes"
	CollectorKubeletConfig    = "kubelet config"
	CollectorControlPlanePods = "control-plane flags"
	CollectorWorkloads        = "workloads"
	CollectorPods             = "standalone pods"
	CollectorStorage          = "storage"
	CollectorCRDs             = "custom resource definitions"
	CollectorIngresses        = "ingresses"
	CollectorConfigMaps       = "kube-system config maps"
)

// listPageSize bounds one API page. Large enough that a normal cluster is one or two
// requests, small enough that a huge one does not build a single enormous response.
const listPageSize = 500

// Collect reads everything the evaluators need, in parallel, and never fails as a whole.
//
// A collector that cannot run records why and leaves its slice empty. That distinction is the
// point of this package: an empty slice with a recorded failure means "we could not look",
// and an empty slice without one means "we looked and there was nothing". Callers must ask
// Read() before drawing a conclusion from emptiness.
func Collect(ctx context.Context, c *cluster.Client, info cluster.ServerInfo) *Inventory {
	inv := &Inventory{
		ClusterName:   c.ContextName,
		Provider:      info.Provider,
		ServerVersion: info.GitVersion,
		CRs:           map[string][]CustomResource{},
		Collected:     map[string]CollectionState{},
	}

	var mu sync.Mutex
	record := func(name string, err error, partial bool) {
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			inv.Collected[name] = CollectionState{OK: false, Reason: explain(err)}
			return
		}
		inv.Collected[name] = CollectionState{OK: true, Partial: partial}
	}

	var wg sync.WaitGroup
	run := func(name string, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := fn()
			record(name, err, false)
		}()
	}

	run(CollectorNodes, func() error {
		nodes, err := collectNodes(ctx, c)
		if err != nil {
			return err
		}
		mu.Lock()
		inv.Nodes = nodes
		mu.Unlock()
		return nil
	})

	run(CollectorWorkloads, func() error {
		workloads, err := collectWorkloads(ctx, c)
		if err != nil {
			return err
		}
		mu.Lock()
		inv.Workloads = workloads
		mu.Unlock()
		return nil
	})

	run(CollectorPods, func() error {
		pods, cp, err := collectPods(ctx, c)
		if err != nil {
			return err
		}
		mu.Lock()
		inv.StandalonePods = pods
		inv.ControlPlanePods = cp
		mu.Unlock()
		return nil
	})

	run(CollectorStorage, func() error {
		pvs, scs, pvcs, drivers, err := collectStorage(ctx, c)
		if err != nil {
			return err
		}
		mu.Lock()
		inv.PersistentVolumes, inv.StorageClasses, inv.PVCs, inv.CSIDrivers = pvs, scs, pvcs, drivers
		mu.Unlock()
		return nil
	})

	run(CollectorCRDs, func() error {
		crds, err := collectCRDs(ctx, c)
		if err != nil {
			return err
		}
		mu.Lock()
		inv.CRDs = crds
		mu.Unlock()
		return nil
	})

	run(CollectorIngresses, func() error {
		ingresses, err := collectIngresses(ctx, c)
		if err != nil {
			return err
		}
		mu.Lock()
		inv.Ingresses = ingresses
		mu.Unlock()
		return nil
	})

	run(CollectorConfigMaps, func() error {
		coredns, kubeProxy, err := collectKubeSystemConfig(ctx, c)
		if err != nil {
			return err
		}
		mu.Lock()
		inv.CoreDNS, inv.KubeProxy = coredns, kubeProxy
		mu.Unlock()
		return nil
	})

	wg.Wait()

	// The kubelet configs need the node list, so they run after it rather than beside it.
	if inv.Read(CollectorNodes) {
		configs, reachable, firstReason := collectKubeletConfigs(ctx, c, inv.Nodes)
		mu.Lock()
		inv.KubeletConfigs = configs
		mu.Unlock()
		switch {
		case reachable == 0:
			// Every node answered with a refusal. An entry per node was still appended, so
			// counting rows would call this a success; what matters is whether any kubelet
			// actually told us its configuration.
			reason := "no node's kubelet configuration could be read"
			if firstReason != "" {
				reason += ": " + firstReason
			}
			record(CollectorKubeletConfig, fmt.Errorf("%s", reason), false)
		case reachable < len(configs):
			mu.Lock()
			inv.Collected[CollectorKubeletConfig] = CollectionState{
				OK: true, Partial: true,
				Reason: fmt.Sprintf("%d of %d kubelets answered, so kubelet rules were checked "+
					"against part of the fleet", reachable, len(configs)),
			}
			mu.Unlock()
		default:
			record(CollectorKubeletConfig, nil, false)
		}
	} else {
		record(CollectorKubeletConfig, fmt.Errorf("nodes could not be listed"), false)
	}

	// A managed control plane runs the API server out of the cluster, so there are no static
	// pods to read flags from. That is not a failure of this tool, but it does mean a large
	// family of rules cannot be checked, and the report has to say so.
	if inv.Read(CollectorPods) && len(inv.ControlPlanePods) == 0 {
		state := inv.Collected[CollectorControlPlanePods]
		state.OK = false
		state.Reason = "no static control-plane pods were found. This is normal on a managed control " +
			"plane (EKS, GKE, AKS), and on distributions such as k3s that run the control plane as a " +
			"single process rather than as pods. Either way its flags cannot be read through the API"
		state.VerifyCommand = "kubectl get pods -n kube-system -l tier=control-plane"
		inv.Collected[CollectorControlPlanePods] = state
	} else if inv.Read(CollectorPods) {
		inv.Collected[CollectorControlPlanePods] = CollectionState{OK: true}
	} else {
		inv.Collected[CollectorControlPlanePods] = CollectionState{
			OK: false, Reason: "pods could not be listed"}
	}

	return inv
}

func collectNodes(ctx context.Context, c *cluster.Client) ([]Node, error) {
	var out []Node
	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.CoreV1().Nodes().List(ctx, opts)
		if err != nil {
			return "", err
		}
		for _, n := range list.Items {
			node := Node{
				Name:                    n.Name,
				Labels:                  n.Labels,
				KubeletVersion:          n.Status.NodeInfo.KubeletVersion,
				ContainerRuntimeVersion: n.Status.NodeInfo.ContainerRuntimeVersion,
				KernelVersion:           n.Status.NodeInfo.KernelVersion,
				OSImage:                 n.Status.NodeInfo.OSImage,
				Status:                  map[string]any{},
			}
			// Catalog rules name a status field by string, and the agent-side product
			// flattens nodeInfo up to the top level. Mirroring that here means one rule
			// definition works against both.
			node.Status["kubeletVersion"] = n.Status.NodeInfo.KubeletVersion
			node.Status["containerRuntimeVersion"] = n.Status.NodeInfo.ContainerRuntimeVersion
			node.Status["kernelVersion"] = n.Status.NodeInfo.KernelVersion
			node.Status["osImage"] = n.Status.NodeInfo.OSImage
			node.Status["operatingSystem"] = n.Status.NodeInfo.OperatingSystem
			node.Status["architecture"] = n.Status.NodeInfo.Architecture
			out = append(out, node)
		}
		return list.Continue, nil
	})
	return out, err
}

func collectWorkloads(ctx context.Context, c *cluster.Client) ([]Workload, error) {
	var out []Workload

	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.AppsV1().Deployments("").List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			d := &list.Items[i]
			out = append(out, workloadFrom("Deployment", d.Namespace, d.Name, d.Labels, &d.Spec.Template))
		}
		return list.Continue, nil
	})
	if err != nil {
		return nil, err
	}

	err = eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.AppsV1().StatefulSets("").List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			s := &list.Items[i]
			out = append(out, workloadFrom("StatefulSet", s.Namespace, s.Name, s.Labels, &s.Spec.Template))
		}
		return list.Continue, nil
	})
	if err != nil {
		return nil, err
	}

	err = eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.AppsV1().DaemonSets("").List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			d := &list.Items[i]
			out = append(out, workloadFrom("DaemonSet", d.Namespace, d.Name, d.Labels, &d.Spec.Template))
		}
		return list.Continue, nil
	})
	return out, err
}

func workloadFrom(kind, namespace, name string, labels map[string]string, tpl *corev1.PodTemplateSpec) Workload {
	w := Workload{Kind: kind, Namespace: namespace, Name: name, Labels: labels}
	for _, ctr := range tpl.Spec.Containers {
		w.Containers = append(w.Containers, Container{Name: ctr.Name, Image: ctr.Image})
	}
	for _, ctr := range tpl.Spec.InitContainers {
		w.InitContainers = append(w.InitContainers, Container{Name: ctr.Name, Image: ctr.Image})
	}
	w.VolumeKeys = volumeKeys(tpl.Spec.Volumes)
	return w
}

// volumeKeys returns the volume-source field names present across a pod's volumes.
//
// The field name IS the plugin identity: a volume with a "gitRepo" key uses the gitRepo
// plugin. The "name" key is every volume's own label and never a plugin, so it is skipped.
func volumeKeys(volumes []corev1.Volume) []string {
	seen := map[string]bool{}
	var out []string
	for _, v := range volumes {
		raw, err := json.Marshal(v)
		if err != nil {
			continue
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(raw, &fields); err != nil {
			continue
		}
		for key := range fields {
			if key == "name" || seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, key)
		}
	}
	return out
}

func collectPods(ctx context.Context, c *cluster.Client) ([]Pod, []ControlPlanePod, error) {
	var standalone []Pod
	var controlPlane []ControlPlanePod

	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.CoreV1().Pods("").List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			p := &list.Items[i]
			// A pod owned by a controller is already represented by its workload; counting
			// it again would report the same volume once per replica.
			if !ownedByController(p) {
				standalone = append(standalone, Pod{
					Namespace:  p.Namespace,
					Name:       p.Name,
					VolumeKeys: volumeKeys(p.Spec.Volumes),
				})
			}
			if p.Namespace != metav1.NamespaceSystem {
				continue
			}
			for _, ctr := range p.Spec.Containers {
				component := controlPlaneComponent(ctr.Name)
				if component == "" {
					continue
				}
				controlPlane = append(controlPlane, ControlPlanePod{
					Name:      p.Name,
					Namespace: p.Namespace,
					Container: ctr.Name,
					Component: component,
					// command and args are one flag list to a rule; the split between them
					// is a container-spec detail, not a semantic one.
					Args: append(append([]string{}, ctr.Command...), ctr.Args...),
				})
			}
		}
		return list.Continue, nil
	})
	return standalone, controlPlane, err
}

func ownedByController(p *corev1.Pod) bool {
	for _, ref := range p.OwnerReferences {
		if ref.Controller != nil && *ref.Controller {
			return true
		}
	}
	return false
}

// controlPlaneComponent maps a container name to the component whose flags it carries.
//
// Substring rather than exact match: distributions name these containers variously
// ("kube-apiserver", "kube-apiserver-rke2"), and the flag surface is the same either way.
func controlPlaneComponent(containerName string) string {
	name := strings.ToLower(containerName)
	for _, component := range []string{
		"kube-apiserver", "kube-controller-manager", "kube-scheduler", "kube-proxy",
	} {
		if strings.Contains(name, component) {
			return component
		}
	}
	return ""
}

func collectStorage(ctx context.Context, c *cluster.Client) ([]PersistentVolume, []StorageClass, []PVC, []string, error) {
	var pvs []PersistentVolume
	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.CoreV1().PersistentVolumes().List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			pv := &list.Items[i]
			pvs = append(pvs, PersistentVolume{Name: pv.Name, SpecKeys: specKeys(pv.Spec)})
		}
		return list.Continue, nil
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var classes []StorageClass
	err = eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.StorageV1().StorageClasses().List(ctx, opts)
		if err != nil {
			return "", err
		}
		for _, sc := range list.Items {
			classes = append(classes, StorageClass{Name: sc.Name, Provisioner: sc.Provisioner})
		}
		return list.Continue, nil
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var claims []PVC
	err = eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.CoreV1().PersistentVolumeClaims("").List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			pvc := &list.Items[i]
			class := ""
			if pvc.Spec.StorageClassName != nil {
				class = *pvc.Spec.StorageClassName
			}
			claims = append(claims, PVC{Namespace: pvc.Namespace, Name: pvc.Name, StorageClassName: class})
		}
		return list.Continue, nil
	})
	if err != nil {
		return nil, nil, nil, nil, err
	}

	var drivers []string
	err = eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.StorageV1().CSIDrivers().List(ctx, opts)
		if err != nil {
			return "", err
		}
		for _, d := range list.Items {
			drivers = append(drivers, d.Name)
		}
		return list.Continue, nil
	})
	// A cluster with no CSIDriver API is old, not broken; the replacement-driver clause simply
	// has nothing to check.
	if err != nil && !apierrors.IsNotFound(err) {
		return nil, nil, nil, nil, err
	}

	return pvs, classes, claims, drivers, nil
}

// specKeys returns the top-level field names of a spec, which for a PersistentVolume name the
// volume plugin backing it.
func specKeys(spec any) []string {
	raw, err := json.Marshal(spec)
	if err != nil {
		return nil
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil
	}
	out := make([]string, 0, len(fields))
	for key := range fields {
		out = append(out, key)
	}
	return out
}

func collectIngresses(ctx context.Context, c *cluster.Client) ([]Ingress, error) {
	var out []Ingress
	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.NetworkingV1().Ingresses("").List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			ing := &list.Items[i]
			// Keys only. Snippet annotation values are raw nginx configuration and must
			// never reach a finding's text, where they would be printed to a terminal and
			// pasted into tickets.
			keys := make([]string, 0, len(ing.Annotations))
			for k := range ing.Annotations {
				keys = append(keys, k)
			}
			out = append(out, Ingress{Namespace: ing.Namespace, Name: ing.Name, AnnotationKeys: keys})
		}
		return list.Continue, nil
	})
	return out, err
}

// eachPage runs a paged list to completion.
func eachPage(ctx context.Context, page func(metav1.ListOptions) (string, error)) error {
	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		next, err := page(opts)
		if err != nil {
			return err
		}
		if next == "" {
			return nil
		}
		opts.Continue = next
	}
}

// explain turns an API error into something a reader can act on.
//
// "forbidden" on its own tells someone nothing; naming the permission and how to grant it
// turns a dead end into a next step.
func explain(err error) string {
	switch {
	case err == nil:
		return ""
	case apierrors.IsForbidden(err):
		return fmt.Sprintf("permission denied: %s", trimAPIError(err))
	case apierrors.IsNotFound(err):
		return "this resource type is not served by the cluster"
	case apierrors.IsResourceExpired(err):
		return "the cluster expired our paging token part-way through, so the list is incomplete"
	case apierrors.IsTimeout(err), apierrors.IsServerTimeout(err):
		return "the API server timed out"
	default:
		return trimAPIError(err)
	}
}

func trimAPIError(err error) string {
	msg := err.Error()
	if i := strings.Index(msg, ": "); i > 0 && i < 40 {
		msg = msg[i+2:]
	}
	return msg
}

var _ = appsv1.Deployment{}
