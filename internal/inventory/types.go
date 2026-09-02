// Package inventory is what the tool read from the cluster.
//
// Every evaluator takes an Inventory and returns findings; nothing below this package talks
// to Kubernetes. That split is what makes the rules testable from a JSON fixture and what
// lets the same evaluators run against a cluster, a manifest directory, or a recorded scan.
//
// The types here distinguish "we looked and found nothing" from "we could not look" at every
// level, because collapsing those two is the single failure mode this tool exists to avoid.
package inventory

import "sort"

// Inventory is one read-only snapshot of a cluster.
type Inventory struct {
	ClusterName   string
	Provider      string // EKS | GKE | AKS | "" when unidentifiable
	ServerVersion string // as reported, e.g. "v1.33.13-eks-a1b2c3"

	Nodes             []Node
	KubeletConfigs    []KubeletConfig
	ControlPlanePods  []ControlPlanePod
	Workloads         []Workload
	StandalonePods    []Pod
	PersistentVolumes []PersistentVolume
	StorageClasses    []StorageClass
	PVCs              []PVC
	CSIDrivers        []string
	CRDs              []CRD
	// CRs is keyed by kind. A kind that could not be read is ABSENT from this map rather than
	// present and empty: an add-on rule must decline on an unread kind, not report it clean.
	CRs       map[string][]CustomResource
	Ingresses []Ingress
	CoreDNS   []CoreDNSConfig
	KubeProxy *KubeProxyConfig
	APIUsage  []APIUsage

	// Collected records what each collector managed to read. Evaluators consult it before
	// concluding anything from an empty slice.
	Collected map[string]CollectionState
}

// CollectionState is one collector's outcome.
type CollectionState struct {
	OK     bool
	Reason string // why not, in words a reader can act on
	// VerifyCommand is what the reader can run themselves when we could not.
	VerifyCommand string
	Partial       bool
}

// Read reports whether a named collector produced usable data.
func (i *Inventory) Read(collector string) bool {
	s, ok := i.Collected[collector]
	return ok && s.OK
}

// CoverageRows turns every collector's outcome into a row for the report.
//
// This exists because recording a failure is not the same as reporting one. Each collector
// already stores why it could not read something; without this, that reason sat in a map nobody
// consulted, the scan still called itself complete, and --strict had nothing to catch. A gap the
// tool knows about and does not print is worse than one it never noticed, because the output
// looks authoritative.
func (i *Inventory) CoverageRows() []CollectorOutcome {
	names := make([]string, 0, len(i.Collected))
	for name := range i.Collected {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]CollectorOutcome, 0, len(names))
	for _, name := range names {
		out = append(out, CollectorOutcome{Name: name, State: i.Collected[name]})
	}
	return out
}

// CollectorOutcome pairs a collector with what happened to it.
type CollectorOutcome struct {
	Name  string
	State CollectionState
}

// Node is one cluster node.
type Node struct {
	Name   string
	Labels map[string]string
	// Status is the node's status object, flattened enough for the rules that read it.
	KubeletVersion          string
	ContainerRuntimeVersion string
	KernelVersion           string
	OSImage                 string
	// Status carries every top-level status field, for catalog rules that name one by string.
	Status map[string]any
}

// KubeletConfig is one node's live kubelet configuration, as served by its /configz endpoint.
type KubeletConfig struct {
	NodeName string
	// Reachable is false when the node's kubelet could not be queried. An unreachable kubelet
	// is not a compliant one.
	Reachable bool
	Reason    string
	Config    map[string]any
}

// ControlPlanePod is a static control-plane pod and the flags it was started with. Absent on
// managed control planes, where the provider runs the API server out of sight.
type ControlPlanePod struct {
	Name      string
	Namespace string
	Container string
	Component string // kube-apiserver | kube-scheduler | kube-controller-manager | kube-proxy
	Args      []string
}

// Container is one container in a pod spec.
type Container struct {
	Name  string
	Image string
}

// Workload is a Deployment, StatefulSet or DaemonSet.
type Workload struct {
	Kind           string
	Namespace      string
	Name           string
	Labels         map[string]string
	Containers     []Container
	InitContainers []Container
	// VolumeKeys are the field names appearing in each pod-template volume, which is how an
	// in-tree volume plugin is recognised.
	VolumeKeys []string
}

// Ref is the "kind/namespace/name" form used in findings.
func (w Workload) Ref() string { return w.Kind + "/" + w.Namespace + "/" + w.Name }

// Pod is a standalone pod: one with no controller owning it.
type Pod struct {
	Namespace  string
	Name       string
	VolumeKeys []string
}

// PersistentVolume carries the top-level spec field names, which name the volume plugin.
type PersistentVolume struct {
	Name     string
	SpecKeys []string
}

// StorageClass is a provisioner binding.
type StorageClass struct {
	Name        string
	Provisioner string
}

// PVC links a claim to its class, so a finding can say how many workloads a class carries.
type PVC struct {
	Namespace        string
	Name             string
	StorageClassName string
}

// CRD is a custom resource definition and the versions it serves.
type CRD struct {
	Name           string
	ServedVersions []string
	// LastAppliedConfigurationPresent and ClientSideApplyManager record how this CRD was
	// installed. A true value proves client-side apply was used; a false one proves only that
	// this particular signal is absent, which is why rules may only fire on true.
	LastAppliedConfigurationPresent bool
	ClientSideApplyManager          bool
	Spec                            map[string]any
}

// CustomResource is one instance of a custom kind.
type CustomResource struct {
	Kind           string
	Namespace      string
	Name           string
	Labels         map[string]string
	AnnotationKeys []string
	Spec           map[string]any
}

// Ref is the "namespace/name" form used in findings.
func (c CustomResource) Ref() string {
	if c.Namespace == "" {
		return c.Name
	}
	return c.Namespace + "/" + c.Name
}

// Ingress carries annotation KEYS only. Snippet annotation values are raw nginx config and
// must never reach a finding's text.
type Ingress struct {
	Namespace      string
	Name           string
	AnnotationKeys []string
}

// CoreDNSConfig is the plugin directives found in a Corefile, names only.
type CoreDNSConfig struct {
	Namespace string
	Name      string
	Plugins   []string
}

// KubeProxyConfig is the proxy mode read from the kube-proxy ConfigMap.
type KubeProxyConfig struct {
	Mode string
}

// APIUsage is one piece of evidence that a removed API version is still in use.
type APIUsage struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	// Tier names which evidence source found this, and Manager who wrote it.
	Tier       string
	Manager    string
	ObservedAt string
	Evidence   string
	// Stale marks evidence superseded by a newer write at the replacement version.
	Stale bool
}
