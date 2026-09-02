// Package cluster opens a read-only connection to a Kubernetes cluster and answers the two
// questions everything else depends on: what version is it, and who runs it.
//
// Nothing in this package writes. The clients it builds are handed to collectors that only
// list and get, and the RBAC preflight below exists so that a permission the caller lacks
// becomes a printed line in the report rather than a silent gap in it.
package cluster

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	authv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/discovery"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/metadata"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	"github.com/runtimez-com/kube-upgrade-check/internal/version"
)

// Client bundles the four client flavours the collectors need.
type Client struct {
	Config    *rest.Config
	Clientset kubernetes.Interface
	Discovery discovery.DiscoveryInterface
	Metadata  metadata.Interface
	Dynamic   dynamic.Interface

	// ContextName is the kubeconfig context in use, printed so a reader can never mistake
	// which cluster they just scanned. Reading the wrong cluster is the most expensive
	// mistake this tool could make.
	ContextName string

	warnings *warningCollector
}

// Options configure the connection.
type Options struct {
	Kubeconfig string
	Context    string
	// QPS and Burst override client-go's defaults, which are far too low for a scan that
	// lists thirty resource types: the default would spend most of its time throttled.
	QPS   float32
	Burst int
}

// Connect builds clients from a kubeconfig, falling back to in-cluster credentials.
func Connect(opts Options) (*Client, error) {
	rules := clientcmd.NewDefaultClientConfigLoadingRules()
	if opts.Kubeconfig != "" {
		rules.ExplicitPath = opts.Kubeconfig
	}
	overrides := &clientcmd.ConfigOverrides{}
	if opts.Context != "" {
		overrides.CurrentContext = opts.Context
	}
	cc := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides)

	cfg, err := cc.ClientConfig()
	if err != nil {
		return nil, fmt.Errorf("no usable kubeconfig or in-cluster credentials: %w", err)
	}

	contextName := opts.Context
	if contextName == "" {
		if raw, err := cc.RawConfig(); err == nil {
			contextName = raw.CurrentContext
		}
	}

	qps, burst := opts.QPS, opts.Burst
	if qps == 0 {
		qps = 50
	}
	if burst == 0 {
		burst = 100
	}
	cfg.QPS, cfg.Burst = qps, burst
	cfg.UserAgent = version.UserAgent()

	// The API server announces deprecated API use in a 299 warning header. Capturing them
	// turns the server's own opinion into evidence we can quote back.
	warnings := &warningCollector{}
	cfg.WarningHandler = warnings

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build clientset: %w", err)
	}
	metaClient, err := metadata.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build metadata client: %w", err)
	}
	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build dynamic client: %w", err)
	}

	return &Client{
		Config:      cfg,
		Clientset:   clientset,
		Discovery:   clientset.Discovery(),
		Metadata:    metaClient,
		Dynamic:     dynClient,
		ContextName: contextName,
		warnings:    warnings,
	}, nil
}

// Warnings returns the API server's own deprecation warnings seen so far.
func (c *Client) Warnings() []string { return c.warnings.seen() }

// ServerInfo is what the cluster says about itself.
type ServerInfo struct {
	GitVersion string
	Provider   string
}

// Identify reads the server version and infers the managed provider.
func (c *Client) Identify(ctx context.Context) (ServerInfo, error) {
	v, err := c.Discovery.ServerVersion()
	if err != nil {
		return ServerInfo{}, fmt.Errorf("read server version: %w", err)
	}
	info := ServerInfo{GitVersion: v.GitVersion}
	info.Provider = providerFromVersion(v.GitVersion)
	if info.Provider == "" {
		info.Provider = c.providerFromNodes(ctx)
	}
	return info, nil
}

// providerFromVersion reads the vendor suffix managed control planes add to their version
// string, e.g. "v1.33.13-eks-a1b2c3" or "v1.31.5-gke.1000".
func providerFromVersion(gitVersion string) string {
	v := strings.ToLower(gitVersion)
	switch {
	case strings.Contains(v, "-eks"):
		return "EKS"
	case strings.Contains(v, "-gke"):
		return "GKE"
	}
	return ""
}

// providerFromNodes is the fallback for AKS, which does not stamp its version string.
//
// Failure here is not an error: an unidentified provider means the support calendar reports
// "we do not know your deadline", which is a legitimate answer.
func (c *Client) providerFromNodes(ctx context.Context) string {
	nodes, err := c.Clientset.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil || len(nodes.Items) == 0 {
		return ""
	}
	for key := range nodes.Items[0].Labels {
		switch {
		case strings.HasPrefix(key, "kubernetes.azure.com/"):
			return "AKS"
		case strings.HasPrefix(key, "eks.amazonaws.com/"):
			return "EKS"
		case strings.HasPrefix(key, "cloud.google.com/gke-"):
			return "GKE"
		}
	}
	return ""
}

// Access is one permission check result.
type Access struct {
	Verb      string
	Group     string
	Resource  string
	Namespace string
	Allowed   bool
	Reason    string
}

// CanI asks the API server whether the caller may perform one read.
//
// Asking up front means the report can say "you cannot list secrets, so the Helm check did
// not run" instead of quietly producing a shorter list of findings. A webhook authorizer can
// still deny at request time, so collectors handle a live 403 as well.
func (c *Client) CanI(ctx context.Context, verb, group, resource, namespace string) Access {
	review := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authv1.ResourceAttributes{
				Verb:      verb,
				Group:     group,
				Resource:  resource,
				Namespace: namespace,
			},
		},
	}
	out, err := c.Clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		// An unavailable review is not a denial. Assume allowed and let the real call decide,
		// rather than reporting a gap the caller may not actually have.
		return Access{Verb: verb, Group: group, Resource: resource, Namespace: namespace,
			Allowed: true, Reason: "access review unavailable, attempted anyway"}
	}
	return Access{
		Verb: verb, Group: group, Resource: resource, Namespace: namespace,
		Allowed: out.Status.Allowed,
		Reason:  out.Status.Reason,
	}
}

// CanINonResource asks about a non-resource URL such as /metrics.
func (c *Client) CanINonResource(ctx context.Context, verb, path string) Access {
	review := &authv1.SelfSubjectAccessReview{
		Spec: authv1.SelfSubjectAccessReviewSpec{
			NonResourceAttributes: &authv1.NonResourceAttributes{Verb: verb, Path: path},
		},
	}
	out, err := c.Clientset.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, review, metav1.CreateOptions{})
	if err != nil {
		return Access{Verb: verb, Resource: path, Allowed: true, Reason: "access review unavailable, attempted anyway"}
	}
	return Access{Verb: verb, Resource: path, Allowed: out.Status.Allowed, Reason: out.Status.Reason}
}

// ServedVersions returns every group/version the API server still serves.
//
// Serving a removed version proves the door is open; it proves nothing about whether anyone
// walked through it. Callers must never treat this alone as evidence of use.
func (c *Client) ServedVersions() (map[schema.GroupVersion]bool, error) {
	if c.Discovery == nil {
		return nil, fmt.Errorf("no discovery client available")
	}
	groups, err := c.Discovery.ServerGroups()
	if err != nil {
		return nil, fmt.Errorf("read served API groups: %w", err)
	}
	served := map[schema.GroupVersion]bool{}
	for _, g := range groups.Groups {
		for _, v := range g.Versions {
			gv, err := schema.ParseGroupVersion(v.GroupVersion)
			if err != nil {
				continue
			}
			served[gv] = true
		}
	}
	return served, nil
}

// ListableResources returns the group-version-kinds the API server will accept a list request
// for.
//
// Several API types exist only to be created and never stored: access reviews, token reviews and
// their kin are questions the API server answers, not objects it keeps. Listing one is not a
// permission problem or a version problem, it is a category error, and reporting it as something
// we "could not see" would fill the report with gaps that are not gaps.
func (c *Client) ListableResources() (listable, requestOnly map[string]bool, partial bool, err error) {
	if c.Discovery == nil {
		return nil, nil, false, fmt.Errorf("no discovery client available")
	}
	_, resources, err := c.Discovery.ServerGroupsAndResources()
	if err != nil && len(resources) == 0 {
		return nil, nil, false, fmt.Errorf("read served API resources: %w", err)
	}
	// A partial result is common: one unavailable aggregated API server, a down metrics-server
	// or a webhook that is not answering, is enough. The groups that did answer are still worth
	// using, but the caller is told the picture is incomplete, because filtering against a
	// partial map silently narrows what gets scanned.
	partial = err != nil
	listable = map[string]bool{}
	requestOnly = map[string]bool{}
	for _, list := range resources {
		gv, parseErr := schema.ParseGroupVersion(list.GroupVersion)
		if parseErr != nil {
			continue
		}
		for _, r := range list.APIResources {
			key := gv.WithKind(r.Kind).String()
			var canList, canCreate bool
			for _, verb := range r.Verbs {
				switch verb {
				case "list":
					canList = true
				case "create":
					canCreate = true
				}
			}
			switch {
			case canList:
				listable[key] = true
			case canCreate:
				// Accepts a create and supports no list: the server answers with it rather than
				// storing it. Nothing of this kind persists, so there is nothing to scan.
				requestOnly[key] = true
			}
		}
	}
	return listable, requestOnly, partial, nil
}

// ResourcesByKind maps each served kind to the resource path used to list it.
//
// A custom resource's plural form is chosen by whoever wrote its definition and cannot be
// derived from the kind name, so it has to be looked up rather than guessed. Only listable
// kinds are included, and the first group serving a kind wins, which favours the built-in API
// over a custom resource that shadows its name.
func (c *Client) ResourcesByKind() (map[string]schema.GroupVersionResource, error) {
	// A missing discovery client is a caller error, but this tool must degrade into a reported
	// gap rather than crash: it runs against clusters whose shape we do not control.
	if c.Discovery == nil {
		return nil, fmt.Errorf("no discovery client available")
	}
	_, lists, err := c.Discovery.ServerGroupsAndResources()
	if err != nil && len(lists) == 0 {
		return nil, fmt.Errorf("read served API resources: %w", err)
	}
	out := map[string]schema.GroupVersionResource{}
	for _, list := range lists {
		gv, parseErr := schema.ParseGroupVersion(list.GroupVersion)
		if parseErr != nil {
			continue
		}
		for _, r := range list.APIResources {
			if _, taken := out[r.Kind]; taken || strings.Contains(r.Name, "/") {
				continue
			}
			for _, verb := range r.Verbs {
				if verb == "list" {
					out[r.Kind] = gv.WithResource(r.Name)
					break
				}
			}
		}
	}
	return out, nil
}

// RawGet fetches a non-resource path such as /metrics.
func (c *Client) RawGet(ctx context.Context, path string) ([]byte, error) {
	if c.Discovery == nil {
		return nil, fmt.Errorf("no discovery client available")
	}
	return c.Discovery.RESTClient().Get().AbsPath(path).DoRaw(ctx)
}

// DefaultTimeout bounds a whole scan. A scan that hangs is worse than one that reports what
// it managed to read.
const DefaultTimeout = 5 * time.Minute

// warningCollector records the API server's 299 warning headers.
type warningCollector struct {
	mu   sync.Mutex
	msgs []string
}

func (w *warningCollector) HandleWarningHeader(code int, agent, text string) {
	if code != 299 || text == "" {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, existing := range w.msgs {
		if existing == text {
			return
		}
	}
	w.msgs = append(w.msgs, text)
}

func (w *warningCollector) seen() []string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]string(nil), w.msgs...)
}
