package inventory

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/runtimez-com/kube-upgrade-check/internal/cluster"
)

// crdGVR is the definition list itself, read through the dynamic client so this tool does not
// depend on the apiextensions typed client.
var crdGVR = schema.GroupVersionResource{
	Group: "apiextensions.k8s.io", Version: "v1", Resource: "customresourcedefinitions",
}

func collectCRDs(ctx context.Context, c *cluster.Client) ([]CRD, error) {
	var out []CRD
	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Dynamic.Resource(crdGVR).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			item := list.Items[i].Object
			meta, _ := item["metadata"].(map[string]any)
			spec, _ := item["spec"].(map[string]any)
			if meta == nil {
				continue
			}
			name, _ := meta["name"].(string)
			crd := CRD{Name: name, Spec: spec}

			if versions, ok := spec["versions"].([]any); ok {
				for _, v := range versions {
					ver, ok := v.(map[string]any)
					if !ok {
						continue
					}
					// Only served versions matter. A version present in the definition but
					// not served cannot be used, so reporting it would be a false alarm.
					if served, _ := ver["served"].(bool); !served {
						continue
					}
					if n, _ := ver["name"].(string); n != "" {
						crd.ServedVersions = append(crd.ServedVersions, n)
					}
				}
			}

			// How a CRD was installed decides whether it can be upgraded the same way. A
			// true value proves client-side apply was used; a false one proves only that
			// this signal is absent, which is why rules may fire on true and never on false.
			if annotations, ok := meta["annotations"].(map[string]any); ok {
				_, present := annotations["kubectl.kubernetes.io/last-applied-configuration"]
				crd.LastAppliedConfigurationPresent = present
			}
			if managed, ok := meta["managedFields"].([]any); ok {
				for _, entry := range managed {
					e, ok := entry.(map[string]any)
					if !ok {
						continue
					}
					if manager, _ := e["manager"].(string); strings.Contains(manager, "client-side-apply") {
						crd.ClientSideApplyManager = true
					}
				}
			}
			out = append(out, crd)
		}
		return list.GetContinue(), nil
	})
	return out, err
}

// kubeletConfigTimeout bounds one node's /configz read. A node whose kubelet does not answer
// promptly is treated as unreachable rather than allowed to stall the scan.
const kubeletConfigTimeout = 5 * time.Second

// collectKubeletConfigs reads every node's live kubelet configuration.
//
// Returns how many nodes actually answered alongside the rows, because an entry is appended for
// every node including the ones that refused. Counting rows would report a fleet of refusals as
// a successful read.
func collectKubeletConfigs(ctx context.Context, c *cluster.Client, nodes []Node) ([]KubeletConfig, int, string) {
	var (
		mu          sync.Mutex
		out         []KubeletConfig
		reachable   int
		firstReason string
		wg          sync.WaitGroup
		limiter     = make(chan struct{}, 8)
	)

	for _, node := range nodes {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			limiter <- struct{}{}
			defer func() { <-limiter }()

			nodeCtx, cancel := context.WithTimeout(ctx, kubeletConfigTimeout)
			defer cancel()

			raw, err := c.RawGet(nodeCtx, fmt.Sprintf("/api/v1/nodes/%s/proxy/configz", name))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				reason := explain(err)
				if firstReason == "" {
					firstReason = reason
				}
				out = append(out, KubeletConfig{NodeName: name, Reachable: false, Reason: reason})
				return
			}
			cfg, err := unwrapKubeletConfig(raw)
			if err != nil {
				if firstReason == "" {
					firstReason = err.Error()
				}
				out = append(out, KubeletConfig{NodeName: name, Reachable: false, Reason: err.Error()})
				return
			}
			reachable++
			out = append(out, KubeletConfig{NodeName: name, Reachable: true, Config: cfg})
		}(node.Name)
	}
	wg.Wait()
	return out, reachable, firstReason
}

// unwrapKubeletConfig strips the envelope the kubelet wraps its configuration in.
//
// /configz returns {"kubeletconfig": {...}}, and a rule selector names a field inside that
// object, not the envelope.
func unwrapKubeletConfig(raw []byte) (map[string]any, error) {
	var envelope map[string]any
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("kubelet returned something that is not JSON")
	}
	if inner, ok := envelope["kubeletconfig"].(map[string]any); ok {
		return inner, nil
	}
	return envelope, nil
}

// collectKubeSystemConfig reads the two kube-system config maps that carry upgrade-relevant
// settings: CoreDNS's Corefile and kube-proxy's mode.
func collectKubeSystemConfig(ctx context.Context, c *cluster.Client) ([]CoreDNSConfig, *KubeProxyConfig, error) {
	var coredns []CoreDNSConfig
	var proxy *KubeProxyConfig

	err := eachPage(ctx, func(opts metav1.ListOptions) (string, error) {
		list, err := c.Clientset.CoreV1().ConfigMaps(metav1.NamespaceSystem).List(ctx, opts)
		if err != nil {
			return "", err
		}
		for i := range list.Items {
			cm := &list.Items[i]
			name := strings.ToLower(cm.Name)

			// Contains, not a prefix: distributions ship this as "rke2-coredns-rke2-coredns"
			// and similar, and a prefix match would miss every one of them.
			if strings.Contains(name, "coredns") {
				if corefile, ok := cm.Data["Corefile"]; ok {
					coredns = append(coredns, CoreDNSConfig{
						Namespace: cm.Namespace, Name: cm.Name, Plugins: corefilePlugins(corefile),
					})
				}
			}
			if name == "kube-proxy" || strings.Contains(name, "kube-proxy-config") {
				if mode := kubeProxyMode(cm.Data); mode != "" {
					proxy = &KubeProxyConfig{Mode: mode}
				}
			}
		}
		return list.Continue, nil
	})
	return coredns, proxy, err
}

// maxCorefileTokens bounds what a malformed or hostile Corefile can turn into.
const maxCorefileTokens = 64

// corefilePlugins returns the plugin directive NAMES inside a Corefile's server blocks.
//
// Names only, never values: a Corefile carries forwarder addresses and zone data, and none of
// that belongs in a report. The scan tracks brace depth and takes directives at depth 1, which
// is where plugins live; depth 0 is the server block itself and deeper levels are a plugin's
// own configuration.
func corefilePlugins(corefile string) []string {
	var (
		out   []string
		seen  = map[string]bool{}
		depth int
	)
	for _, line := range strings.Split(corefile, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if depth == 1 {
			if directive := firstToken(trimmed); directive != "" && !seen[directive] {
				seen[directive] = true
				out = append(out, directive)
				if len(out) >= maxCorefileTokens {
					return out
				}
			}
		}
		depth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
		if depth < 0 {
			depth = 0
		}
	}
	return out
}

// firstToken is the directive name at the start of a line, with any trailing brace removed.
func firstToken(line string) string {
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return ""
	}
	token := strings.TrimSuffix(fields[0], "{")
	token = strings.TrimSpace(token)
	if token == "" || token == "}" {
		return ""
	}
	return token
}

// kubeProxyMode digs the proxy mode out of the kube-proxy config map.
//
// The hosted product cannot read this at all, so a local scan answers a question the API
// alone does not.
func kubeProxyMode(data map[string]string) string {
	for _, key := range []string{"config.conf", "kube-proxy-config.yaml", "config.yaml"} {
		body, ok := data[key]
		if !ok {
			continue
		}
		for _, line := range strings.Split(body, "\n") {
			trimmed := strings.TrimSpace(line)
			if !strings.HasPrefix(trimmed, "mode:") {
				continue
			}
			mode := strings.TrimSpace(strings.TrimPrefix(trimmed, "mode:"))
			mode = strings.Trim(mode, `"'`)
			// An explicitly empty mode means "the default for this version", which is a
			// different fact from a mode that was set. Report it as unset.
			if mode != "" {
				return mode
			}
		}
	}
	return ""
}
