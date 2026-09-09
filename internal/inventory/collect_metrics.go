package inventory

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"

	"github.com/runtimez-com/kube-upgrade-check/internal/cluster"
)

// CollectorKubeletMetrics is the collector name for each kubelet's /metrics endpoint.
const CollectorKubeletMetrics = "kubelet metrics"

// KubeletMetrics is the handful of series one kubelet exports that a rule can settle on:
// the cgroup version of the host and the Kubernetes version at which its container runtime
// loses support. Neither fact is in Node status; the kubelet is the only place that says.
type KubeletMetrics struct {
	NodeName  string
	Reachable bool
	Reason    string
	// Series holds only the metric names that were asked for, each with every sample seen.
	Series map[string][]MetricSample
}

// MetricSample is one line of a Prometheus text exposition: its labels and value.
type MetricSample struct {
	Labels map[string]string
	Value  float64
}

// CollectKubeletMetrics reads /metrics from every node's kubelet through the API server proxy
// and keeps the named series. It needs the same nodes/proxy permission as the kubelet
// configuration read, and records the outcome the same way: every refusal is a per-node row,
// and a fleet that refused entirely is a failed collector, not an empty success.
func CollectKubeletMetrics(ctx context.Context, c *cluster.Client, inv *Inventory, names []string) {
	if len(names) == 0 {
		return
	}
	if inv.Collected == nil {
		inv.Collected = map[string]CollectionState{}
	}
	if !inv.Read(CollectorNodes) {
		inv.Collected[CollectorKubeletMetrics] = CollectionState{OK: false, Reason: "nodes could not be listed"}
		return
	}
	wanted := map[string]bool{}
	for _, n := range names {
		wanted[n] = true
	}

	var (
		mu          sync.Mutex
		out         []KubeletMetrics
		reachable   int
		firstReason string
		wg          sync.WaitGroup
		limiter     = make(chan struct{}, 8)
	)
	for _, node := range inv.Nodes {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			limiter <- struct{}{}
			defer func() { <-limiter }()

			nodeCtx, cancel := context.WithTimeout(ctx, kubeletConfigTimeout)
			defer cancel()
			raw, err := c.RawGet(nodeCtx, fmt.Sprintf("/api/v1/nodes/%s/proxy/metrics", name))
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				reason := explain(err)
				if firstReason == "" {
					firstReason = reason
				}
				out = append(out, KubeletMetrics{NodeName: name, Reachable: false, Reason: reason})
				return
			}
			reachable++
			out = append(out, KubeletMetrics{NodeName: name, Reachable: true, Series: parseMetrics(string(raw), wanted)})
		}(node.Name)
	}
	wg.Wait()

	inv.KubeletMetrics = out
	verify := "kubectl get --raw /api/v1/nodes/<node>/proxy/metrics | grep -E '" + strings.Join(names, "|") + "'"
	switch {
	case reachable == 0:
		reason := "no node's kubelet metrics could be read"
		if firstReason != "" {
			reason += ": " + firstReason
		}
		inv.Collected[CollectorKubeletMetrics] = CollectionState{OK: false, Reason: reason, VerifyCommand: verify}
	case reachable < len(out):
		inv.Collected[CollectorKubeletMetrics] = CollectionState{
			OK: true, Partial: true, VerifyCommand: verify,
			Reason: fmt.Sprintf("%d of %d kubelets answered, so metric-backed node rules were checked "+
				"against part of the fleet", reachable, len(out)),
		}
	default:
		inv.Collected[CollectorKubeletMetrics] = CollectionState{OK: true}
	}
}

// parseMetrics keeps the wanted series from a Prometheus text exposition. It reads the
// subset of the format the kubelet emits for gauges: an optional {label="value",...} block
// and a numeric sample. Anything it cannot parse is skipped rather than guessed at.
func parseMetrics(text string, wanted map[string]bool) map[string][]MetricSample {
	out := map[string][]MetricSample{}
	scanner := bufio.NewScanner(strings.NewReader(text))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		name := line
		if i := strings.IndexAny(line, "{ "); i >= 0 {
			name = line[:i]
		}
		if !wanted[name] {
			continue
		}
		rest := strings.TrimSpace(line[len(name):])
		labels := map[string]string{}
		if strings.HasPrefix(rest, "{") {
			end := strings.Index(rest, "}")
			if end < 0 {
				continue
			}
			for _, pair := range strings.Split(rest[1:end], ",") {
				k, v, ok := strings.Cut(strings.TrimSpace(pair), "=")
				if !ok {
					continue
				}
				labels[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
			}
			rest = strings.TrimSpace(rest[end+1:])
		}
		valueText := rest
		if i := strings.IndexByte(rest, ' '); i >= 0 {
			valueText = rest[:i] // a trailing timestamp, if any
		}
		value, err := strconv.ParseFloat(valueText, 64)
		if err != nil {
			continue
		}
		out[name] = append(out[name], MetricSample{Labels: labels, Value: value})
	}
	return out
}
