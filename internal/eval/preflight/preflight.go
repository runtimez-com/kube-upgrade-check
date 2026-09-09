// Package preflight reports what would stop the upgrade itself, as opposed to what breaks
// after it: a path that skips a minor, nodes that are not Ready, disruption budgets that will
// not let a drain proceed, admission and conversion webhooks whose Fail policy would block the
// API while their backend is down, and aggregated APIs the API server cannot reach.
//
// None of these come from a catalog. They are properties of the running cluster, not of a
// release, so they are checked on every path. What they share with the rest of the tool is the
// rule that a check which could not run is printed as a gap, never as a pass.
package preflight

import (
	"fmt"
	"sort"
	"strings"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

// Rule IDs, stable so a reader can filter on them.
const (
	RuleSkippedMinor          = "rtz-k8s-preflight-skipped-minor"
	RuleNodeNotReady          = "rtz-k8s-preflight-node-not-ready"
	RulePDBBlocksDrain        = "rtz-k8s-preflight-pdb-blocks-drain"
	RuleBarePods              = "rtz-k8s-preflight-bare-pods"
	RuleWebhookBackendDown    = "rtz-k8s-preflight-webhook-backend-unavailable"
	RuleWebhookFailPolicy     = "rtz-k8s-preflight-webhook-fail-policy"
	RuleConversionBackendDown = "rtz-k8s-preflight-crd-conversion-backend-unavailable"
	RuleAPIServiceUnavailable = "rtz-k8s-preflight-apiservice-unavailable"
	source                    = "upgrade preflight"
	maxNamed                  = 20
)

// Analyze runs every preflight check that has the data it needs and records a gap for each
// one that does not.
func Analyze(inv *inventory.Inventory, currentVersion, targetVersion string) ([]report.Finding, []report.Coverage) {
	var findings []report.Finding
	var coverage []report.Coverage

	if f := skippedMinor(inv.ClusterName, currentVersion, targetVersion); f != nil {
		findings = append(findings, *f)
	}

	add := func(f []report.Finding, c []report.Coverage) {
		findings = append(findings, f...)
		coverage = append(coverage, c...)
	}
	add(nodeReadiness(inv))
	add(drainFeasibility(inv))
	add(webhooks(inv))
	add(conversionWebhooks(inv))
	add(apiServices(inv))
	return findings, coverage
}

// skippedMinor: a control plane moves one minor at a time. kubeadm refuses a larger jump and
// every managed provider walks the intermediate versions for you, so a scan of 1.31 → 1.34 is a
// plan for three upgrades, not one. The findings for the whole path are still right; the reader
// just needs to know they will be applying them in stages.
func skippedMinor(clusterName, currentVersion, targetVersion string) *report.Finding {
	skew, ok := catalog.MinorSkew(currentVersion, targetVersion)
	if !ok || skew <= 1 {
		return nil
	}
	hops := hopsBetween(currentVersion, targetVersion)
	return &report.Finding{
		ID:     report.NewID(RuleSkippedMinor, clusterName),
		RuleID: RuleSkippedMinor,
		Title: fmt.Sprintf("Target %s is %d minors above %s: the control plane must be upgraded one minor at a time",
			catalog.MinorOf(targetVersion), skew, catalog.MinorOf(currentVersion)),
		Recommendation: "Plan the upgrade as " + strings.Join(hops, " → ") + ". kubeadm rejects a jump of more " +
			"than one minor, and EKS, GKE and AKS apply intermediate minors in turn. Re-run this check " +
			"against each hop before taking it; the findings below cover the whole path.",
		Category:         "RELIABILITY",
		Severity:         catalog.SeverityHigh,
		ScoreImpact:      catalog.SeverityHigh.ScoreImpact(),
		ResourceName:     clusterName,
		ResourceType:     "Cluster",
		AppliesAtVersion: catalog.MinorOf(targetVersion),
		Evidence:         []string{"upgrade path: " + strings.Join(hops, " → ")},
	}
}

func hopsBetween(current, target string) []string {
	hops := []string{catalog.MinorOf(current)}
	next := current
	for i := 0; i < 12; i++ {
		next = catalog.NextMinor(next)
		if next == "" {
			break
		}
		hops = append(hops, next)
		if catalog.MinorKey(next) >= catalog.MinorKey(target) {
			break
		}
	}
	return hops
}

// nodeReadiness: a node that is not Ready cannot take the pods a drain moves, and a control
// plane upgrade on a cluster that is already short of nodes turns a planned disruption into
// an outage.
func nodeReadiness(inv *inventory.Inventory) ([]report.Finding, []report.Coverage) {
	if !inv.Read(inventory.CollectorNodes) {
		return nil, []report.Coverage{gap("node readiness", inv.Collected[inventory.CollectorNodes].Reason, "kubectl get nodes")}
	}
	var notReady []string
	unknown := 0
	for _, n := range inv.Nodes {
		if n.Conditions == nil {
			unknown++
			continue
		}
		if status := n.Conditions["Ready"]; status != "True" {
			if status == "" {
				status = "no Ready condition"
			}
			notReady = append(notReady, fmt.Sprintf("Node %s (Ready=%s)", n.Name, status))
		}
	}
	var coverage []report.Coverage
	if unknown == len(inv.Nodes) && len(inv.Nodes) > 0 {
		return nil, []report.Coverage{gap("node readiness", "node conditions were not collected in this scan", "kubectl get nodes")}
	}
	coverage = append(coverage, report.Coverage{Source: source, Scope: "node readiness", State: report.CoverageComplete})
	if len(notReady) == 0 {
		return nil, coverage
	}
	sort.Strings(notReady)
	return []report.Finding{{
		ID:                report.NewID(RuleNodeNotReady, notReady[0]),
		RuleID:            RuleNodeNotReady,
		Title:             fmt.Sprintf("%d of %d nodes are not Ready", len(notReady), len(inv.Nodes)),
		Recommendation:    "Bring every node to Ready, or remove the ones that are not coming back, before upgrading. Drained pods need somewhere to land, and a control plane upgrade on a degraded fleet compounds the disruption.",
		Category:          "RELIABILITY",
		Severity:          catalog.SeverityHigh,
		ScoreImpact:       catalog.SeverityHigh.ScoreImpact(),
		ResourceName:      collapse(notReady),
		ResourceType:      "Node",
		AffectedResources: capNamed(notReady),
		Evidence:          capNamed(notReady),
	}}, coverage
}

// drainFeasibility: a PodDisruptionBudget with no disruptions left, and pods under it, stops
// `kubectl drain` cold; a pod with no controller is deleted by a drain and never recreated.
func drainFeasibility(inv *inventory.Inventory) ([]report.Finding, []report.Coverage) {
	var findings []report.Finding
	var coverage []report.Coverage

	if !inv.Read(inventory.CollectorPDBs) {
		state := inv.Collected[inventory.CollectorPDBs]
		coverage = append(coverage, gap("disruption budgets", state.Reason, fallback(state.VerifyCommand, "kubectl get pdb -A")))
	} else {
		var blocking []string
		for _, p := range inv.PDBs {
			if p.DisruptionsAllowed == 0 && p.ExpectedPods > 0 {
				blocking = append(blocking, fmt.Sprintf("%s/%s (healthy %d/%d, allowed 0)",
					p.Namespace, p.Name, p.CurrentHealthy, p.DesiredHealthy))
			}
		}
		coverage = append(coverage, report.Coverage{Source: source, Scope: "disruption budgets", State: report.CoverageComplete})
		if len(blocking) > 0 {
			sort.Strings(blocking)
			findings = append(findings, report.Finding{
				ID:                report.NewID(RulePDBBlocksDrain, blocking[0]),
				RuleID:            RulePDBBlocksDrain,
				Title:             fmt.Sprintf("%d PodDisruptionBudget(s) allow zero disruptions and will block node drains", len(blocking)),
				Recommendation:    "A drain waits on these budgets until they allow a disruption, and a node upgrade that drains first waits with it. Raise the replica count above minAvailable, relax the budget, or accept that these nodes must be drained by hand with --disable-eviction.",
				Category:          "RELIABILITY",
				Severity:          catalog.SeverityHigh,
				ScoreImpact:       catalog.SeverityHigh.ScoreImpact(),
				ResourceName:      collapse(blocking),
				ResourceType:      "PodDisruptionBudget",
				AffectedResources: capNamed(blocking),
				Evidence:          capNamed(blocking),
				VerifyCommand:     "kubectl get pdb -A -o custom-columns=NS:.metadata.namespace,NAME:.metadata.name,ALLOWED:.status.disruptionsAllowed,EXPECTED:.status.expectedPods",
			})
		}
	}

	if !inv.Read(inventory.CollectorPods) {
		coverage = append(coverage, gap("bare pods", inv.Collected[inventory.CollectorPods].Reason, "kubectl get pods -A -o json | jq -r '.items[] | select(.metadata.ownerReferences == null) | \"\\(.metadata.namespace)/\\(.metadata.name)\"'"))
		return findings, coverage
	}
	coverage = append(coverage, report.Coverage{Source: source, Scope: "bare pods", State: report.CoverageComplete})
	if len(inv.StandalonePods) == 0 {
		return findings, coverage
	}
	var bare []string
	for _, p := range inv.StandalonePods {
		bare = append(bare, p.Namespace+"/"+p.Name)
	}
	sort.Strings(bare)
	findings = append(findings, report.Finding{
		ID:                report.NewID(RuleBarePods, bare[0]),
		RuleID:            RuleBarePods,
		Title:             fmt.Sprintf("%d pod(s) have no controller and will not come back after a drain", len(bare)),
		Recommendation:    "A drain deletes these pods and nothing recreates them; `kubectl drain` refuses to proceed without --force. Move each one under a Deployment, StatefulSet, DaemonSet or Job, or accept the loss explicitly.",
		Category:          "RELIABILITY",
		Severity:          catalog.SeverityMedium,
		ScoreImpact:       catalog.SeverityMedium.ScoreImpact(),
		ResourceName:      collapse(bare),
		ResourceType:      "Pod",
		AffectedResources: capNamed(bare),
		Evidence:          capNamed(bare),
	})
	return findings, coverage
}

// webhooks: an admission webhook whose failurePolicy is Fail (the default) blocks every API
// operation it matches while its backend is unreachable. During an upgrade the backend is
// rescheduled like everything else, and the window when it is down is exactly when the API
// server is busiest creating pods. A backend that is down NOW blocks the upgrade outright.
func webhooks(inv *inventory.Inventory) ([]report.Finding, []report.Coverage) {
	if !inv.Read(inventory.CollectorWebhooks) {
		state := inv.Collected[inventory.CollectorWebhooks]
		return nil, []report.Coverage{gap("admission webhooks", state.Reason, fallback(state.VerifyCommand, "kubectl get validatingwebhookconfigurations,mutatingwebhookconfigurations"))}
	}
	var down, failPolicy, unchecked []string
	for _, w := range inv.Webhooks {
		if w.FailurePolicy != "Fail" {
			continue
		}
		ref := fmt.Sprintf("%s/%s (%s)", w.Config, w.Name, w.Kind)
		switch {
		case w.URL:
			failPolicy = append(failPolicy, ref+" → external URL, not checked")
		case w.Service == nil:
			failPolicy = append(failPolicy, ref+" → no backend declared")
		case !w.Backend.Checked:
			unchecked = append(unchecked, ref+": "+w.Backend.Reason)
		case !w.Backend.Ready:
			down = append(down, ref+": "+w.Backend.Reason)
		default:
			failPolicy = append(failPolicy, ref+" → "+w.Service.Namespace+"/"+w.Service.Name+" (ready)")
		}
	}
	state := inv.Collected[inventory.CollectorWebhooks]
	var coverage []report.Coverage
	if len(unchecked) > 0 {
		coverage = append(coverage, report.Coverage{
			Source: source, Scope: "admission webhooks", State: report.CoveragePartial,
			Reason:        fmt.Sprintf("%d Fail-policy webhook backend(s) could not be checked: %s", len(unchecked), strings.Join(capNamed(unchecked), "; ")),
			VerifyCommand: fallback(state.VerifyCommand, "kubectl get endpointslices -A -l kubernetes.io/service-name=<service>"),
		})
	} else {
		coverage = append(coverage, report.Coverage{Source: source, Scope: "admission webhooks", State: report.CoverageComplete})
	}

	var findings []report.Finding
	if len(down) > 0 {
		sort.Strings(down)
		findings = append(findings, report.Finding{
			ID:                report.NewID(RuleWebhookBackendDown, down[0]),
			RuleID:            RuleWebhookBackendDown,
			Title:             fmt.Sprintf("%d Fail-policy admission webhook(s) have no ready backend right now", len(down)),
			Recommendation:    "Every API request these webhooks match is being rejected until the backend is back, which includes the pod creations an upgrade depends on. Restore the backend, or set failurePolicy: Ignore for the duration of the upgrade if the webhook is not security-critical.",
			Category:          "RELIABILITY",
			Severity:          catalog.SeverityCritical,
			ScoreImpact:       catalog.SeverityCritical.ScoreImpact(),
			ResourceName:      collapse(down),
			ResourceType:      "Webhook",
			AffectedResources: capNamed(down),
			Evidence:          capNamed(down),
			VerifyCommand:     "kubectl get endpointslices -A -l kubernetes.io/service-name=<service>",
		})
	}
	if len(failPolicy) > 0 {
		sort.Strings(failPolicy)
		findings = append(findings, report.Finding{
			ID:                report.NewID(RuleWebhookFailPolicy, failPolicy[0]),
			RuleID:            RuleWebhookFailPolicy,
			Title:             fmt.Sprintf("%d admission webhook(s) use failurePolicy: Fail and will block the API while their backend restarts", len(failPolicy)),
			Recommendation:    "Expected for policy and security webhooks, but worth knowing before a rolling upgrade: while each backend is rescheduled, the requests it matches are refused. Upgrade the webhook's own workload first, keep at least two replicas with a PodDisruptionBudget, and scope the rules so kube-system pods are not intercepted.",
			Category:          "RELIABILITY",
			Severity:          catalog.SeverityLow,
			ScoreImpact:       catalog.SeverityLow.ScoreImpact(),
			ResourceName:      collapse(failPolicy),
			ResourceType:      "Webhook",
			AffectedResources: capNamed(failPolicy),
			Evidence:          capNamed(failPolicy),
		})
	}
	return findings, coverage
}

// conversionWebhooks: a CRD converting through a webhook cannot serve its objects at a version
// other than the stored one while the webhook is down, and an upgrade that moves storage
// versions or restarts the operator hits exactly that.
func conversionWebhooks(inv *inventory.Inventory) ([]report.Finding, []report.Coverage) {
	if !inv.Read(inventory.CollectorCRDs) {
		return nil, []report.Coverage{gap("CRD conversion webhooks", inv.Collected[inventory.CollectorCRDs].Reason, "kubectl get crd -o jsonpath='{range .items[?(@.spec.conversion.strategy==\"Webhook\")]}{.metadata.name}{\"\\n\"}{end}'")}
	}
	var down, unchecked []string
	for _, crd := range inv.CRDs {
		conv := crd.Conversion
		if conv == nil || conv.Strategy != "Webhook" || conv.Service == nil {
			continue
		}
		switch {
		case !conv.Backend.Checked:
			unchecked = append(unchecked, crd.Name+": "+conv.Backend.Reason)
		case !conv.Backend.Ready:
			down = append(down, crd.Name+": "+conv.Backend.Reason)
		}
	}
	var coverage []report.Coverage
	if len(unchecked) > 0 {
		coverage = append(coverage, report.Coverage{
			Source: source, Scope: "CRD conversion webhooks", State: report.CoveragePartial,
			Reason:        fmt.Sprintf("%d conversion webhook backend(s) could not be checked: %s", len(unchecked), strings.Join(capNamed(unchecked), "; ")),
			VerifyCommand: "kubectl get endpointslices -A -l kubernetes.io/service-name=<service>",
		})
	} else {
		coverage = append(coverage, report.Coverage{Source: source, Scope: "CRD conversion webhooks", State: report.CoverageComplete})
	}
	if len(down) == 0 {
		return nil, coverage
	}
	sort.Strings(down)
	return []report.Finding{{
		ID:                report.NewID(RuleConversionBackendDown, down[0]),
		RuleID:            RuleConversionBackendDown,
		Title:             fmt.Sprintf("%d CRD conversion webhook(s) have no ready backend right now", len(down)),
		Recommendation:    "Reads and writes of these custom resources at any version other than the stored one fail until the webhook is back, and controllers that watch them stall. Restore the backend before upgrading.",
		Category:          "RELIABILITY",
		Severity:          catalog.SeverityCritical,
		ScoreImpact:       catalog.SeverityCritical.ScoreImpact(),
		ResourceName:      collapse(down),
		ResourceType:      "CustomResourceDefinition",
		AffectedResources: capNamed(down),
		Evidence:          capNamed(down),
	}}, coverage
}

// apiServices: an aggregated API the API server cannot reach breaks discovery for every
// client, stalls garbage collection and namespace deletion, and makes `kubectl` print errors
// on every call. Upgrading on top of that is how a small outage becomes a long one.
func apiServices(inv *inventory.Inventory) ([]report.Finding, []report.Coverage) {
	if !inv.Read(inventory.CollectorAPIServices) {
		state := inv.Collected[inventory.CollectorAPIServices]
		return nil, []report.Coverage{gap("aggregated APIs", state.Reason, fallback(state.VerifyCommand, "kubectl get apiservices"))}
	}
	var unavailable []string
	for _, s := range inv.APIServices {
		if s.Local || s.Available {
			continue
		}
		unavailable = append(unavailable, s.Name+": "+fallback(s.Reason, "not available"))
	}
	coverage := []report.Coverage{{Source: source, Scope: "aggregated APIs", State: report.CoverageComplete}}
	if len(unavailable) == 0 {
		return nil, coverage
	}
	sort.Strings(unavailable)
	return []report.Finding{{
		ID:                report.NewID(RuleAPIServiceUnavailable, unavailable[0]),
		RuleID:            RuleAPIServiceUnavailable,
		Title:             fmt.Sprintf("%d aggregated API service(s) are unavailable", len(unavailable)),
		Recommendation:    "Fix or delete each APIService before upgrading: metrics-server and similar extension servers that are gone leave a registration that breaks discovery and garbage collection for the whole cluster.",
		Category:          "RELIABILITY",
		Severity:          catalog.SeverityHigh,
		ScoreImpact:       catalog.SeverityHigh.ScoreImpact(),
		ResourceName:      collapse(unavailable),
		ResourceType:      "APIService",
		AffectedResources: capNamed(unavailable),
		Evidence:          capNamed(unavailable),
		VerifyCommand:     "kubectl get apiservices | grep -v True",
	}}, coverage
}

// ---------- helpers ----------

func gap(scope, reason, verify string) report.Coverage {
	if strings.TrimSpace(reason) == "" {
		reason = scope + " could not be read"
	}
	return report.Coverage{Source: source, Scope: scope, State: report.CoverageUnavailable, Reason: reason, VerifyCommand: verify}
}

func collapse(items []string) string {
	if len(items) == 1 {
		return items[0]
	}
	return fmt.Sprintf("%s and %d more", items[0], len(items)-1)
}

func capNamed(items []string) []string {
	if len(items) > maxNamed {
		return items[:maxNamed]
	}
	return items
}

func fallback(value, whenEmpty string) string {
	if strings.TrimSpace(value) == "" {
		return whenEmpty
	}
	return value
}
