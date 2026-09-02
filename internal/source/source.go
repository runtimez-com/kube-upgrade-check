// Package source gathers evidence that a cluster still uses an API version the target
// Kubernetes release removes.
//
// This is harder than it looks, and the reason is worth stating: the API server converts
// objects on read. Ask for a Deployment and you get it back at whatever version you asked for,
// regardless of what was originally written. So no amount of listing tells you what version an
// object was created with, and a tool that lists objects and reports their apiVersion is
// reporting its own request back to itself.
//
// What does survive is the record of who wrote what. Every object carries managed-field entries
// naming the client that last wrote each part of it and the API version it used. Helm keeps its
// own copy of the manifest it applied. Client-side apply leaves the submitted manifest in an
// annotation. The API server counts deprecated requests it has served. Each of those is a
// different kind of evidence with different blind spots, so each is gathered separately and
// labelled, and the report says which one found what.
package source

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"

	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/cluster"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

// Evidence tier names, printed against each finding so a reader knows how strong the claim is.
const (
	// TierServed means the removed version is still served here. It proves the door is open,
	// never that anyone walked through it, so it can never make a finding on its own.
	TierServed = "served"
	// TierManagedFields means a named client last wrote these fields at that version. This is
	// the strongest per-object evidence available.
	TierManagedFields = "managed-fields"
	// TierLastApplied means a client-side apply submitted that version.
	TierLastApplied = "last-applied"
	// TierMetrics means the API server has served a request at that version since it started.
	TierMetrics = "apiserver-metrics"
)

// listPageSize bounds one page of a metadata list.
const listPageSize = 500

// Usage is one piece of evidence.
type Usage struct {
	APIVersion string
	Kind       string
	Namespace  string
	Name       string
	Tier       string
	Manager    string
	ObservedAt string
	Evidence   string
	// Stale marks evidence superseded by a newer write at the replacement version, which means
	// the object has since been rewritten and the old entry is a leftover.
	Stale bool
}

// Ref is the "namespace/name" form used in findings.
func (u Usage) Ref() string {
	if u.Namespace == "" {
		return u.Name
	}
	return u.Namespace + "/" + u.Name
}

// Result is what a scan of all tiers produced.
type Result struct {
	Usages   []Usage
	Coverage []report.Coverage
	// Served records which removed group-versions the API server still serves, so a rule can
	// distinguish "not applicable here" from "not found".
	Served map[string]bool
}

// Scan gathers evidence across every enabled tier.
//
// It never fails as a whole: a tier that cannot run records why and the others continue. The
// only thing that ends a scan is the caller's context.
func Scan(ctx context.Context, c *cluster.Client, cat *catalog.Catalog, targetVersion string) Result {
	result := Result{Served: map[string]bool{}}

	targets, served, coverage := resolveTargets(c, cat, targetVersion)
	result.Served = served
	result.Coverage = append(result.Coverage, coverage...)
	if len(targets) == 0 {
		return result
	}

	var mu sync.Mutex
	var wg sync.WaitGroup
	limiter := make(chan struct{}, 6)

	for _, t := range targets {
		wg.Add(1)
		go func(t target) {
			defer wg.Done()
			limiter <- struct{}{}
			defer func() { <-limiter }()

			usages, cov := scanObjects(ctx, c, t)
			mu.Lock()
			defer mu.Unlock()
			result.Usages = append(result.Usages, usages...)
			result.Coverage = append(result.Coverage, cov)
		}(t)
	}
	wg.Wait()

	metricUsages, metricCoverage := scanMetrics(ctx, c, kindByResource(c))
	result.Usages = append(result.Usages, metricUsages...)
	result.Coverage = append(result.Coverage, metricCoverage)

	sort.SliceStable(result.Usages, func(i, j int) bool {
		if result.Usages[i].APIVersion != result.Usages[j].APIVersion {
			return result.Usages[i].APIVersion < result.Usages[j].APIVersion
		}
		return result.Usages[i].Ref() < result.Usages[j].Ref()
	})
	return result
}

// target is one resource type to list, plus the removed versions we are looking for on it.
type target struct {
	gvr             schema.GroupVersionResource
	kind            string
	removedVersions map[string]bool
	// replacement is the current group-version, used to spot evidence that has since been
	// superseded by a rewrite.
	replacement string
}

// resolveTargets turns catalog rows into the small set of resource types worth listing.
//
// Only rows the target version actually removes are considered, and each is resolved to the
// version the API server serves today. An object written at a removed version is readable only
// through its replacement, so that is what gets listed.
func resolveTargets(c *cluster.Client, cat *catalog.Catalog, targetVersion string) ([]target, map[string]bool, []report.Coverage) {
	targetKey := catalog.MinorKey(targetVersion)
	if targetKey == 0 {
		return nil, nil, nil
	}

	served, err := c.ServedVersions()
	if err != nil {
		return nil, nil, []report.Coverage{{
			Source: "removed APIs", State: report.CoverageUnavailable,
			Reason: "the API server's list of served versions could not be read: " + err.Error(),
		}}
	}
	servedNames := map[string]bool{}
	for gv := range served {
		servedNames[gv.String()] = true
	}

	// Not every served type can be listed. Access reviews and their kin are questions the API
	// server answers rather than objects it stores, so asking for a list of them is a category
	// error, not a gap in what we could see.
	listable, requestOnly, discoveryPartial, err := c.ListableResources()
	if err != nil {
		// With no map at all the filter is skipped entirely and every target is attempted,
		// which errs toward scanning too much rather than too little.
		listable, requestOnly = nil, nil
	}

	// Group removed versions by the kind they belong to, so one list answers for all of them.
	byKind := map[string]*target{}
	var unscannable []unscannableRule
	for _, rule := range cat.DeprecationRules {
		if rule.Kind == "" || rule.Kind == "*" || rule.APIVersion == "" {
			continue
		}
		if key := catalog.MinorKey(rule.RemovedIn); key == 0 || key > targetKey {
			continue
		}
		// The version to list through. Normally the replacement, since an object written at a
		// removed version is readable only through the version that superseded it.
		//
		// Some rows have no replacement to speak of: PodSecurityPolicy's is a sentence telling
		// you to migrate to Pod Security Admission. Those used to be skipped in silence, which
		// meant the single most famous removed API in Kubernetes was scanned by nothing and
		// reported as nothing. When the removed version is itself still served, as it is on any
		// cluster that has not yet crossed the removal, that is what gets listed.
		listVersion := rule.Replacement
		if listVersion == "" || !servedNames[listVersion] {
			listVersion = rule.APIVersion
		}
		if !servedNames[listVersion] {
			// Neither the removed version nor its replacement is served. There is no way for an
			// object of this kind to exist here, so this is not applicable rather than
			// unchecked, and reporting it as a gap would be noise the reader cannot act on.
			continue
		}
		if listable != nil {
			gv, parseErr := schema.ParseGroupVersion(listVersion)
			if parseErr != nil || !listable[gv.WithKind(rule.Kind).String()] {
				// Some API types are questions the server answers rather than objects it keeps:
				// access reviews, token reviews and their kin accept a create and store nothing.
				// Nothing can be listed because nothing persists, which is again not applicable.
				if requestOnly != nil && requestOnly[gv.WithKind(rule.Kind).String()] {
					continue
				}
				unscannable = append(unscannable, unscannableRule{
					kind: rule.Kind, apiVersion: rule.APIVersion,
					reason: "this cluster does not accept a list request for this resource type",
				})
				continue
			}
		}
		t, ok := byKind[rule.Kind+"|"+listVersion]
		if !ok {
			gv, err := schema.ParseGroupVersion(listVersion)
			if err != nil {
				continue
			}
			t = &target{
				gvr:             gv.WithResource(resourceFor(rule.Kind)),
				kind:            rule.Kind,
				removedVersions: map[string]bool{},
				replacement:     listVersion,
			}
			byKind[rule.Kind+"|"+listVersion] = t
		}
		t.removedVersions[rule.APIVersion] = true
	}

	out := make([]target, 0, len(byKind))
	for _, t := range byKind {
		out = append(out, *t)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].kind < out[j].kind })

	coverage := unscannableCoverage(unscannable)
	if discoveryPartial {
		coverage = append(coverage, report.Coverage{
			Source: "removed APIs", Scope: "API discovery",
			State: report.CoveragePartial,
			Reason: "some API groups did not answer discovery, usually an unavailable aggregated API " +
				"server, so resource types they own may not have been scanned",
			VerifyCommand: "kubectl get apiservices | grep -v True",
		})
	}
	return out, servedNames, coverage
}

// unscannableRule is a removed-API row no list could cover.
type unscannableRule struct {
	kind       string
	apiVersion string
	reason     string
}

// unscannableCoverage reports rows the object tier could not scan, folded by reason.
//
// Skipping these in silence was the worst bug in this file: a rule that could not be checked
// left no trace at all, so the report was identical to one where the check ran and found
// nothing.
func unscannableCoverage(rules []unscannableRule) []report.Coverage {
	if len(rules) == 0 {
		return nil
	}
	byReason := map[string][]string{}
	var order []string
	for _, r := range rules {
		if _, seen := byReason[r.reason]; !seen {
			order = append(order, r.reason)
		}
		byReason[r.reason] = append(byReason[r.reason], r.kind+" "+r.apiVersion)
	}
	sort.Strings(order)

	out := make([]report.Coverage, 0, len(order))
	for _, reason := range order {
		kinds := byReason[reason]
		sort.Strings(kinds)
		out = append(out, report.Coverage{
			Source: "removed APIs", Scope: strings.Join(kinds, ", "),
			State: report.CoverageUnavailable, Reason: reason, RulesSkipped: len(kinds),
		})
	}
	return out
}

// resourceFor is the lowercase plural the API uses for a kind.
//
// The irregular plurals are spelled out because the general rule turns "Ingress" into
// "ingresss" and "NetworkPolicy" into "networkpolicys".
func resourceFor(kind string) string {
	lower := strings.ToLower(kind)
	switch {
	case strings.HasSuffix(lower, "s"), strings.HasSuffix(lower, "x"):
		return lower + "es"
	case strings.HasSuffix(lower, "y"):
		return strings.TrimSuffix(lower, "y") + "ies"
	default:
		return lower + "s"
	}
}

// scanObjects lists one resource type and reads both per-object evidence tiers from it.
//
// One list serves both tiers: managed fields and the client-side-apply annotation both live in
// object metadata, so a metadata-only list answers for each without fetching any specs.
func scanObjects(ctx context.Context, c *cluster.Client, t target) ([]Usage, report.Coverage) {
	var usages []Usage
	scope := t.kind

	opts := metav1.ListOptions{Limit: listPageSize}
	for {
		if err := ctx.Err(); err != nil {
			return usages, report.Coverage{
				Source: "removed APIs", Scope: scope, State: report.CoveragePartial,
				Reason: "the scan was cancelled part-way through this resource type",
			}
		}
		list, err := c.Metadata.Resource(t.gvr).Namespace(metav1.NamespaceAll).List(ctx, opts)
		if err != nil {
			return usages, coverageForError(scope, err, len(usages) > 0)
		}

		for i := range list.Items {
			item := &list.Items[i]
			usages = append(usages, fromManagedFields(item, t)...)
			usages = append(usages, fromLastApplied(item, t)...)
		}

		if list.Continue == "" {
			break
		}
		opts.Continue = list.Continue
	}

	return usages, report.Coverage{Source: "removed APIs", Scope: scope, State: report.CoverageComplete}
}

// fromManagedFields reads the record of who last wrote each part of an object.
//
// This is the tier that makes the check trustworthy. Every writer, whether kubectl, Helm, a
// GitOps controller or a bespoke operator, leaves an entry naming itself, the API version it
// used, and when. An entry at a removed version means those fields have not been rewritten
// since, which is exactly the condition an upgrade breaks.
func fromManagedFields(item metav1.Object, t target) []Usage {
	var usages []Usage
	var newest string
	for _, entry := range item.GetManagedFields() {
		if entry.APIVersion == t.replacement && entry.Time != nil {
			if ts := entry.Time.UTC().Format("2006-01-02"); ts > newest {
				newest = ts
			}
		}
	}

	for _, entry := range item.GetManagedFields() {
		if !t.removedVersions[entry.APIVersion] {
			continue
		}
		observed := ""
		if entry.Time != nil {
			observed = entry.Time.UTC().Format("2006-01-02")
		}
		usages = append(usages, Usage{
			APIVersion: entry.APIVersion,
			Kind:       t.kind,
			Namespace:  item.GetNamespace(),
			Name:       item.GetName(),
			Tier:       TierManagedFields,
			Manager:    entry.Manager,
			ObservedAt: observed,
			// A later write at the current version means the object has been rewritten and
			// the old entry is a leftover, so the finding is weaker but not absent.
			Stale: newest != "" && observed != "" && newest > observed,
			Evidence: fmt.Sprintf("%s last wrote this at %s on %s",
				fallback(entry.Manager, "an unnamed client"), entry.APIVersion, fallback(observed, "an unrecorded date")),
		})
	}
	return usages
}

// fromLastApplied reads the manifest a client-side apply submitted.
//
// Weaker than managed fields and much narrower: only client-side kubectl apply writes it, so
// Helm, server-side apply and most operators leave nothing. It is kept because it is the one
// signal that names the manifest a human actually edited.
func fromLastApplied(item metav1.Object, t target) []Usage {
	raw, ok := item.GetAnnotations()["kubectl.kubernetes.io/last-applied-configuration"]
	if !ok || raw == "" {
		return nil
	}
	version := apiVersionOf(raw)
	if version == "" || !t.removedVersions[version] {
		return nil
	}
	return []Usage{{
		APIVersion: version,
		Kind:       t.kind,
		Namespace:  item.GetNamespace(),
		Name:       item.GetName(),
		Tier:       TierLastApplied,
		Evidence:   fmt.Sprintf("the last applied manifest for this object declares %s", version),
	}}
}

// apiVersionOf pulls the apiVersion out of a stored manifest without parsing the whole thing.
func apiVersionOf(manifest string) string {
	const key = `"apiVersion":`
	i := strings.Index(manifest, key)
	if i < 0 {
		return ""
	}
	rest := manifest[i+len(key):]
	start := strings.Index(rest, `"`)
	if start < 0 {
		return ""
	}
	rest = rest[start+1:]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// scanMetrics reads the API server's own count of deprecated requests it has served.
//
// Cluster-wide rather than per-object, and only since the API server last started, so it can
// confirm something is still calling a removed version without saying what. A high request
// count with no matching object usually means a controller, not a person.
// kindByResource inverts discovery so a metric's resource label can be turned back into a kind.
//
// Prometheus labels name the lowercase plural ("ingresses"); the catalog is keyed by kind
// ("Ingress"). Without this mapping every metrics observation failed its catalog lookup and was
// dropped, which made the whole tier dead while it still reported itself complete.
func kindByResource(c *cluster.Client) map[string]string {
	byKind, err := c.ResourcesByKind()
	if err != nil {
		return nil
	}
	out := make(map[string]string, len(byKind))
	for kind, gvr := range byKind {
		out[gvr.Resource] = kind
	}
	return out
}

func scanMetrics(ctx context.Context, c *cluster.Client, kinds map[string]string) ([]Usage, report.Coverage) {
	raw, err := c.RawGet(ctx, "/metrics")
	if err != nil {
		reason := "the API server's metrics endpoint could not be read"
		switch {
		case apierrors.IsForbidden(err):
			reason = "reading /metrics is not permitted for this account, so requests to removed APIs could not be counted"
		case apierrors.IsNotFound(err):
			reason = "this cluster does not expose /metrics through the API server"
		}
		return nil, report.Coverage{
			Source: "removed APIs", Scope: "apiserver metrics",
			State: report.CoverageUnavailable, Reason: reason,
			VerifyCommand: "kubectl get --raw /metrics | grep apiserver_requested_deprecated_apis",
		}
	}

	var usages []Usage
	var unmatched []string
	for _, line := range strings.Split(string(raw), "\n") {
		if !strings.HasPrefix(line, "apiserver_requested_deprecated_apis") {
			continue
		}
		if strings.HasSuffix(strings.TrimSpace(line), " 0") {
			continue
		}
		group, version, resource := metricLabels(line)
		if version == "" {
			continue
		}
		apiVersion := version
		if group != "" {
			apiVersion = group + "/" + version
		}
		kind, known := kinds[resource]
		if !known {
			// A resource discovery does not describe cannot be matched to a catalog rule. Say
			// so rather than dropping the observation, since the API server just told us
			// something is calling a deprecated API.
			unmatched = append(unmatched, apiVersion+" "+resource)
			continue
		}
		usages = append(usages, Usage{
			APIVersion: apiVersion,
			Kind:       kind,
			Tier:       TierMetrics,
			Evidence: fmt.Sprintf("the API server has served requests for %s %s since it last started",
				apiVersion, resource),
		})
	}
	if len(unmatched) > 0 {
		sort.Strings(unmatched)
		return usages, report.Coverage{
			Source: "removed APIs", Scope: "apiserver metrics",
			State: report.CoveragePartial,
			Reason: "the API server reported deprecated requests for resource types discovery does not " +
				"describe, so they could not be matched to a rule: " + strings.Join(unmatched, ", "),
			RulesSkipped: len(unmatched),
		}
	}
	return usages, report.Coverage{
		Source: "removed APIs", Scope: "apiserver metrics", State: report.CoverageComplete,
		Reason: "counts requests since the API server last started, so a quiet period can hide a caller",
	}
}

// metricLabels pulls the group, version and resource labels out of a metric line.
func metricLabels(line string) (group, version, resource string) {
	open := strings.Index(line, "{")
	close := strings.Index(line, "}")
	if open < 0 || close < open {
		return "", "", ""
	}
	for _, pair := range strings.Split(line[open+1:close], ",") {
		key, value, ok := strings.Cut(pair, "=")
		if !ok {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"`)
		switch strings.TrimSpace(key) {
		case "group":
			group = value
		case "version":
			version = value
		case "resource":
			resource = value
		}
	}
	return group, version, resource
}

// coverageForError turns a failed list into a coverage row a reader can act on.
func coverageForError(scope string, err error, partial bool) report.Coverage {
	state := report.CoverageUnavailable
	if partial {
		state = report.CoveragePartial
	}
	reason := err.Error()
	switch {
	case apierrors.IsForbidden(err):
		reason = "listing this resource type is not permitted for this account"
	case apierrors.IsNotFound(err), apierrors.IsMethodNotSupported(err):
		reason = "this cluster does not serve this resource type"
	case apierrors.IsResourceExpired(err):
		reason = "the cluster expired our paging token part-way through, so only part of this resource type was read"
		state = report.CoveragePartial
	}
	return report.Coverage{
		Source: "removed APIs", Scope: scope, State: state, Reason: reason,
		VerifyCommand: fmt.Sprintf("kubectl get %s -A", strings.ToLower(scope)),
	}
}

func fallback(value, whenEmpty string) string {
	if strings.TrimSpace(value) == "" {
		return whenEmpty
	}
	return value
}

// ToInventory converts evidence into the inventory shape the evaluators read.
func ToInventory(usages []Usage) []inventory.APIUsage {
	out := make([]inventory.APIUsage, 0, len(usages))
	for _, u := range usages {
		out = append(out, inventory.APIUsage{
			APIVersion: u.APIVersion, Kind: u.Kind, Namespace: u.Namespace, Name: u.Name,
			Tier: u.Tier, Manager: u.Manager, ObservedAt: u.ObservedAt,
			Evidence: u.Evidence, Stale: u.Stale,
		})
	}
	return out
}
