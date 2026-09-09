// Package generated evaluates the release-note rules under catalog/k8s-rules.
//
// Each rule was extracted from a Kubernetes changelog by the backend's pipeline and carries the
// sentence it rests on. Most of them (116 of 149 at the time of writing) are NOT_DETECTABLE:
// the note describes behaviour no API call can settle, and those print as advisories exactly
// like the hand-written advisory catalog. The rest name a predicate over objects the collector
// read, and settle as a finding, a clear, or a decline.
//
// The discipline is the same as everywhere else in this tool: a rule whose evidence could not be
// read is a printed gap, never a pass. A kind the cluster does not serve at all is different, and
// is not a gap: there can be no objects, so the rule does not apply.
package generated

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

const (
	// Source is the coverage-row source name for every gap this package reports.
	Source = "release-note rules"
	// maxNamed caps how many objects a finding names. The count is still reported.
	maxNamed  = 10
	checkWith = " Check with: "
)

// Wants returns the kinds the detectable rules on the path from current to target read, each
// with the top-level spec and status keys those rules look at. The collector keeps only those
// keys, so a cluster-wide Pod list costs a few bytes per pod rather than a copy of every spec.
//
// Nodes are read by the typed collector and are not requested here.
func Wants(cat *catalog.Catalog, currentVersion, targetVersion string) map[string]inventory.Projection {
	wants := map[string]inventory.Projection{}
	for _, rule := range onPath(cat, currentVersion, targetVersion) {
		d := rule.Detection
		if d.Kind == catalog.DetectNotDetectable || d.Kind == catalog.DetectCRDServedVersion {
			continue
		}
		if d.Kind == catalog.DetectAPIVersionInUse && staticCatalogOwns(cat, d) {
			continue
		}
		for _, kind := range d.ObjectKinds() {
			if kind == "Node" {
				continue
			}
			p := wants[kind]
			if p.Keep == nil {
				p.Keep = []string{}
			}
			switch d.Kind {
			case catalog.DetectSpecFieldPresent, catalog.DetectSpecFieldEquals, catalog.DetectSpecPathMatches:
				key, _, _ := strings.Cut(strings.TrimSuffix(d.Target, "[]"), ".")
				key = strings.TrimSuffix(key, "[]")
				if key != "" && !contains(p.Keep, key) {
					p.Keep = append(p.Keep, key)
				}
			}
			wants[kind] = p
		}
	}
	return wants
}

// Analyze settles every kubernetes-sourced rule on the path from current to target.
//
// served is the map of removed group-versions the API server still serves, as the removed-API
// scan recorded it; it lets a group-level rule tell "not served here" from "not enumerated".
func Analyze(inv *inventory.Inventory, served map[string]bool, currentVersion, targetVersion string,
	cat *catalog.Catalog) ([]report.Finding, []report.Coverage) {

	var findings []report.Finding
	gaps := map[string]*gap{}

	for _, rule := range onPath(cat, currentVersion, targetVersion) {
		d := rule.Detection
		if d.Kind == catalog.DetectNotDetectable {
			findings = append(findings, advisory(rule, inv, targetVersion))
			continue
		}
		var out outcome
		switch d.Kind {
		case catalog.DetectAPIVersionInUse:
			if staticCatalogOwns(cat, d) {
				// The removed-API catalog carries this apiVersion and kind, and its evaluator
				// reports it with per-object write evidence. Reporting it here as well would
				// print one break twice under two rule IDs.
				continue
			}
			out = apiVersionInUse(inv, served, d)
		case catalog.DetectKindPresent:
			out = kindPresent(inv, d)
		case catalog.DetectLabelKeyPresent:
			out = keyPresent(inv, d, false)
		case catalog.DetectAnnotationKeyPresent:
			out = keyPresent(inv, d, true)
		case catalog.DetectSpecFieldPresent:
			out = specField(inv, d, false)
		case catalog.DetectSpecFieldEquals:
			out = specField(inv, d, true)
		case catalog.DetectSpecPathMatches:
			out = specPathMatches(inv, d)
		case catalog.DetectCRDServedVersion:
			out = crdServedVersion(inv, d)
		default:
			out = declinedFor(d.Kind+" rules", "detection kind "+d.Kind+" is not supported by this tool", "")
		}
		switch {
		case out.isDeclined:
			key := out.scope + "|" + out.declined
			g := gaps[key]
			if g == nil {
				g = &gap{scope: out.scope, reason: out.declined, verify: out.verify}
				gaps[key] = g
			}
			g.rules++
		case out.fired:
			findings = append(findings, finding(rule, inv.ClusterName, out))
		}
	}

	coverage := make([]report.Coverage, 0, len(gaps))
	for _, g := range gaps {
		coverage = append(coverage, report.Coverage{
			Source: Source, Scope: g.scope, State: report.CoverageUnavailable,
			Reason: g.reason, RulesSkipped: g.rules, VerifyCommand: g.verify,
		})
	}
	sort.Slice(coverage, func(i, j int) bool {
		if coverage[i].Scope != coverage[j].Scope {
			return coverage[i].Scope < coverage[j].Scope
		}
		return coverage[i].Reason < coverage[j].Reason
	})
	return findings, coverage
}

type gap struct {
	scope, reason, verify string
	rules                 int
}

// onPath is every kubernetes-sourced rule whose version lies in (current, target].
//
// The window matches the advisory catalog's: a change already live on the running cluster is
// not part of this upgrade. An unparseable current version widens the window rather than
// narrowing it, so uncertainty can add noise but never drops a rule.
//
// Add-on sources are not evaluated here. Their rules only make sense once the add-on is
// detected and versioned, which is the add-on evaluator's job.
func onPath(cat *catalog.Catalog, currentVersion, targetVersion string) []catalog.GeneratedRule {
	targetKey := catalog.MinorKey(targetVersion)
	if targetKey == 0 {
		return nil
	}
	currentKey := catalog.MinorKey(currentVersion)
	var out []catalog.GeneratedRule
	for _, rule := range cat.GeneratedRules {
		if rule.SourceID != "kubernetes" {
			continue
		}
		key := catalog.MinorKey(rule.AppliesAtVersion)
		if key == 0 || key > targetKey || (currentKey != 0 && key <= currentKey) {
			continue
		}
		out = append(out, rule)
	}
	return out
}

// staticCatalogOwns reports whether the removed-API catalog already carries this apiVersion,
// for this kind or (when the rule names no kind) for any kind.
func staticCatalogOwns(cat *catalog.Catalog, d catalog.Detection) bool {
	if d.ObjectKind != "" {
		_, ok := cat.DeprecationFor(d.Target, d.ObjectKind)
		return ok
	}
	for _, r := range cat.DeprecationRules {
		if r.APIVersion == d.Target {
			return true
		}
	}
	return false
}

// ---------- outcomes ----------

type outcome struct {
	fired    bool
	evidence []string
	affected []string
	matched  int
	// isDeclined marks a rule that could not be settled; declined says why, and scope and verify
	// go on the coverage row. A separate flag rather than a non-empty reason, because a collector
	// that failed without recording a reason must still be a gap and not a silent clear.
	isDeclined bool
	declined   string
	scope      string
	verify     string
}

func fired(evidence string, affected []string, matched int) outcome {
	return outcome{fired: true, evidence: []string{evidence}, affected: affected, matched: matched}
}

func clear() outcome { return outcome{} }

func declinedFor(scope, reason, verify string) outcome {
	if strings.TrimSpace(reason) == "" {
		reason = scope + " could not be read"
	}
	return outcome{isDeclined: true, declined: reason, scope: scope, verify: verify}
}

// ---------- rows ----------

// row is one object as the predicates see it, whichever collector produced it.
type row struct {
	ref       string
	namespace string
	name      string
	labels    map[string]string
	annKeys   []string
	spec      map[string]any
	status    map[string]any
	writtenAt []string
	managers  []string
}

type rowState int

const (
	rowsRead rowState = iota
	rowsUnread
	rowsNotServed
	rowsNotCollected
)

// rowsOf returns the objects of one kind and how the read went. Nodes come from the typed
// collector; everything else from the dynamic one.
func rowsOf(inv *inventory.Inventory, kind string) ([]row, rowState, string) {
	if kind == "Node" {
		if !inv.Read(inventory.CollectorNodes) {
			return nil, rowsUnread, inv.Collected[inventory.CollectorNodes].Reason
		}
		out := make([]row, 0, len(inv.Nodes))
		for _, n := range inv.Nodes {
			out = append(out, row{ref: n.Name, name: n.Name, labels: n.Labels, status: n.Status})
		}
		return out, rowsRead, ""
	}
	if rows, ok := inv.CRs[kind]; ok {
		out := make([]row, 0, len(rows))
		for _, cr := range rows {
			out = append(out, row{
				ref: cr.Ref(), namespace: cr.Namespace, name: cr.Name, labels: cr.Labels,
				annKeys: cr.AnnotationKeys, spec: cr.Spec, status: cr.Status,
				writtenAt: cr.WrittenAt, managers: cr.Managers,
			})
		}
		return out, rowsRead, ""
	}
	if reason, ok := inv.CRUnread[kind]; ok {
		return nil, rowsUnread, reason
	}
	if inv.CRNotServed[kind] {
		return nil, rowsNotServed, ""
	}
	return nil, rowsNotCollected, "objects of kind " + kind + " were not collected in this scan"
}

// subject gathers the rows a rule reads across its object kinds, applying the namespace and
// name filters. The bool is false when the rule does not apply here (no kind served); a
// non-empty decline names the first kind that could not be read.
func subject(inv *inventory.Inventory, d catalog.Detection) (rows []row, applies bool, decline outcome) {
	var namePattern *regexp.Regexp
	if d.ObjectName != "" {
		p, err := regexp.Compile(d.ObjectName)
		if err != nil {
			return nil, true, declinedFor(d.ObjectKind, "rule objectName is not a valid regex: "+d.ObjectName, "")
		}
		namePattern = p
	}
	servedSomewhere := false
	for _, kind := range d.ObjectKinds() {
		got, state, reason := rowsOf(inv, kind)
		switch state {
		case rowsNotServed:
			continue
		case rowsUnread, rowsNotCollected:
			return nil, true, declinedFor(kind, reason, verifyList(kind))
		}
		servedSomewhere = true
		for _, r := range got {
			if d.Namespace != "" && r.namespace != d.Namespace {
				continue
			}
			if namePattern != nil && !namePattern.MatchString(r.name) {
				continue
			}
			rows = append(rows, r)
		}
	}
	return rows, servedSomewhere, outcome{}
}

func verifyList(kind string) string {
	return "kubectl get " + strings.ToLower(kind) + " --all-namespaces"
}

// ---------- predicates ----------

func kindPresent(inv *inventory.Inventory, d catalog.Detection) outcome {
	rows, applies, decline := subject(inv, d)
	if decline.isDeclined {
		return decline
	}
	if !applies || len(rows) == 0 {
		return clear()
	}
	return fired(fmt.Sprintf("%d %s object(s) present", len(rows), d.ObjectKind), refs(rows), len(rows))
}

func keyPresent(inv *inventory.Inventory, d catalog.Detection, annotations bool) outcome {
	rows, applies, decline := subject(inv, d)
	if decline.isDeclined {
		return decline
	}
	if !applies {
		return clear()
	}
	what := "label key"
	if annotations {
		what = "annotation key"
	}
	var hits []row
	matchedKeys := map[string]bool{}
	for _, r := range rows {
		var keys []string
		if annotations {
			keys = r.annKeys
		} else {
			for k := range r.labels {
				keys = append(keys, k)
			}
		}
		if hit := matchKey(keys, d.Target); hit != "" {
			matchedKeys[hit] = true
			hits = append(hits, r)
		}
	}
	if len(hits) == 0 {
		return clear()
	}
	via := ""
	if len(matchedKeys) == 1 && !matchedKeys[d.Target] {
		for k := range matchedKeys {
			via = " (matched " + k + ")"
		}
	}
	return fired(fmt.Sprintf("%s %s present on %d %s object(s)%s", what, d.Target, len(hits), d.ObjectKind, via),
		refs(hits), len(hits))
}

// matchKey finds the key a rule's target names, in three deliberate modes: a target ending in
// "/" is a prefix family; a target containing "/" is exact; a bare name matches exactly or as
// the name part after the last "/", because release notes routinely give a label its short
// form. The matched key is returned so the finding can say which one it was.
func matchKey(keys []string, target string) string {
	if target == "" {
		return ""
	}
	sort.Strings(keys)
	if strings.HasSuffix(target, "/") {
		for _, k := range keys {
			if strings.HasPrefix(k, target) {
				return k
			}
		}
		return ""
	}
	for _, k := range keys {
		if k == target {
			return k
		}
	}
	if strings.Contains(target, "/") {
		return ""
	}
	for _, k := range keys {
		if k[strings.LastIndex(k, "/")+1:] == target {
			return k
		}
	}
	return ""
}

func specField(inv *inventory.Inventory, d catalog.Detection, equals bool) outcome {
	rows, applies, decline := subject(inv, d)
	if decline.isDeclined {
		return decline
	}
	if !applies {
		return clear()
	}
	var hits []row
	for _, r := range rows {
		for _, section := range []map[string]any{r.spec, r.status} {
			v, ok := section[d.Target]
			if !ok || v == nil {
				continue
			}
			if !equals || valueMatches(v, d.Value) {
				hits = append(hits, r)
				break
			}
		}
	}
	if len(hits) == 0 {
		return clear()
	}
	what := "field " + d.Target + " present"
	if equals {
		what = "field " + d.Target + "=" + d.Value
	}
	return fired(fmt.Sprintf("%s on %d %s object(s)", what, len(hits), d.ObjectKind), refs(hits), len(hits))
}

func specPathMatches(inv *inventory.Inventory, d catalog.Detection) outcome {
	pattern, err := regexp.Compile(d.Value)
	if err != nil {
		return declinedFor(d.ObjectKind, "rule value is not a valid regex: "+d.Value, "")
	}
	rows, applies, decline := subject(inv, d)
	if decline.isDeclined {
		return decline
	}
	if !applies {
		return clear()
	}
	segments := strings.Split(d.Target, ".")
	var hits []row
	for _, r := range rows {
		var leaves []string
		for _, section := range []map[string]any{r.spec, r.status} {
			if section != nil {
				leaves = append(leaves, leavesAt(section, segments)...)
			}
		}
		for _, leaf := range leaves {
			if pattern.MatchString(leaf) {
				hits = append(hits, r)
				break
			}
		}
	}
	if len(hits) == 0 {
		return clear()
	}
	return fired(fmt.Sprintf("%s matches /%s/ on %d %s object(s)", d.Target, d.Value, len(hits), d.ObjectKind),
		refs(hits), len(hits))
}

// leavesAt walks a dotted path where a segment ending in "[]" means each element, and returns
// every scalar found at the end as text.
func leavesAt(node any, segments []string) []string {
	if len(segments) == 0 {
		switch v := node.(type) {
		case nil:
			return nil
		case map[string]any:
			return nil
		case []any:
			var out []string
			for _, e := range v {
				out = append(out, leavesAt(e, nil)...)
			}
			return out
		default:
			return []string{fmt.Sprint(v)}
		}
	}
	seg := segments[0]
	each := strings.HasSuffix(seg, "[]")
	seg = strings.TrimSuffix(seg, "[]")
	m, ok := node.(map[string]any)
	if !ok {
		return nil
	}
	child, ok := m[seg]
	if !ok {
		return nil
	}
	if each {
		list, ok := child.([]any)
		if !ok {
			return nil
		}
		var out []string
		for _, e := range list {
			out = append(out, leavesAt(e, segments[1:])...)
		}
		return out
	}
	return leavesAt(child, segments[1:])
}

func crdServedVersion(inv *inventory.Inventory, d catalog.Detection) outcome {
	if !inv.Read(inventory.CollectorCRDs) {
		return declinedFor("CustomResourceDefinition", inv.Collected[inventory.CollectorCRDs].Reason,
			"kubectl get crd -o jsonpath='{range .items[*]}{.metadata.name}{\" \"}{.spec.versions[*].name}{\"\\n\"}{end}'")
	}
	var affected []string
	for _, crd := range inv.CRDs {
		name := strings.ToLower(crd.Name)
		if d.ObjectKind != "" && !strings.Contains(name, strings.ToLower(d.ObjectKind)) {
			continue
		}
		for _, v := range crd.ServedVersions {
			if v == d.Target {
				affected = append(affected, name)
				break
			}
		}
	}
	if len(affected) == 0 {
		return clear()
	}
	sort.Strings(affected)
	return fired(fmt.Sprintf("%d CRD(s) serve version %s", len(affected), d.Target), affected, len(affected))
}

// apiVersionInUse fires when an object's managed fields show a manager still writing at the
// target apiVersion (or any version of the target group when the target names no version).
func apiVersionInUse(inv *inventory.Inventory, served map[string]bool, d catalog.Detection) outcome {
	byGroup := !strings.Contains(d.Target, "/")
	if d.ObjectKind == "" {
		// Which kinds live under a group-version is a discovery question this evaluator cannot
		// ask, and guessing would fabricate. Say so, unless the scan already knows it is not
		// served, in which case there is nothing to enumerate.
		if v, known := served[d.Target]; known && !v {
			return clear()
		}
		return declinedFor(d.Target, "objects written at "+d.Target+" were not enumerated: the rule names no kind",
			"kubectl get --raw /apis/"+d.Target)
	}
	rows, applies, decline := subject(inv, d)
	if decline.isDeclined {
		return decline
	}
	if !applies {
		return clear()
	}
	var hits []row
	var evidence []string
	for _, r := range rows {
		for _, v := range r.writtenAt {
			if v == d.Target || (byGroup && strings.HasPrefix(v, d.Target+"/")) {
				hits = append(hits, r)
				if len(evidence) < maxNamed {
					evidence = append(evidence, r.ref+" last written at "+v+by(r.managers))
				}
				break
			}
		}
	}
	if len(hits) == 0 {
		return clear()
	}
	out := fired(fmt.Sprintf("%d %s object(s) still written at %s", len(hits), d.ObjectKind, d.Target), refs(hits), len(hits))
	out.evidence = append(out.evidence, evidence...)
	return out
}

func by(managers []string) string {
	if len(managers) == 0 {
		return ""
	}
	return " by " + strings.Join(managers, ", ")
}

// ---------- findings ----------

func finding(rule catalog.GeneratedRule, clusterName string, out outcome) report.Finding {
	recommendation := rule.Remediation
	verify := strings.TrimSpace(rule.VerifyCommand)
	if verify != "" {
		recommendation += checkWith + verify
	}
	resource := clusterName
	if len(out.affected) > 0 {
		resource = out.affected[0]
	}
	evidence := out.evidence
	if out.matched > len(out.affected) {
		evidence = append(evidence, fmt.Sprintf("%d objects match; first %d named", out.matched, len(out.affected)))
	}
	return report.Finding{
		ID:                report.NewID(rule.RuleID, resource),
		RuleID:            rule.RuleID,
		Title:             rule.Title,
		Recommendation:    recommendation,
		Category:          "RELIABILITY",
		Severity:          rule.Severity,
		ScoreImpact:       rule.Severity.ScoreImpact(),
		ResourceName:      resource,
		ResourceType:      rule.Detection.ObjectKind,
		AppliesAtVersion:  catalog.MinorOf(rule.AppliesAtVersion),
		VerifyCommand:     verify,
		AffectedResources: out.affected,
		Quote:             rule.Quote,
		Evidence:          evidence,
	}
}

// advisory renders a NOT_DETECTABLE rule the way the advisory catalog renders its own: INFO,
// no score, the reason it cannot be checked, and any hint the scan can add about where to look.
func advisory(rule catalog.GeneratedRule, inv *inventory.Inventory, targetVersion string) report.Finding {
	recommendation := rule.Remediation
	if reason := strings.TrimSpace(rule.Detection.Reason); reason != "" {
		recommendation += " Not checked here: " + reason
	}
	verify := strings.TrimSpace(rule.VerifyCommand)
	if verify != "" {
		recommendation += checkWith + verify
	}
	return report.Finding{
		ID:               report.NewID(rule.RuleID, inv.ClusterName),
		RuleID:           rule.RuleID,
		Title:            rule.Title + " [target " + targetVersion + "]",
		Recommendation:   recommendation,
		Category:         "RELIABILITY",
		Severity:         catalog.SeverityInfo,
		ScoreImpact:      0,
		ResourceName:     inv.ClusterName,
		ResourceType:     "Cluster",
		EnforcementLevel: "advisory",
		VerifyCommand:    verify,
		AppliesAtVersion: catalog.MinorOf(rule.AppliesAtVersion),
		Quote:            rule.Quote,
		Evidence:         hint(rule.Scope, inv),
	}
}

// hint names what a scope hint points at, using whatever this scan happened to collect. A hint
// settles nothing, so a kind that was not read simply adds no line.
func hint(scope *catalog.ScopeHint, inv *inventory.Inventory) []string {
	if scope == nil {
		return nil
	}
	d := catalog.Detection{Kind: scope.Kind, ObjectKind: scope.ObjectKind, Namespace: scope.Namespace,
		Target: scope.Target, Value: scope.Value}
	switch scope.Kind {
	case catalog.DetectKindPresent:
		n := 0
		for _, kind := range d.ObjectKinds() {
			n += typedCount(inv, kind)
		}
		if n > 0 {
			return []string{fmt.Sprintf("hint: %d %s object(s) to review", n, scope.ObjectKind)}
		}
	case catalog.DetectSpecFieldPresent:
		if out := specField(inv, d, false); out.fired {
			return []string{"hint: " + out.evidence[0] + ": " + strings.Join(out.affected, ", ")}
		}
	case catalog.DetectImageRepositoryPresent:
		var named []string
		for _, w := range inv.Workloads {
			for _, c := range append(append([]inventory.Container{}, w.Containers...), w.InitContainers...) {
				if strings.Contains(c.Image, scope.Target) {
					named = append(named, w.Namespace+"/"+w.Name)
					break
				}
			}
		}
		if len(named) > 0 {
			return []string{fmt.Sprintf("hint: %d workload(s) run an image from %s: %s", len(named), scope.Target,
				strings.Join(capNamed(named), ", "))}
		}
	}
	return nil
}

// typedCount counts objects of a kind from whichever collector holds them.
func typedCount(inv *inventory.Inventory, kind string) int {
	switch kind {
	case "Node":
		return len(inv.Nodes)
	case "Deployment", "DaemonSet", "StatefulSet", "Job", "CronJob", "ReplicaSet":
		n := 0
		for _, w := range inv.Workloads {
			if w.Kind == kind {
				n++
			}
		}
		if n > 0 {
			return n
		}
	}
	return len(inv.CRs[kind])
}

// ---------- helpers ----------

func valueMatches(field any, want string) bool {
	return strings.EqualFold(strings.TrimSpace(fmt.Sprint(field)), strings.TrimSpace(want))
}

func refs(rows []row) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ref)
	}
	sort.Strings(out)
	return capNamed(out)
}

func capNamed(items []string) []string {
	if len(items) > maxNamed {
		return items[:maxNamed]
	}
	return items
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
