// Package generated evaluates the release-note rules under catalog/k8s-rules.
//
// Each rule was extracted from a changelog or migration guide by the hosted product's pipeline
// and carries the sentence it rests on. Most are NOT_DETECTABLE: the note describes behaviour
// no API call can settle, and those print as advisories exactly like the hand-written advisory
// catalog. The rest name a predicate over objects the collector read, and settle as a finding,
// a clear, or a decline.
//
// There is one rule set per SOURCE: the Kubernetes release notes, kube-proxy, the version-skew
// policy, and one per add-on (CoreDNS, cert-manager, Traefik, ...). The Kubernetes sets run on
// the Kubernetes hop; an add-on's set runs on the add-on's OWN hop, the version range the
// add-on tier resolved for it, and not at all when there is none. Both products evaluate the
// same files with the same selection, so a rule that fires here fires there.
//
// The discipline is the same as everywhere else in this tool: a rule whose evidence could not be
// read is a printed gap, never a pass. A kind the cluster does not serve at all is different, and
// is not a gap: there can be no objects, so the rule does not apply.
package generated

import (
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/addons"
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

// Hops is the add-on version ranges the add-on tier resolved, keyed by add-on id. Each add-on
// rule set is selected against its own entry; a set with no entry is not evaluated.
type Hops = map[string]addons.Hop

// Wants returns the kinds the rules on the path read, each with the top-level spec and status
// keys those rules look at. The collector keeps only those keys, so a cluster-wide Pod list
// costs a few bytes per pod rather than a copy of every spec.
//
// Scope hints and gates are included: a hint that names candidates needs its kind read, and a
// gate that cannot be checked declines the rule it guards. Nodes are read by the typed
// collector and are not requested here.
func Wants(cat *catalog.Catalog, currentVersion, targetVersion string, hops Hops) map[string]inventory.Projection {
	wants := map[string]inventory.Projection{}
	want := func(kind string, d catalog.Detection) {
		if kind == "" || kind == "Node" {
			return
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
		case catalog.DetectImageRepositoryPresent:
			for _, key := range []string{"containers", "initContainers"} {
				if !contains(p.Keep, key) {
					p.Keep = append(p.Keep, key)
				}
			}
		}
		wants[kind] = p
	}
	for _, rule := range onPath(cat, currentVersion, targetVersion, hops).rules {
		d := rule.Detection
		switch {
		case d.Kind == catalog.DetectNotDetectable, d.Kind == catalog.DetectCRDServedVersion,
			d.Kind == catalog.DetectVersionSkewExceeds:
		case d.Kind == catalog.DetectAPIVersionInUse && staticCatalogOwns(cat, d):
		default:
			for _, kind := range d.ObjectKinds() {
				want(kind, d)
			}
		}
		if s := rule.Scope; s != nil {
			hint := catalog.Detection{Kind: s.Kind, ObjectKind: s.ObjectKind, Target: s.Target, Value: s.Value}
			for _, kind := range hint.ObjectKinds() {
				want(kind, hint)
			}
		}
		if g := rule.Gate; g != nil {
			gate := catalog.Detection{Kind: g.Kind, ObjectKind: g.ObjectKind, Target: g.Target, Value: g.Value}
			for _, kind := range gate.ObjectKinds() {
				want(kind, gate)
			}
		}
	}
	return wants
}

// Analyze settles every rule on the path.
//
// served is the map of removed group-versions the API server still serves, as the removed-API
// scan recorded it; it lets a group-level rule tell "not served here" from "not enumerated".
// hops is what the add-on tier resolved; it decides which add-on rule sets run.
func Analyze(inv *inventory.Inventory, served map[string]bool, currentVersion, targetVersion string,
	cat *catalog.Catalog, hops Hops) ([]report.Finding, []report.Coverage) {

	sel := onPath(cat, currentVersion, targetVersion, hops)
	gaps := map[string]*gap{}
	var outcomes []ruleOutcome

	for _, rule := range sel.rules {
		d := rule.Detection
		if d.Kind == catalog.DetectNotDetectable {
			outcomes = append(outcomes, ruleOutcome{rule: rule, advisory: true})
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
		case catalog.DetectCRDServedVersion:
			out = crdServedVersion(inv, d)
		case catalog.DetectVersionSkewExceeds:
			out = versionSkew(inv, d, targetVersion)
		default:
			out = rowRule(inv, d)
		}
		if rule.Gate != nil && !out.isDeclined {
			out = gated(inv, rule, out)
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
			outcomes = append(outcomes, ruleOutcome{rule: rule, out: out})
		}
	}

	foldDuplicates(outcomes)

	var findings []report.Finding
	for _, o := range outcomes {
		switch {
		case o.advisory:
			findings = append(findings, advisory(o.rule, inv, hopTarget(o.rule, targetVersion, hops)))
		case o.duplicateOf != "":
			// Folded into the retained finding, which names it. Every rule in the hop was
			// evaluated; the fold only stops one change from printing as several cards.
		default:
			findings = append(findings, finding(o.rule, inv.ClusterName, o.out, o.alsoRaisedBy))
		}
	}

	coverage := make([]report.Coverage, 0, len(gaps)+len(sel.skipped))
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
	// A source that was not evaluated is stated, never silently absent. It is COMPLETE rather
	// than a gap: no CoreDNS installed, or no CoreDNS move on this path, means no CoreDNS note
	// applies, which is a fact about the cluster and not a failure to look. The one case that
	// IS a gap, an add-on that is installed but whose version could not be read, is already
	// its own finding in the add-on tier.
	for _, s := range sel.skipped {
		coverage = append(coverage, report.Coverage{
			Source: Source, Scope: s.source + " rules", State: report.CoverageComplete, Reason: s.reason,
		})
	}
	return findings, coverage
}

type gap struct {
	scope, reason, verify string
	rules                 int
}

type ruleOutcome struct {
	rule         catalog.GeneratedRule
	out          outcome
	advisory     bool
	duplicateOf  string
	alsoRaisedBy []string
}

// ---------- selection ----------

type selection struct {
	rules   []catalog.GeneratedRule
	skipped []skippedSource
}

type skippedSource struct {
	source, reason string
}

// onPath selects the rules this scan evaluates, per source.
//
// A Kubernetes-versioned source (the release notes, kube-proxy) contributes the rules whose
// minor lies in (current, target], the same window the advisory catalog uses: a change already
// live on the running cluster is not part of this upgrade. An unparseable current version
// widens the window rather than narrowing it, so uncertainty can add noise but never drops a
// rule. The always-on skew policy contributes everything. An add-on source contributes the
// rules whose add-on minor lies in (installed, required] of that add-on's resolved hop, and
// nothing without one.
func onPath(cat *catalog.Catalog, currentVersion, targetVersion string, hops Hops) selection {
	var sel selection
	targetKey := catalog.MinorKey(targetVersion)
	if targetKey == 0 {
		return sel
	}
	currentKey := catalog.MinorKey(currentVersion)
	skipped := map[string]bool{}
	for _, rule := range cat.GeneratedRules {
		if !rule.IsEnabled() {
			continue
		}
		switch catalog.SourceScoping(rule.SourceID) {
		case catalog.ScopedToKubernetesHop:
			key := catalog.MinorKey(rule.AppliesAtVersion)
			if key == 0 || key > targetKey || (currentKey != 0 && key <= currentKey) {
				continue
			}
		case catalog.AlwaysOn:
		case catalog.ScopedToAddonHop:
			hop, ok := hops[rule.SourceID]
			if !ok {
				if !skipped[rule.SourceID] {
					skipped[rule.SourceID] = true
					sel.skipped = append(sel.skipped, skippedSource{source: rule.SourceID,
						reason: rule.SourceID + " release notes were not evaluated: they apply to " +
							rule.SourceID + "'s own version range, and this scan resolved none (the add-on " +
							"is not installed, its version could not be read, or nothing on this path " +
							"requires moving it)"})
				}
				continue
			}
			v := rule.AppliesAtVersion
			if !catalog.IsParseable(v) {
				continue
			}
			if lo := catalog.AddonMinor(hop.InstalledVersion); lo != "" && catalog.CompareVersions(v, lo) <= 0 {
				continue
			}
			if hi := catalog.AddonMinor(hop.RequiredVersion); hi != "" && catalog.CompareVersions(v, hi) > 0 {
				continue
			}
		}
		sel.rules = append(sel.rules, rule)
	}
	sort.Slice(sel.skipped, func(i, j int) bool { return sel.skipped[i].source < sel.skipped[j].source })
	return sel
}

// hopTarget is the version an advisory is headed for: the Kubernetes target, or the add-on's
// required version for an add-on rule.
func hopTarget(rule catalog.GeneratedRule, targetVersion string, hops Hops) string {
	if catalog.SourceScoping(rule.SourceID) == catalog.ScopedToAddonHop {
		if hop, ok := hops[rule.SourceID]; ok {
			return rule.SourceID + " " + hop.RequiredVersion
		}
	}
	return targetVersion
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
	kind      string
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
			out = append(out, row{kind: kind, ref: n.Name, name: n.Name, labels: n.Labels, status: n.Status})
		}
		return out, rowsRead, ""
	}
	if kind == "CustomResourceDefinition" {
		if !inv.Read(inventory.CollectorCRDs) {
			return nil, rowsUnread, inv.Collected[inventory.CollectorCRDs].Reason
		}
		out := make([]row, 0, len(inv.CRDs))
		for _, crd := range inv.CRDs {
			out = append(out, row{kind: kind, ref: crd.Name, name: crd.Name, spec: inventory.CRDSpec(crd)})
		}
		return out, rowsRead, ""
	}
	if rows, ok := inv.CRs[kind]; ok {
		out := make([]row, 0, len(rows))
		for _, cr := range rows {
			out = append(out, row{
				kind: kind, ref: cr.Ref(), namespace: cr.Namespace, name: cr.Name, labels: cr.Labels,
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
// name filters. applies is false when the rule does not apply here (no kind served); a
// non-empty decline names the first kind that could not be read. unfiltered counts the rows
// before the name filter, so a clear can say what it looked at.
func subject(inv *inventory.Inventory, d catalog.Detection) (rows []row, applies bool, unfiltered int, decline outcome) {
	var namePattern *regexp.Regexp
	if d.ObjectName != "" {
		p, err := regexp.Compile(d.ObjectName)
		if err != nil {
			return nil, true, 0, declinedFor(d.ObjectKind, "rule objectName is not a valid regex: "+d.ObjectName, "")
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
			return nil, true, 0, declinedFor(kind, reason, verifyList(kind))
		}
		servedSomewhere = true
		for _, r := range got {
			if d.Namespace != "" && r.namespace != d.Namespace {
				continue
			}
			unfiltered++
			if namePattern != nil && !namePattern.MatchString(r.name) {
				continue
			}
			rows = append(rows, r)
		}
	}
	return rows, servedSomewhere, unfiltered, outcome{}
}

func verifyList(kind string) string {
	return "kubectl get " + strings.ToLower(kind) + " --all-namespaces"
}

// ---------- row predicates ----------

// rowRule settles every row-scanning detection kind: gather the subject, apply the predicate to
// each row, name the hits.
//
// A name-scoped rule (objectName) reads ONE subject, and a kind that is served and read but
// holds no row of that name cannot answer a question about the object's content. That is a
// decline ("absence is not clean"), except for KIND_PRESENT, whose question is exactly whether
// an object so named exists.
func rowRule(inv *inventory.Inventory, d catalog.Detection) outcome {
	m, err := newMatcher(d)
	if err != nil {
		return declinedFor(d.ObjectKind, err.Error(), "")
	}
	rows, applies, _, decline := subject(inv, d)
	if decline.isDeclined {
		return decline
	}
	if !applies {
		return clear()
	}
	if len(rows) == 0 && d.ObjectName != "" && d.Kind != catalog.DetectKindPresent {
		return declinedFor(d.ObjectKind, "no "+d.ObjectKind+" named /"+d.ObjectName+"/ was found, and this rule "+
			"asks about that object's content; absence is not clean", verifyList(d.ObjectKind))
	}
	var hits []row
	var evidence []string
	for _, r := range rows {
		if hit, note := m.matches(r); hit {
			hits = append(hits, r)
			if note != "" && len(evidence) < maxNamed {
				evidence = append(evidence, note)
			}
		}
	}
	if len(hits) == 0 {
		return clear()
	}
	out := fired(m.describe(len(hits)), refs(hits), len(hits))
	out.evidence = append(out.evidence, evidence...)
	return out
}

// matcher is one detection kind applied to one row. The same predicate decides a detection, a
// scope hint and a gate, so the three cannot drift apart.
type matcher struct {
	d       catalog.Detection
	pattern *regexp.Regexp
}

func newMatcher(d catalog.Detection) (matcher, error) {
	m := matcher{d: d}
	if d.Kind == catalog.DetectSpecPathMatches {
		p, err := regexp.Compile(d.Value)
		if err != nil {
			return m, fmt.Errorf("rule value is not a valid regex: %s", d.Value)
		}
		m.pattern = p
	}
	return m, nil
}

// matches reports whether the row satisfies the predicate, with an optional per-row note for
// the evidence.
func (m matcher) matches(r row) (bool, string) {
	d := m.d
	switch d.Kind {
	case catalog.DetectKindPresent:
		return true, ""
	case catalog.DetectLabelKeyPresent:
		var keys []string
		for k := range r.labels {
			keys = append(keys, k)
		}
		if hit := matchKey(keys, d.Target); hit != "" {
			if hit != d.Target {
				return true, r.ref + " (matched " + hit + ")"
			}
			return true, ""
		}
	case catalog.DetectAnnotationKeyPresent:
		if hit := matchKey(append([]string{}, r.annKeys...), d.Target); hit != "" {
			if hit != d.Target {
				return true, r.ref + " (matched " + hit + ")"
			}
			return true, ""
		}
	case catalog.DetectSpecFieldPresent, catalog.DetectSpecFieldEquals:
		for _, section := range []map[string]any{r.spec, r.status} {
			v, ok := section[d.Target]
			if !ok || v == nil {
				continue
			}
			if d.Kind == catalog.DetectSpecFieldPresent || valueMatches(v, d.Value) {
				return true, ""
			}
		}
	case catalog.DetectSpecPathMatches:
		segments := strings.Split(d.Target, ".")
		for _, section := range []map[string]any{r.spec, r.status} {
			if section == nil {
				continue
			}
			for _, leaf := range leavesAt(section, segments) {
				if m.pattern.MatchString(leaf) {
					return true, ""
				}
			}
		}
	case catalog.DetectImageRepositoryPresent:
		for _, image := range images(r.spec) {
			if strings.Contains(image, d.Target) {
				return true, r.ref + " (" + image + ")"
			}
		}
	}
	return false, ""
}

// describe is the evidence sentence for n hits.
func (m matcher) describe(n int) string {
	d := m.d
	switch d.Kind {
	case catalog.DetectKindPresent:
		return fmt.Sprintf("%d %s object(s) present", n, d.ObjectKind)
	case catalog.DetectLabelKeyPresent:
		return fmt.Sprintf("label key %s present on %d %s object(s)", d.Target, n, d.ObjectKind)
	case catalog.DetectAnnotationKeyPresent:
		return fmt.Sprintf("annotation key %s present on %d %s object(s)", d.Target, n, d.ObjectKind)
	case catalog.DetectSpecFieldPresent:
		return fmt.Sprintf("field %s present on %d %s object(s)", d.Target, n, d.ObjectKind)
	case catalog.DetectSpecFieldEquals:
		return fmt.Sprintf("field %s=%s on %d %s object(s)", d.Target, d.Value, n, d.ObjectKind)
	case catalog.DetectSpecPathMatches:
		return fmt.Sprintf("%s matches /%s/ on %d %s object(s)", d.Target, d.Value, n, d.ObjectKind)
	case catalog.DetectImageRepositoryPresent:
		return fmt.Sprintf("%d %s object(s) run an image from %s", n, d.ObjectKind, d.Target)
	}
	return fmt.Sprintf("%d %s object(s) match", n, d.ObjectKind)
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

// leavesAt walks a dotted path where a segment ending in "[]" means each element, and returns
// every scalar found at the end as text.
//
// A MAP at the end of the path (a workload's nodeSelector, any labels-shaped map) yields one
// "key=value" string per scalar entry and the bare key for a nested one: the keys of such maps
// carry dots (karpenter.sh/provisioner-name), so no dotted path can step INTO them, and this is
// the only way a rule can name a key, a value, or the pair. Same reading as the hosted product.
func leavesAt(node any, segments []string) []string {
	if len(segments) == 0 {
		switch v := node.(type) {
		case nil:
			return nil
		case map[string]any:
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			var out []string
			for _, k := range keys {
				switch child := v[k].(type) {
				case map[string]any, []any:
					out = append(out, k)
				case nil:
					out = append(out, k)
				default:
					out = append(out, k+"="+fmt.Sprint(child))
				}
			}
			return out
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

// images is every container image in a projected workload spec.
func images(spec map[string]any) []string {
	var out []string
	for _, key := range []string{"containers", "initContainers"} {
		list, _ := spec[key].([]any)
		for _, c := range list {
			m, _ := c.(map[string]any)
			if image, _ := m["image"].(string); image != "" {
				out = append(out, image)
			}
		}
	}
	return out
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
	return fired(fmt.Sprintf("%d CRD(s) serve version %s", len(affected), d.Target), capNamed(affected), len(affected))
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
	rows, applies, _, decline := subject(inv, d)
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

// versionSkew settles the skew policy: a kubelet (every node) or kube-proxy (the kube-system
// DaemonSet's image tag) more than d.Value minors behind the target.
//
// Both branches count what was actually READ. A cluster with no kube-proxy DaemonSet told us
// nothing about its proxy version: k3s and several managed distributions run the proxy inside
// the node agent, so the absent DaemonSet is the common case, and reporting it as "within the
// window" would be the empty-collection clear this tool exists to prevent.
func versionSkew(inv *inventory.Inventory, d catalog.Detection, targetVersion string) outcome {
	targetKey := catalog.MinorKey(targetVersion)
	maxAllowed := 0
	if _, err := fmt.Sscanf(strings.TrimSpace(d.Value), "%d", &maxAllowed); err != nil || targetKey == 0 {
		return declinedFor("version skew", "the skew rule's value "+d.Value+" or the target version "+targetVersion+" is not a number", "")
	}
	subjectName := strings.ToLower(d.Target)
	var affected []string
	if strings.Contains(subjectName, "kube-proxy") {
		if !inv.Read(inventory.CollectorWorkloads) {
			return declinedFor("kube-proxy", inv.Collected[inventory.CollectorWorkloads].Reason, "kubectl -n kube-system get daemonset kube-proxy -o wide")
		}
		named, readable := 0, 0
		for _, w := range inv.Workloads {
			if w.Kind != "DaemonSet" || w.Namespace != "kube-system" || !strings.HasPrefix(w.Name, "kube-proxy") {
				continue
			}
			named++
			for _, c := range w.Containers {
				key := catalog.MinorKey(imageTag(c.Image))
				if key == 0 {
					continue
				}
				readable++
				if behind := targetKey - key; behind > maxAllowed {
					affected = append(affected, fmt.Sprintf("%s (%s, %d minors behind target)", w.Ref(), c.Image, behind))
				}
			}
		}
		switch {
		case named == 0:
			return declinedFor("kube-proxy", "no kube-proxy DaemonSet in kube-system: this distribution runs the proxy inside "+
				"the node agent (k3s and some managed control planes do), so its version cannot be read", "kubectl -n kube-system get daemonset -o wide")
		case readable == 0:
			return declinedFor("kube-proxy", fmt.Sprintf("the %d kube-proxy DaemonSet(s) in kube-system carry no image tag that parses as a version", named),
				"kubectl -n kube-system get daemonset kube-proxy -o jsonpath='{.spec.template.spec.containers[*].image}'")
		case len(affected) == 0:
			return clear()
		}
		return fired(fmt.Sprintf("kube-proxy more than %d minors behind the target", maxAllowed), capNamed(affected), len(affected))
	}
	if !inv.Read(inventory.CollectorNodes) {
		return declinedFor("Node", inv.Collected[inventory.CollectorNodes].Reason, "kubectl get nodes -o wide")
	}
	readable := 0
	for _, n := range inv.Nodes {
		key := catalog.MinorKey(n.KubeletVersion)
		if key == 0 {
			continue
		}
		readable++
		if behind := targetKey - key; behind > maxAllowed {
			affected = append(affected, fmt.Sprintf("%s (kubelet %s, %d minors behind target)", n.Name, n.KubeletVersion, behind))
		}
	}
	switch {
	case readable == 0:
		return declinedFor("Node", fmt.Sprintf("none of the %d nodes reports a kubelet version that parses", len(inv.Nodes)), "kubectl get nodes -o wide")
	case len(affected) == 0:
		return clear()
	}
	return fired(fmt.Sprintf("kubelets more than %d minors behind the target", maxAllowed), capNamed(affected), len(affected))
}

// imageTag returns the tag of an image reference, or "" for a digest-pinned or untagged one.
func imageTag(image string) string {
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at]
	}
	colon := strings.LastIndex(image, ":")
	if colon < 0 || strings.LastIndex(image, "/") > colon {
		return ""
	}
	return image[colon+1:]
}

// ---------- gates ----------

// gated applies a rule's precondition to a settled detection.
//
// The gate reuses the hint vocabulary and settles nothing by itself. No object satisfies it:
// the rule clears, with the precondition stated in the evidence of nothing (a clear prints no
// line). Its kind could not be read: the rule declines, because a precondition that cannot be
// checked leaves the rule unsettled. Satisfied: the detection stands, and when the gate reads
// the SAME single kind the detection does, the finding is narrowed to the objects that opened
// the gate, so it never names an object the precondition does not cover.
func gated(inv *inventory.Inventory, rule catalog.GeneratedRule, out outcome) outcome {
	g := rule.Gate
	gd := catalog.Detection{Kind: g.Kind, ObjectKind: g.ObjectKind, Namespace: g.Namespace,
		ObjectName: g.ObjectName, Target: g.Target, Value: g.Value}
	what := g.Kind + " " + g.ObjectKind
	if g.Target != "" {
		what += " " + g.Target
	}
	if g.Value != "" {
		what += " " + g.Value
	}
	m, err := newMatcher(gd)
	if err != nil {
		return declinedFor(g.ObjectKind, "gate "+err.Error(), "")
	}
	rows, applies, _, decline := subject(inv, gd)
	if decline.isDeclined {
		decline.declined = "the precondition (" + what + ") could not be checked: " + decline.declined
		return decline
	}
	if !applies {
		// The gate's kind is not served here at all, so nothing can satisfy it.
		return clear()
	}
	opened := map[string]bool{}
	var openedRefs []string
	for _, r := range rows {
		if hit, _ := m.matches(r); hit {
			opened[r.ref] = true
			openedRefs = append(openedRefs, r.ref)
		}
	}
	if len(opened) == 0 {
		return clear()
	}
	if !out.fired {
		return out
	}
	sort.Strings(openedRefs)
	named := strings.Join(capTo(openedRefs, 3), ", ")
	if len(openedRefs) > 3 {
		named += ", …"
	}
	met := fmt.Sprintf(" (precondition met by %d %s: %s)", len(openedRefs), g.ObjectKind, named)
	detKinds, gateKinds := rule.Detection.ObjectKinds(), gd.ObjectKinds()
	sameKind := len(detKinds) == 1 && len(gateKinds) == 1 && detKinds[0] == gateKinds[0] &&
		rowScanning(rule.Detection.Kind)
	if !sameKind {
		out.evidence[0] += met
		return out
	}
	var narrowed []string
	for _, a := range out.affected {
		if opened[a] {
			narrowed = append(narrowed, a)
		}
	}
	if len(narrowed) == 0 {
		if len(out.affected) >= maxNamed {
			// The named list is truncated, so the objects that opened the gate may simply sit
			// past the cap. Clearing on that would be a false clean.
			out.evidence[0] += met + fmt.Sprintf(" — more than %d objects matched, so the list is truncated "+
				"and could not be narrowed to the precondition; check each against %s", maxNamed, what)
			return out
		}
		return clear()
	}
	if len(narrowed) < len(out.affected) {
		met += fmt.Sprintf(" — narrowed from %d detected object(s) to those meeting the precondition", len(out.affected))
	}
	out.affected, out.matched = narrowed, len(narrowed)
	out.evidence[0] += met
	return out
}

func rowScanning(kind string) bool {
	switch kind {
	case catalog.DetectKindPresent, catalog.DetectAnnotationKeyPresent, catalog.DetectLabelKeyPresent,
		catalog.DetectSpecFieldPresent, catalog.DetectSpecFieldEquals, catalog.DetectSpecPathMatches,
		catalog.DetectImageRepositoryPresent:
		return true
	}
	return false
}

// ---------- duplicates ----------

// foldDuplicates marks a later fired rule that is the SAME CHANGE on the SAME objects as an
// earlier one as a duplicate of it.
//
// A vendor repeats a note per release branch (Argo CD's redis NetworkPolicy at 2.9/2.10/2.11),
// and a deprecation and its later removal ship under one slug. A hop that crosses several of
// them fires each on the same objects; printing each would count one problem several times.
// Same change means: the same slug (rule id minus its version) with the same detection, or the
// same quote, on the same named objects. The retained entry is the MOST SEVERE, then the
// EARLIEST version (numeric order, "2.9" before "2.10"), then list order, so a
// deprecation-then-removal pair keeps the removal's card. Same fold as the hosted product.
func foldDuplicates(outcomes []ruleOutcome) {
	order := make([]int, 0, len(outcomes))
	for i := range outcomes {
		order = append(order, i)
	}
	sort.SliceStable(order, func(x, y int) bool {
		a, b := outcomes[order[x]].rule, outcomes[order[y]].rule
		if ra, rb := a.Severity.Rank(), b.Severity.Rank(); ra != rb {
			return ra > rb
		}
		if c := catalog.CompareVersions(a.AppliesAtVersion, b.AppliesAtVersion); c != 0 {
			return c < 0
		}
		return order[x] < order[y]
	})
	seen := map[string]int{}
	for _, i := range order {
		o := &outcomes[i]
		if o.advisory || !o.out.fired {
			continue
		}
		objects := strings.Join(sortedCopy(o.out.affected), "\x01")
		d := o.rule.Detection
		keys := []string{
			"d|" + o.rule.Slug() + "|" + d.Kind + "|" + d.ObjectKind + "|" + d.Namespace + "|" + d.ObjectName + "|" + d.Target + "|" + d.Value + "|" + objects,
			"q|" + o.rule.Quote + "|" + objects,
		}
		dup := -1
		for _, k := range keys {
			if j, ok := seen[k]; ok {
				dup = j
				break
			}
		}
		if dup >= 0 {
			o.duplicateOf = outcomes[dup].rule.RuleID
			outcomes[dup].alsoRaisedBy = append(outcomes[dup].alsoRaisedBy, o.rule.RuleID+" (at "+o.rule.AppliesAtVersion+")")
			continue
		}
		for _, k := range keys {
			seen[k] = i
		}
	}
}

// ---------- findings ----------

func finding(rule catalog.GeneratedRule, clusterName string, out outcome, alsoRaisedBy []string) report.Finding {
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
	if len(alsoRaisedBy) > 0 {
		evidence = append(evidence, "same change also raised by "+strings.Join(alsoRaisedBy, ", ")+"; counted once")
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
		AppliesAtVersion:  rule.AppliesAtVersion,
		VerifyCommand:     verify,
		AffectedResources: out.affected,
		Quote:             rule.Quote,
		Evidence:          evidence,
		RuleSource:        rule.SourceID,
	}
}

// advisory renders a NOT_DETECTABLE rule the way the advisory catalog renders its own: INFO,
// no score, the reason it cannot be checked, and any hint the scan can add about where to look.
func advisory(rule catalog.GeneratedRule, inv *inventory.Inventory, target string) report.Finding {
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
		Title:            rule.Title + " [target " + target + "]",
		Recommendation:   recommendation,
		Category:         "RELIABILITY",
		Severity:         catalog.SeverityInfo,
		ScoreImpact:      0,
		ResourceName:     inv.ClusterName,
		ResourceType:     "Cluster",
		EnforcementLevel: "advisory",
		VerifyCommand:    verify,
		AppliesAtVersion: rule.AppliesAtVersion,
		Quote:            rule.Quote,
		Evidence:         hint(rule.Scope, inv),
		RuleSource:       rule.SourceID,
	}
}

// hint names what a scope hint points at, using whatever this scan happened to collect. A hint
// settles nothing, so a kind that was not read simply adds no line, and a broad hint is a
// longer list rather than a false claim.
func hint(scope *catalog.ScopeHint, inv *inventory.Inventory) []string {
	if scope == nil {
		return nil
	}
	d := catalog.Detection{Kind: scope.Kind, ObjectKind: scope.ObjectKind, Namespace: scope.Namespace,
		ObjectName: scope.ObjectName, Target: scope.Target, Value: scope.Value}
	m, err := newMatcher(d)
	if err != nil {
		return nil
	}
	var named []string
	rows, applies, _, decline := subject(inv, d)
	switch {
	case decline.isDeclined || !applies:
		// Fall back to the typed collectors for the two shapes they can answer.
		switch scope.Kind {
		case catalog.DetectKindPresent:
			n := 0
			for _, kind := range d.ObjectKinds() {
				n += typedCount(inv, kind)
			}
			if n > 0 {
				return []string{fmt.Sprintf("hint: %d %s object(s) to review", n, scope.ObjectKind)}
			}
		case catalog.DetectImageRepositoryPresent:
			for _, w := range inv.Workloads {
				if !contains(d.ObjectKinds(), w.Kind) {
					continue
				}
				for _, c := range append(append([]inventory.Container{}, w.Containers...), w.InitContainers...) {
					if strings.Contains(c.Image, scope.Target) {
						named = append(named, w.Namespace+"/"+w.Name)
						break
					}
				}
			}
		}
	default:
		for _, r := range rows {
			if hit, _ := m.matches(r); hit {
				named = append(named, r.ref)
			}
		}
	}
	if len(named) == 0 {
		return nil
	}
	sort.Strings(named)
	return []string{fmt.Sprintf("hint: %d %s object(s) to review: %s", len(named), scope.ObjectKind,
		strings.Join(capNamed(named), ", "))}
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

// valueMatches compares a field against the rule's value: scalars as trimmed, case-insensitive
// text; containers on their compact JSON, which is how the hosted product compares them.
func valueMatches(field any, want string) bool {
	switch field.(type) {
	case map[string]any, []any:
		b, err := json.Marshal(field)
		return err == nil && strings.EqualFold(strings.TrimSpace(string(b)), strings.TrimSpace(want))
	}
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

func capNamed(items []string) []string { return capTo(items, maxNamed) }

func capTo(items []string, n int) []string {
	if len(items) > n {
		return items[:n]
	}
	return items
}

func sortedCopy(items []string) []string {
	out := append([]string{}, items...)
	sort.Strings(out)
	return out
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}
