// Package addons answers the question a Kubernetes upgrade actually turns on for most teams:
// does the third-party software already running in this cluster support the version you are
// moving to.
//
// Vendors publish this badly and inconsistently. Some ship a clean compatibility matrix, some
// bury it in a release note, some publish nothing at all. So the verdict has six states rather
// than two, and they are never collapsed: "supported", "too old", "too new", "the vendor
// publishes no matrix", "we could not read your installed version", and "your version is not
// in the vendor's table". A report that turned the last four into a green tick would be
// lying about the only question the reader asked.
package addons

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/eval/addons/predicates"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

// Verdicts for an add-on against the target Kubernetes version.
const (
	VerdictSupported           = "SUPPORTED"
	VerdictAboveMax            = "ABOVE_MAX"
	VerdictBelowMin            = "BELOW_MIN"
	VerdictNoVendorData        = "NO_VENDOR_DATA"
	VerdictVersionUnresolved   = "VERSION_UNRESOLVED"
	VerdictVersionNotInCatalog = "VERSION_NOT_IN_CATALOG"
)

// staleAfterDays is how long a hand-transcribed vendor table is treated as current.
//
// Past it the coverage row says the catalog may be out of date. Findings are never suppressed
// or downgraded for age: a possibly-stale ceiling still beats no signal at all.
const staleAfterDays = 180

// Result is everything the add-on tier produced.
type Result struct {
	Findings []report.Finding
	Addons   []report.AddonStatus
	Coverage []report.Coverage
}

// Analyze detects installed add-ons and judges them against the target version.
func Analyze(inv *inventory.Inventory, currentVersion, targetVersion string, addons []catalog.Addon, now time.Time) Result {
	var result Result
	if catalog.MinorKey(targetVersion) == 0 {
		return result
	}

	if !inv.Read(inventory.CollectorWorkloads) {
		reason := "workloads could not be listed, so no add-on could be detected"
		if state, ok := inv.Collected[inventory.CollectorWorkloads]; ok && state.Reason != "" {
			reason = state.Reason
		}
		result.Coverage = append(result.Coverage, report.Coverage{
			Source: "add-on compatibility", State: report.CoverageUnavailable,
			Reason: reason, RulesSkipped: len(addons),
			VerifyCommand: "kubectl get deploy,sts,ds -A -o wide",
		})
		return result
	}

	detected := detect(inv, addons)
	if len(detected) == 0 {
		result.Coverage = append(result.Coverage, report.Coverage{
			Source: "add-on compatibility", State: report.CoverageComplete,
			Reason: "none of the catalogued add-ons are installed in this cluster",
		})
		return result
	}

	var detectedIDs []string
	for _, d := range detected {
		detectedIDs = append(detectedIDs, d.addon.AddonID)
	}
	stale := map[string]bool{}
	for _, id := range catalogStale(addons, detectedIDs, now) {
		stale[id] = true
	}

	registry := predicates.Registry()
	var skipped []skippedRule

	for _, d := range detected {
		status, findings := judge(inv, d, currentVersion, targetVersion, registry, &skipped)
		status.Stale = stale[d.addon.AddonID]
		result.Addons = append(result.Addons, status)
		result.Findings = append(result.Findings, findings...)
	}

	sort.Slice(result.Addons, func(i, j int) bool { return result.Addons[i].AddonID < result.Addons[j].AddonID })

	state, reason := report.CoverageComplete, ""
	if len(stale) > 0 {
		names := make([]string, 0, len(stale))
		for id := range stale {
			names = append(names, id)
		}
		sort.Strings(names)
		state = report.CoveragePartial
		reason = fmt.Sprintf("the vendor data for %s was last checked more than %d days ago and may be out of date",
			strings.Join(names, ", "), staleAfterDays)
	}
	result.Coverage = append(result.Coverage, report.Coverage{
		Source: "add-on compatibility", State: state, Reason: reason,
		Scope: fmt.Sprintf("%d detected", len(detected)),
	})
	// A rule that could not evaluate gets its own row. Without this a cluster whose custom
	// resources were unreadable produced the same silent output as one where every rule ran and
	// found nothing.
	result.Coverage = append(result.Coverage, skippedCoverage(skipped)...)

	return result
}

// skippedRule records a rule that could not be evaluated, and why.
type skippedRule struct {
	addonID string
	ruleID  string
	reason  string
}

// skippedCoverage folds skipped rules into one row per reason, so an add-on whose whole custom
// resource read failed does not print a line per rule.
func skippedCoverage(skipped []skippedRule) []report.Coverage {
	if len(skipped) == 0 {
		return nil
	}
	byReason := map[string][]string{}
	var order []string
	for _, s := range skipped {
		if _, seen := byReason[s.reason]; !seen {
			order = append(order, s.reason)
		}
		byReason[s.reason] = append(byReason[s.reason], s.addonID+"/"+s.ruleID)
	}
	sort.Strings(order)

	out := make([]report.Coverage, 0, len(order))
	for _, reason := range order {
		rules := byReason[reason]
		sort.Strings(rules)
		out = append(out, report.Coverage{
			Source:       "add-on rules",
			Scope:        strings.Join(rules, ", "),
			State:        report.CoverageUnavailable,
			Reason:       reason,
			RulesSkipped: len(rules),
		})
	}
	return out
}

// detection is one add-on found running, with how its version was established.
type detection struct {
	addon         catalog.Addon
	version       string
	versionSource string
	workloadRef   string
	namespace     string
}

// detect finds which catalogued add-ons are running, by container image.
//
// The match is a suffix on the image's repository path, never the whole reference: the same
// software is published to a dozen registries and mirrored into private ones, and the trailing
// path is the part that stays stable.
func detect(inv *inventory.Inventory, addons []catalog.Addon) []detection {
	var out []detection

	for _, addon := range addons {
		found := false
		for _, w := range inv.Workloads {
			if found {
				break
			}
			for _, c := range append(append([]inventory.Container{}, w.Containers...), w.InitContainers...) {
				if !matchesImage(c.Image, addon.Detect.ImageSuffixes) {
					continue
				}
				d := detection{addon: addon, workloadRef: w.Ref(), namespace: w.Namespace}
				if tag := imageTag(c.Image); catalog.IsParseable(tag) {
					d.version, d.versionSource = tag, "imageTag"
				} else if label := w.Labels["app.kubernetes.io/version"]; catalog.IsParseable(label) {
					// The image tag is the better source, but plenty of clusters run digest-pinned
					// images where it says nothing at all.
					d.version, d.versionSource = label, "label"
				}
				out = append(out, d)
				found = true
				break
			}
		}
	}
	return out
}

func matchesImage(image string, suffixes []string) bool {
	repo := strings.ToLower(repositoryOf(image))
	if repo == "" {
		return false
	}
	for _, suffix := range suffixes {
		if strings.HasSuffix(repo, strings.ToLower(suffix)) {
			return true
		}
	}
	return false
}

// repositoryOf strips the tag and digest, leaving the repository path.
func repositoryOf(image string) string {
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at]
	}
	if colon := strings.LastIndex(image, ":"); colon >= 0 {
		if slash := strings.LastIndex(image, "/"); slash < colon {
			image = image[:colon]
		}
	}
	return image
}

// imageTag returns the tag, treating a registry port as what it is rather than as a version.
func imageTag(image string) string {
	if at := strings.Index(image, "@"); at >= 0 {
		image = image[:at]
	}
	colon := strings.LastIndex(image, ":")
	if colon < 0 {
		return ""
	}
	if slash := strings.LastIndex(image, "/"); slash > colon {
		return ""
	}
	return image[colon+1:]
}

// judge produces one add-on's status and any findings its rules raise.
func judge(inv *inventory.Inventory, d detection, currentVersion, targetVersion string,
	registry map[string]predicates.Predicate, skipped *[]skippedRule) (report.AddonStatus, []report.Finding) {

	verdict, window, minimumFix := evaluateWindows(d.addon.SupportWindows, d.version, targetVersion)

	status := report.AddonStatus{
		AddonID:           d.addon.AddonID,
		DisplayName:       displayName(d.addon),
		InstalledVersion:  d.version,
		VersionSource:     d.versionSource,
		WorkloadRef:       d.workloadRef,
		Verdict:           verdict,
		MinimumVersionFix: minimumFix,
		SourceURL:         d.addon.Source.URL,
	}
	if window != nil {
		status.MinK8s, status.MaxK8s = window.MinK8s, window.MaxK8s
	}
	status.UpgradeNotes = notesOnPath(d.addon, d.version)

	findings := windowFinding(d, status, targetVersion)
	findings = append(findings, ruleFindings(inv, d, registry, skipped)...)
	return status, findings
}

// evaluateWindows compares the installed version against the vendor's published matrix.
func evaluateWindows(windows []catalog.SupportWindow, installed, targetK8s string) (string, *catalog.SupportWindow, string) {
	if len(windows) == 0 {
		return VerdictNoVendorData, nil, ""
	}
	if !catalog.IsParseable(installed) {
		return VerdictVersionUnresolved, nil, ""
	}
	targetKey := catalog.MinorKey(targetK8s)
	if targetKey == 0 {
		return VerdictVersionNotInCatalog, nil, ""
	}

	window := mostSpecific(windows, installed)
	if window == nil {
		return VerdictVersionNotInCatalog, nil, minimumCovering(windows, targetKey)
	}
	minKey, maxKey := catalog.MinorKey(window.MinK8s), catalog.MinorKey(window.MaxK8s)
	if minKey == 0 && maxKey == 0 {
		return VerdictVersionNotInCatalog, window, ""
	}
	// A window may be open at either end, which is how a vendor says "supported from here on"
	// or "no floor". Treating an absent bound as unparseable would flip a genuinely supported
	// add-on into an unknown.
	switch {
	case maxKey != 0 && targetKey > maxKey:
		return VerdictAboveMax, window, minimumCovering(windows, targetKey)
	case minKey != 0 && targetKey < minKey:
		return VerdictBelowMin, window, minimumCovering(windows, targetKey)
	default:
		return VerdictSupported, window, ""
	}
}

// mostSpecific picks the narrowest catalog row that prefixes the installed version.
//
// Vendors publish overlapping rows: a "1.0" line covering the series and a "1.0.5" line for
// one patch that widened the ceiling. The more specific row has to win, or every 1.0.x release
// silently inherits a Kubernetes version it was never tested against.
func mostSpecific(windows []catalog.SupportWindow, installed string) *catalog.SupportWindow {
	var best *catalog.SupportWindow
	bestSpecificity := -1
	for i := range windows {
		w := &windows[i]
		if !catalog.IsPrefixOf(w.Version, installed) {
			continue
		}
		if s := catalog.Specificity(w.Version); s > bestSpecificity {
			best, bestSpecificity = w, s
		}
	}
	return best
}

// minimumCovering is the lowest catalogued add-on version whose window covers the target, which
// is the vendor's own answer to "what do I upgrade this to first".
func minimumCovering(windows []catalog.SupportWindow, targetKey int) string {
	best := ""
	for _, w := range windows {
		lo, hi := catalog.MinorKey(w.MinK8s), catalog.MinorKey(w.MaxK8s)
		if lo == 0 && hi == 0 {
			continue
		}
		if (lo != 0 && targetKey < lo) || (hi != 0 && targetKey > hi) {
			continue
		}
		if best == "" || catalog.CompareVersions(w.Version, best) < 0 {
			best = w.Version
		}
	}
	return best
}

// windowFinding turns a non-supported verdict into a finding.
//
// Every state except SUPPORTED produces one, including the three that mean "we do not know".
// Those are INFO and score nothing, but they appear, because an add-on we could not judge is
// not an add-on that passed.
func windowFinding(d detection, status report.AddonStatus, targetVersion string) []report.Finding {
	if status.Verdict == VerdictSupported {
		return nil
	}

	name := displayName(d.addon)
	var (
		severity    = catalog.SeverityInfo
		title       string
		explanation string
	)

	switch status.Verdict {
	case VerdictAboveMax:
		severity = catalog.SeverityHigh
		title = fmt.Sprintf("%s %s does not support Kubernetes %s", name, d.version, targetVersion)
		explanation = fmt.Sprintf("The vendor's table gives %s %s a ceiling of Kubernetes %s.",
			name, d.version, status.MaxK8s)
		if status.MinimumVersionFix != "" {
			explanation += fmt.Sprintf(" Upgrade %s to at least %s before upgrading Kubernetes.", name, status.MinimumVersionFix)
		} else {
			explanation += " The vendor's table lists no version that supports the target, so check for a newer release."
		}
	case VerdictBelowMin:
		severity = catalog.SeverityHigh
		title = fmt.Sprintf("%s %s is older than Kubernetes %s supports", name, d.version, targetVersion)
		explanation = fmt.Sprintf("The vendor's table gives this version a floor of Kubernetes %s.", status.MinK8s)
		if status.MinimumVersionFix != "" {
			explanation += fmt.Sprintf(" Upgrade %s to at least %s.", name, status.MinimumVersionFix)
		}
	case VerdictNoVendorData:
		title = fmt.Sprintf("%s publishes no Kubernetes compatibility matrix", name)
		explanation = fmt.Sprintf("%s is installed, but the vendor does not publish a table of which "+
			"Kubernetes versions each release supports, so compatibility with %s could not be checked. "+
			"Read the release notes for the versions on your path.", name, targetVersion)
	case VerdictVersionUnresolved:
		title = fmt.Sprintf("%s is installed but its version could not be determined", name)
		explanation = fmt.Sprintf("The image for %s carries no parseable tag and the workload has no "+
			"version label, so its supported Kubernetes range could not be looked up. This usually means "+
			"a digest-pinned image.", name)
	case VerdictVersionNotInCatalog:
		title = fmt.Sprintf("%s %s is not listed in the vendor's compatibility table", name, d.version)
		explanation = fmt.Sprintf("The installed version does not appear in the vendor's published table, "+
			"so its support for Kubernetes %s could not be confirmed.", targetVersion)
		if status.MinimumVersionFix != "" {
			explanation += fmt.Sprintf(" The lowest listed version supporting the target is %s.", status.MinimumVersionFix)
		}
	}

	return []report.Finding{{
		ID:               report.NewID("rtz-addon-"+d.addon.AddonID+"-support", d.workloadRef),
		RuleID:           "rtz-addon-" + d.addon.AddonID + "-support",
		Title:            title,
		Recommendation:   explanation,
		Category:         "RELIABILITY",
		Severity:         severity,
		ScoreImpact:      severity.ScoreImpact(),
		ResourceName:     d.workloadRef,
		ResourceType:     d.addon.AddonID,
		AppliesAtVersion: catalog.MinorOf(targetVersion),
		SourceURL:        d.addon.Source.URL,
		Evidence:         []string{fmt.Sprintf("Detected %s from %s", displayVersion(d), d.workloadRef)},
	}}
}

// ruleFindings runs the add-on's predicate-backed rules.
func ruleFindings(inv *inventory.Inventory, d detection, registry map[string]predicates.Predicate, skipped *[]skippedRule) []report.Finding {
	if len(d.addon.Rules) == 0 {
		return nil
	}
	ctx := buildContext(inv, d)

	var findings []report.Finding
	for _, rule := range d.addon.Rules {
		if !gateAllows(rule, d.version) {
			continue
		}
		predicate, ok := registry[rule.Kind]
		if !ok {
			// Never silently dropped: a rule nobody implements is a gap in this build, and the
			// reader is told rather than shown a shorter list of checks.
			*skipped = append(*skipped, skippedRule{d.addon.AddonID, rule.RuleID,
				"this build does not implement the check the rule asks for"})
			continue
		}
		outcome := predicate.Evaluate(ctx, rule.Params)
		switch outcome.Outcome {
		case predicates.Declined:
			*skipped = append(*skipped, skippedRule{d.addon.AddonID, rule.RuleID, outcome.Reason})
			continue
		case predicates.Clear:
			continue
		}
		evidence := outcome.Evidence

		severity := rule.Severity
		if severity.Rank() == 0 {
			severity = catalog.SeverityMedium
		}
		impact := rule.ScoreImpact
		if impact == 0 {
			impact = severity.ScoreImpact()
		}

		recommendation := evidence + " " + rule.Recommendation
		if rule.Quote != "" {
			recommendation += fmt.Sprintf(" The vendor writes: %q", rule.Quote)
		}

		findings = append(findings, report.Finding{
			ID:             report.NewID(rule.RuleID, d.workloadRef),
			RuleID:         rule.RuleID,
			Title:          rule.Title,
			Recommendation: recommendation,
			Category:       "RELIABILITY",
			Severity:       severity,
			ScoreImpact:    impact,
			ResourceName:   d.workloadRef,
			ResourceType:   d.addon.AddonID,
			Quote:          rule.Quote,
			SourceURL:      rule.SourceURL,
			Evidence:       []string{evidence},
		})
	}
	return findings
}

// gateAllows applies a rule's version gates.
//
// The two gates are deliberately asymmetric. A floor needs the installed version to be provably
// at or above it. A ceiling needs it provably below: an unreadable version fails both, because
// a rule that fired on a version we could not parse would be an accusation with nothing behind
// it.
func gateAllows(rule catalog.AddonRule, installed string) bool {
	if rule.AppliesWhenVersionAtLeast != "" && !catalog.AtLeast(installed, rule.AppliesWhenVersionAtLeast) {
		return false
	}
	if rule.AppliesWhenVersionBelow != "" {
		if !catalog.IsParseable(installed) || catalog.AtLeast(installed, rule.AppliesWhenVersionBelow) {
			return false
		}
	}
	return true
}

// buildContext assembles the cluster data this add-on's predicates may read.
func buildContext(inv *inventory.Inventory, d detection) predicates.Context {
	ctx := predicates.Context{
		Label:             displayName(d.addon),
		InstalledVersion:  d.version,
		CRDNames:          map[string]bool{},
		CRDServedVersions: map[string]map[string]bool{},
		CRDFlags:          map[string]map[string]bool{},
		Rows:              map[string][]predicates.Row{},
		Labels:            map[string][]predicates.Row{},
	}

	if inv.Read(inventory.CollectorCRDs) {
		for _, crd := range inv.CRDs {
			name := strings.ToLower(crd.Name)
			ctx.CRDNames[name] = true
			versions := map[string]bool{}
			for _, v := range crd.ServedVersions {
				versions[v] = true
			}
			ctx.CRDServedVersions[name] = versions
			ctx.CRDFlags[name] = map[string]bool{
				"lastAppliedConfigurationPresent": crd.LastAppliedConfigurationPresent,
				"clientSideApplyManager":          crd.ClientSideApplyManager,
			}
		}
	}

	// Only kinds that were actually read are entered, so a predicate can tell an empty result
	// from an unread one.
	for _, declared := range d.addon.InventoryKinds {
		kind, scoped := splitKind(declared)
		rows, read := customRows(inv, kind, scoped, d.namespace)
		if read {
			ctx.Rows[kind] = rows
		}
	}

	for _, w := range inv.Workloads {
		ctx.Labels[w.Kind] = append(ctx.Labels[w.Kind], predicates.Row{
			Kind: w.Kind, Namespace: w.Namespace, Name: w.Name, Labels: w.Labels,
		})
	}
	return ctx
}

// splitKind separates a declared kind from its optional namespace scoping.
//
// A shared core kind such as ConfigMap is declared as "ConfigMap@namespace" so the read stays
// inside the add-on's own namespace rather than sweeping the cluster.
func splitKind(declared string) (string, bool) {
	kind, _, scoped := strings.Cut(declared, "@")
	return kind, scoped
}

// customRows returns instances of a kind, and whether the kind was readable at all.
func customRows(inv *inventory.Inventory, kind string, scoped bool, namespace string) ([]predicates.Row, bool) {
	switch kind {
	case "Ingress":
		if !inv.Read(inventory.CollectorIngresses) {
			return nil, false
		}
		rows := make([]predicates.Row, 0, len(inv.Ingresses))
		for _, ing := range inv.Ingresses {
			rows = append(rows, predicates.Row{
				Kind: "Ingress", Namespace: ing.Namespace, Name: ing.Name, AnnotationKeys: ing.AnnotationKeys,
			})
		}
		return rows, true

	case "ConfigMap":
		if !inv.Read(inventory.CollectorConfigMaps) {
			return nil, false
		}
		rows := make([]predicates.Row, 0, len(inv.CoreDNS))
		for _, cm := range inv.CoreDNS {
			if scoped && namespace != "" && cm.Namespace != namespace {
				continue
			}
			plugins := make([]any, 0, len(cm.Plugins))
			for _, p := range cm.Plugins {
				plugins = append(plugins, p)
			}
			rows = append(rows, predicates.Row{
				Kind: "ConfigMap", Namespace: cm.Namespace, Name: cm.Name,
				Spec: map[string]any{"corednsPlugins": plugins},
			})
		}
		return rows, true

	default:
		rows, ok := inv.CRs[kind]
		if !ok {
			return nil, false
		}
		out := make([]predicates.Row, 0, len(rows))
		for _, cr := range rows {
			out = append(out, predicates.Row{
				Kind: cr.Kind, Namespace: cr.Namespace, Name: cr.Name,
				Labels: cr.Labels, AnnotationKeys: cr.AnnotationKeys, Spec: cr.Spec,
			})
		}
		return out, true
	}
}

// notesOnPath returns the vendor's own breaking-change notes between the installed version and
// the newest one the catalog knows about.
//
// The ceiling falls back to LatestKnownVersion for add-ons with no support windows. Without
// that fallback an add-on publishing no matrix has no version anchor at all, and its notes
// would never render, which is exactly the add-on whose notes matter most.
func notesOnPath(addon catalog.Addon, installed string) []catalog.UpgradeNote {
	if len(addon.UpgradeNotes) == 0 {
		return nil
	}
	ceiling := addon.LatestKnownVersion
	for _, w := range addon.SupportWindows {
		if ceiling == "" || catalog.CompareVersions(w.Version, ceiling) > 0 {
			ceiling = w.Version
		}
	}
	if ceiling == "" {
		return nil
	}

	var out []catalog.UpgradeNote
	for _, note := range addon.UpgradeNotes {
		if catalog.CompareVersions(note.Version, ceiling) > 0 {
			continue
		}
		// With no readable installed version every note stays: the reader can filter by eye,
		// but a note dropped for a version we could not parse is gone silently.
		if catalog.IsParseable(installed) && catalog.CompareVersions(note.Version, installed) <= 0 {
			continue
		}
		out = append(out, note)
	}
	sort.SliceStable(out, func(i, j int) bool {
		return catalog.CompareVersions(out[i].Version, out[j].Version) < 0
	})
	return out
}

func catalogStale(addons []catalog.Addon, ids []string, now time.Time) []string {
	c := &catalog.Catalog{Addons: addons}
	return c.StaleAddons(ids, now, staleAfterDays)
}

func displayName(addon catalog.Addon) string {
	if addon.DisplayName != "" {
		return addon.DisplayName
	}
	return addon.AddonID
}

func displayVersion(d detection) string {
	if d.version == "" {
		return displayName(d.addon) + " (version unresolved)"
	}
	return displayName(d.addon) + " " + d.version
}
