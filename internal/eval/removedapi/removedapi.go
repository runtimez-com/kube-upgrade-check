// Package removedapi turns evidence of removed-API use into findings.
//
// The evidence itself is gathered elsewhere; this package decides what it means. The judgement
// that matters is the negative one: reporting nothing found is only honest when something
// actually looked. A resource type nobody could list produces a coverage gap, never a pass.
package removedapi

import (
	"fmt"
	"sort"
	"strings"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

const maxNamed = 50

// Analyze groups evidence by rule and produces one finding per removed API still in use.
func Analyze(usages []inventory.APIUsage, currentVersion, targetVersion string, cat *catalog.Catalog) []report.Finding {
	targetKey := catalog.MinorKey(targetVersion)
	if targetKey == 0 {
		return nil
	}

	type group struct {
		rule      catalog.DeprecationRule
		severity  catalog.Severity
		appliesAt string
		objects   map[string]bool
		tiers     map[string]bool
		evidence  map[string]bool
		allStale  bool
		seen      bool
	}
	groups := map[string]*group{}

	for _, u := range usages {
		rule, ok := lookup(cat, u.APIVersion, u.Kind)
		if !ok {
			continue
		}
		severity, appliesAt, fires := grade(rule, targetKey)
		if !fires {
			continue
		}

		key := rule.APIVersion + "|" + rule.Kind
		g, ok := groups[key]
		if !ok {
			g = &group{
				rule: rule, severity: severity, appliesAt: appliesAt,
				objects: map[string]bool{}, tiers: map[string]bool{}, evidence: map[string]bool{},
				allStale: true,
			}
			groups[key] = g
		}
		// A stronger tier wins the severity, matching how the two tiers rank: a per-object
		// write record outranks a cluster-wide request count.
		if severity.Rank() > g.severity.Rank() {
			g.severity, g.appliesAt = severity, appliesAt
		}
		g.tiers[u.Tier] = true
		g.evidence[u.Evidence] = true
		if ref := objectRef(u); ref != "" {
			g.objects[ref] = true
		}
		if !u.Stale {
			g.allStale = false
		}
		g.seen = true
	}

	var findings []report.Finding
	for _, g := range groups {
		if !g.seen {
			continue
		}
		objects := sortedKeys(g.objects)
		tiers := sortedKeys(g.tiers)
		evidence := sortedKeys(g.evidence)

		severity := g.severity
		recommendation := g.rule.Remediation
		// Evidence that has since been superseded still matters, because the record is what an
		// upgrade reads, but it is a weaker claim and the wording says so.
		if g.allStale && len(objects) > 0 {
			severity = downgrade(severity)
			recommendation += " These objects have since been rewritten at the current version, " +
				"so the old record may be a leftover. Confirm before treating it as blocking."
		}

		title := fmt.Sprintf("%s %s was removed in %s", g.rule.Kind, g.rule.APIVersion, g.rule.RemovedIn)
		if len(objects) == 0 {
			title = fmt.Sprintf("%s %s is still being requested, and was removed in %s",
				g.rule.Kind, g.rule.APIVersion, g.rule.RemovedIn)
		}

		findings = append(findings, report.Finding{
			ID:                report.NewID(g.rule.RuleID, firstOr(objects, g.rule.APIVersion)),
			RuleID:            g.rule.RuleID,
			Title:             title,
			Recommendation:    recommendation,
			Category:          "RELIABILITY",
			Severity:          severity,
			ScoreImpact:       severity.ScoreImpact(),
			ResourceName:      collapse(objects, g.rule.APIVersion),
			ResourceType:      g.rule.Kind,
			AffectedResources: capNamed(objects),
			AppliesAtVersion:  catalog.MinorOf(g.appliesAt),
			Evidence:          capNamed(evidence),
			Tiers:             tiers,
		})
	}

	report.Sort(findings)
	return findings
}

// ServedButUnused reports how many removed API versions this cluster still serves.
//
// Serving one proves the door is open; it proves nothing about whether anyone walked through it,
// which is why this can never produce a finding on its own. It earns a line in the report
// because "we scanned these and found no user" and "these are not present here at all" are
// different statements, and only one of them is evidence of anything.
func ServedButUnused(served map[string]bool, cat *catalog.Catalog, targetVersion string) report.Coverage {
	targetKey := catalog.MinorKey(targetVersion)
	if targetKey == 0 || len(served) == 0 {
		return report.Coverage{}
	}

	seen := map[string]bool{}
	var stillServed []string
	for _, rule := range cat.DeprecationRules {
		if key := catalog.MinorKey(rule.RemovedIn); key == 0 || key > targetKey {
			continue
		}
		if served[rule.APIVersion] && !seen[rule.APIVersion] {
			seen[rule.APIVersion] = true
			stillServed = append(stillServed, rule.APIVersion)
		}
	}
	if len(stillServed) == 0 {
		return report.Coverage{
			Source: "removed APIs", Scope: "still-served versions", State: report.CoverageComplete,
			Reason: "this cluster no longer serves any API version the target removes",
		}
	}
	sort.Strings(stillServed)
	return report.Coverage{
		Source: "removed APIs", Scope: "still-served versions", State: report.CoverageComplete,
		Reason: fmt.Sprintf("this cluster still serves %d API version(s) the target removes, "+
			"and objects on them were scanned: %s", len(stillServed), strings.Join(stillServed, ", ")),
	}
}

// lookup finds the rule for an apiVersion and kind, falling back to the detector table so a
// group-version removed wholesale is covered by one row.
func lookup(cat *catalog.Catalog, apiVersion, kind string) (catalog.DeprecationRule, bool) {
	if rule, ok := cat.DeprecationFor(apiVersion, kind); ok {
		return rule, true
	}
	life, ok := cat.LifecycleFor(apiVersion, kind)
	if !ok {
		return catalog.DeprecationRule{}, false
	}
	return catalog.DeprecationRule{
		APIVersion: apiVersion, Kind: kind,
		DeprecatedIn: life.DeprecatedIn, RemovedIn: life.RemovedIn, Replacement: life.Replacement,
		RuleID: "rtz-k8s-dep-" + slug(apiVersion) + "-" + strings.ToLower(kind),
		Title:  fmt.Sprintf("%s %s", kind, apiVersion),
		Remediation: fmt.Sprintf("Move %s objects from %s to %s before upgrading.",
			kind, apiVersion, fallback(life.Replacement, "a supported API version")),
	}, true
}

// grade decides whether a rule fires at this target and how severely.
//
// Removal is critical: the objects stop being readable. Deprecation is high but not critical,
// because everything still works and there is time to act.
func grade(rule catalog.DeprecationRule, targetKey int) (catalog.Severity, string, bool) {
	if key := catalog.MinorKey(rule.RemovedIn); key != 0 && key <= targetKey {
		return catalog.SeverityCritical, rule.RemovedIn, true
	}
	if key := catalog.MinorKey(rule.DeprecatedIn); key != 0 && key <= targetKey {
		return catalog.SeverityHigh, rule.DeprecatedIn, true
	}
	return "", "", false
}

func downgrade(s catalog.Severity) catalog.Severity {
	switch s {
	case catalog.SeverityCritical:
		return catalog.SeverityHigh
	case catalog.SeverityHigh:
		return catalog.SeverityMedium
	default:
		return s
	}
}

func objectRef(u inventory.APIUsage) string {
	if u.Name == "" {
		return ""
	}
	if u.Namespace == "" {
		return u.Name
	}
	return u.Namespace + "/" + u.Name
}

func sortedKeys(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func collapse(objects []string, whenEmpty string) string {
	switch len(objects) {
	case 0:
		return whenEmpty
	case 1:
		return objects[0]
	default:
		return fmt.Sprintf("%s (+%d more)", objects[0], len(objects)-1)
	}
}

func firstOr(items []string, fallbackValue string) string {
	if len(items) == 0 {
		return fallbackValue
	}
	return items[0]
}

func capNamed(items []string) []string {
	if len(items) <= maxNamed {
		return items
	}
	return items[:maxNamed]
}

func slug(apiVersion string) string {
	s := strings.ToLower(apiVersion)
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, ".", "-")
	return s
}

func fallback(value, whenEmpty string) string {
	if strings.TrimSpace(value) == "" {
		return whenEmpty
	}
	return value
}
