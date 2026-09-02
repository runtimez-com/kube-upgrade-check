// Package advisory reports behaviour changes on the upgrade path that no API call can check.
//
// Every rule here is unverifiable by construction: a scrape config that moved, a default that
// flipped, a flag whose meaning changed. The tool cannot tell whether a given cluster is
// affected, so these are printed as things to read with the command to check them, marked
// INFO, and never allowed to move the score. Leaving them out entirely would be the worse
// error — the reader would never learn the change exists.
package advisory

import (
	"strings"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

// checkWith introduces the command a reader can run to settle an item themselves.
const checkWith = " Check with: "

// Analyze returns the advisories that fall on the path from current to target.
//
// The window is exclusive at the bottom and inclusive at the top: a change already in effect
// on the running cluster is not part of this upgrade. Without that lower bound a cluster
// moving one minor received twenty advisories about behaviour that had been live on it for
// years, which buried the two that were actually about the upgrade.
//
// An unparseable current version widens the window rather than narrowing it. Uncertainty may
// add noise; it must never silently drop a finding.
func Analyze(currentVersion, targetVersion, clusterName string, rules []catalog.AdvisoryRule) []report.Finding {
	targetKey := catalog.MinorKey(targetVersion)
	if targetKey == 0 {
		return nil
	}
	currentKey := catalog.MinorKey(currentVersion)

	var findings []report.Finding
	for _, rule := range rules {
		ruleKey := catalog.MinorKey(rule.Version)
		if ruleKey == 0 || ruleKey > targetKey {
			continue
		}
		if currentKey != 0 && ruleKey <= currentKey {
			continue
		}

		recommendation := rule.Remediation
		verify := strings.TrimSpace(rule.VerifyCommand)
		if verify != "" {
			recommendation += checkWith + verify
		}

		findings = append(findings, report.Finding{
			ID:               report.NewID(rule.RuleID, clusterName),
			RuleID:           rule.RuleID,
			Title:            rule.Title + " [target " + targetVersion + "]",
			Recommendation:   recommendation,
			Category:         "RELIABILITY",
			Severity:         catalog.SeverityInfo,
			ScoreImpact:      0,
			ResourceName:     clusterName,
			ResourceType:     "Cluster",
			EnforcementLevel: "advisory",
			VerifyCommand:    verify,
			AppliesAtVersion: catalog.MinorOf(rule.Version),
		})
	}
	return findings
}
