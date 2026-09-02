// Package report defines what a scan produces: findings, coverage, and the JSON contract.
//
// The coverage half matters as much as the findings half. A tool that checks nine things and
// silently skips the tenth reports the same clean result as one that checked all ten, and the
// reader has no way to tell the difference. Everything this tool could not see gets a row.
package report

import (
	"crypto/sha1"
	"encoding/hex"
	"sort"
	"strings"
	"time"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
)

// Finding is one thing that breaks, or one thing we could not check.
//
// Field names match the runtimez API's readiness response so a finding from this tool and one
// from the hosted product are the same shape, and rule IDs are identical, so they can be
// compared directly.
type Finding struct {
	ID               string           `json:"id"`
	RuleID           string           `json:"ruleId"`
	Title            string           `json:"title"`
	Description      string           `json:"description,omitempty"`
	Impact           string           `json:"impact,omitempty"`
	Recommendation   string           `json:"recommendation,omitempty"`
	Category         string           `json:"category"`
	Severity         catalog.Severity `json:"severity"`
	ResourceName     string           `json:"resourceName,omitempty"`
	ResourceType     string           `json:"resourceType,omitempty"`
	ScoreImpact      int              `json:"scoreImpact"`
	AppliesAtVersion string           `json:"appliesAtVersion,omitempty"`
	// EnforcementLevel is "blocking" for real breaks and "advisory" for items that are worth
	// reading but can never move the score.
	EnforcementLevel  string   `json:"enforcementLevel,omitempty"`
	VerifyCommand     string   `json:"verifyCommand,omitempty"`
	AffectedResources []string `json:"affectedResources,omitempty"`

	// Quote and SourceURL carry the vendor's own words and where they came from. The hosted
	// product folds these into the recommendation text; keeping them separate here means a
	// reader can check the claim without trusting the tool.
	Quote     string `json:"quote,omitempty"`
	SourceURL string `json:"sourceUrl,omitempty"`

	// Evidence is why this fired, in the words of what was actually observed, and Tiers names
	// which evidence source produced it.
	Evidence []string `json:"evidence,omitempty"`
	Tiers    []string `json:"tiers,omitempty"`
}

// NewID builds the deterministic finding id the hosted product uses, so the same finding
// carries the same id in both.
func NewID(ruleID, resourceName string) string {
	sum := sha1.Sum([]byte(ruleID + "|" + resourceName))
	return hex.EncodeToString(sum[:])
}

// CoverageState says how completely one check could run.
type CoverageState string

const (
	// CoverageComplete means the check ran against everything it needed.
	CoverageComplete CoverageState = "COMPLETE"
	// CoveragePartial means it ran, but against less than the whole picture.
	CoveragePartial CoverageState = "PARTIAL"
	// CoverageUnavailable means it could not run at all. Never rendered as a pass.
	CoverageUnavailable CoverageState = "UNAVAILABLE"
)

// Coverage is one row of "what we could and could not see", with the reason in plain words
// and, where one exists, the command the reader can run themselves.
type Coverage struct {
	Source        string        `json:"source"`
	Scope         string        `json:"scope,omitempty"`
	State         CoverageState `json:"state"`
	Reason        string        `json:"reason,omitempty"`
	RulesSkipped  int           `json:"rulesSkipped,omitempty"`
	VerifyCommand string        `json:"verifyCommand,omitempty"`
}

// OK reports whether this coverage row represents a check that fully ran.
func (c Coverage) OK() bool { return c.State == CoverageComplete }

// ScanStatus summarises whether the whole scan can be trusted as complete.
type ScanStatus string

const (
	ScanComplete         ScanStatus = "COMPLETE"
	ScanPartial          ScanStatus = "PARTIAL"
	ScanInsufficientData ScanStatus = "INSUFFICIENT_DATA"
)

// Support is the vendor support clock for the cluster's current version.
type Support struct {
	DaysUntilForcedUpgrade            *int     `json:"daysUntilForcedUpgrade,omitempty"`
	StandardSupportEnd                string   `json:"standardSupportEnd,omitempty"`
	ExtendedSupportEnd                string   `json:"extendedSupportEnd,omitempty"`
	ForcedUpgradeDate                 string   `json:"forcedUpgradeDate,omitempty"`
	CostWarning                       string   `json:"costWarning,omitempty"`
	AnnualExtendedSupportCostEstimate *float64 `json:"annualExtendedSupportCostEstimate,omitempty"`
	VendorManaged                     bool     `json:"vendorManaged"`
	// DataSourced is false when the provider could not be identified, which is the difference
	// between "no deadline" and "we do not know your deadline".
	DataSourced bool `json:"dataSourced"`
}

// AddonStatus is one detected add-on and its verdict against the target version.
type AddonStatus struct {
	AddonID           string                `json:"addonId"`
	DisplayName       string                `json:"displayName"`
	InstalledVersion  string                `json:"installedVersion,omitempty"`
	VersionSource     string                `json:"versionSource,omitempty"`
	WorkloadRef       string                `json:"workloadRef,omitempty"`
	Verdict           string                `json:"verdict"`
	MinK8s            string                `json:"minK8s,omitempty"`
	MaxK8s            string                `json:"maxK8s,omitempty"`
	MinimumVersionFix string                `json:"minimumVersionFix,omitempty"`
	SourceURL         string                `json:"sourceUrl,omitempty"`
	Stale             bool                  `json:"catalogStale,omitempty"`
	UpgradeNotes      []catalog.UpgradeNote `json:"upgradeNotes,omitempty"`
}

// PatchCurrency reports whether the cluster is on the newest patch of its own minor.
type PatchCurrency struct {
	CurrentPatch string `json:"currentPatch,omitempty"`
	LatestPatch  string `json:"latestPatch,omitempty"`
	UpToDate     bool   `json:"upToDate"`
}

// Result is the whole scan. This is what -o json prints.
type Result struct {
	Cluster                 string         `json:"cluster,omitempty"`
	Provider                string         `json:"provider,omitempty"`
	CurrentVersion          string         `json:"currentVersion"`
	TargetVersion           string         `json:"targetVersion"`
	NodeCount               int            `json:"nodeCount"`
	Score                   int            `json:"score"`
	RiskLevel               string         `json:"riskLevel"`
	Support                 Support        `json:"support"`
	PatchCurrency           *PatchCurrency `json:"patchCurrency,omitempty"`
	Findings                []Finding      `json:"findings"`
	FindingCountsBySeverity map[string]int `json:"findingCountsBySeverity"`
	Addons                  []AddonStatus  `json:"addons,omitempty"`
	Coverage                []Coverage     `json:"coverage"`
	ScanStatus              ScanStatus     `json:"scanStatus"`
	CheckedAt               time.Time      `json:"checkedAt"`
	ToolVersion             string         `json:"toolVersion"`
}

// Sort orders findings most severe first, then by rule id so output is stable between runs.
// An unstable report cannot be diffed, and diffing two runs is how anyone verifies a fix.
func Sort(findings []Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		ri, rj := findings[i].Severity.Rank(), findings[j].Severity.Rank()
		if ri != rj {
			return ri > rj
		}
		if findings[i].RuleID != findings[j].RuleID {
			return findings[i].RuleID < findings[j].RuleID
		}
		return findings[i].ResourceName < findings[j].ResourceName
	})
}

// CountBySeverity tallies findings for the summary line.
func CountBySeverity(findings []Finding) map[string]int {
	out := map[string]int{}
	for _, f := range findings {
		out[strings.ToUpper(string(f.Severity))]++
	}
	return out
}

// StatusFor derives the overall scan status from coverage.
//
// Any unavailable check makes the scan partial: the findings that did run are still real, but
// the absence of others is not evidence of health.
func StatusFor(coverage []Coverage) ScanStatus {
	var unavailable, partial, complete int
	for _, c := range coverage {
		switch c.State {
		case CoverageUnavailable:
			unavailable++
		case CoveragePartial:
			partial++
		case CoverageComplete:
			complete++
		}
	}
	switch {
	case complete == 0 && (unavailable > 0 || partial > 0):
		return ScanInsufficientData
	case unavailable > 0 || partial > 0:
		return ScanPartial
	default:
		return ScanComplete
	}
}
