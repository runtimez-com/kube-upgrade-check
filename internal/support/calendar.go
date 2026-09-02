// Package support answers "how long until you are forced to upgrade, and what does waiting
// cost".
//
// This is the half of an upgrade report that reaches people who do not read Kubernetes
// changelogs. A list of broken APIs is an engineering problem; a date and an annual figure is
// a planning one, and the second is what gets the first prioritised.
//
// The dates here are transcribed by hand from vendor schedules. Where a figure is an estimate
// rather than a published price, the output says so rather than implying precision it does
// not have.
package support

import (
	"fmt"
	"math"
	"strings"
	"time"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

// window is one provider's support period for one Kubernetes minor.
type window struct {
	standardEnd string
	extendedEnd string
	costNote    string
}

// calendar is keyed "PROVIDER|minor".
var calendar = map[string]window{
	"EKS|1.25": {"2024-05-01", "2025-05-01", eksNote}, "EKS|1.26": {"2024-06-01", "2025-06-01", eksNote},
	"EKS|1.27": {"2024-07-01", "2025-07-01", eksNote}, "EKS|1.28": {"2024-11-01", "2025-11-01", eksNote},
	"EKS|1.29": {"2025-03-01", "2026-03-01", eksNote}, "EKS|1.30": {"2025-07-01", "2026-07-01", eksNote},
	"EKS|1.31": {"2025-11-01", "2026-11-01", eksNote}, "EKS|1.32": {"2026-03-01", "2027-03-01", eksNote},
	"EKS|1.33": {"2026-07-01", "2027-07-01", eksNote}, "EKS|1.34": {"2026-11-01", "2027-11-01", eksNote},
	"EKS|1.35": {"2027-03-01", "2028-03-01", eksNote}, "EKS|1.36": {"2027-07-01", "2028-07-01", eksNote},
	"EKS|1.37": {"2027-11-01", "2028-11-01", eksNote},

	"GKE|1.25": {"2024-02-01", "2024-08-01", gkeNote}, "GKE|1.26": {"2024-05-01", "2024-11-01", gkeNote},
	"GKE|1.27": {"2024-08-01", "2025-02-01", gkeNote}, "GKE|1.28": {"2024-11-01", "2025-05-01", gkeNote},
	"GKE|1.29": {"2025-03-01", "2025-09-01", gkeNote}, "GKE|1.30": {"2025-07-01", "2026-01-01", gkeNote},
	"GKE|1.31": {"2025-11-01", "2026-05-01", gkeNote}, "GKE|1.32": {"2026-03-01", "2026-09-01", gkeNote},
	"GKE|1.33": {"2026-07-01", "2027-01-01", gkeNote}, "GKE|1.34": {"2026-11-01", "2027-05-01", gkeNote},
	"GKE|1.35": {"2027-03-01", "2027-09-01", gkeNote}, "GKE|1.36": {"2027-07-01", "2028-01-01", gkeNote},
	"GKE|1.37": {"2027-11-01", "2028-05-01", gkeNote},

	"AKS|1.25": {"2024-05-01", "2025-05-01", aksNote}, "AKS|1.26": {"2024-07-01", "2025-07-01", aksNote},
	"AKS|1.27": {"2024-07-01", "2025-07-01", "AKS long-term support (1.27) around $0.10 per cluster per hour on the Premium tier"},
	"AKS|1.28": {"2024-11-01", "2025-11-01", aksNote}, "AKS|1.29": {"2025-01-01", "2026-01-01", aksNote},
	"AKS|1.30": {"2025-07-01", "2026-07-01", aksNote}, "AKS|1.31": {"2025-11-01", "2026-11-01", aksNote},
	"AKS|1.32": {"2026-03-01", "2027-03-01", aksNote}, "AKS|1.33": {"2026-07-01", "2027-07-01", aksNote},
	"AKS|1.34": {"2026-11-01", "2027-11-01", aksNote}, "AKS|1.35": {"2027-03-01", "2028-03-01", aksNote},
	"AKS|1.36": {"2027-07-01", "2028-07-01", aksNote}, "AKS|1.37": {"2027-11-01", "2028-11-01", aksNote},
}

const (
	eksNote = "EKS extended support is about $0.60 per cluster per hour"
	gkeNote = "GKE extended support is billed per cluster"
	aksNote = "AKS long-term support is available on the Premium tier"
)

// hourlyExtendedRate is the per-cluster extended-support rate.
//
// Only the EKS figure is a published price. The other two are estimates, and the report labels
// them as such — a number presented as fact when it is a guess is worse than no number.
var hourlyExtendedRate = map[string]float64{"EKS": 0.60, "GKE": 0.10, "AKS": 0.10}

// publishedRate names the providers whose rate we did not estimate.
var publishedRate = map[string]bool{"EKS": true}

const hoursPerYear = 8760.0

// upstreamEOL is the community end-of-life date per minor, used when the cluster is not on a
// managed provider we recognise. Roughly 14 months after release.
var upstreamEOL = map[string]string{
	"1.25": "2023-10-28", "1.26": "2024-02-28", "1.27": "2024-06-28", "1.28": "2024-10-28",
	"1.29": "2025-02-28", "1.30": "2025-06-28", "1.31": "2025-10-28", "1.32": "2026-02-28",
	"1.33": "2026-06-28", "1.34": "2026-10-28", "1.35": "2027-02-28", "1.36": "2027-06-28",
	"1.37": "2027-10-28",
}

// latestPatch is the newest known patch for each minor, for the patch-currency check.
var latestPatch = map[string]string{
	"1.33": "1.33.13", "1.34": "1.34.11", "1.35": "1.35.8", "1.36": "1.36.4", "1.37": "1.37.0",
}

// Status computes the support clock for a cluster.
//
// Two tracks, in order: the managed provider's own schedule when we recognise the provider,
// otherwise the upstream community end-of-life date. When neither covers the version, every
// field stays empty and DataSourced is false — "we do not know your deadline" is a real
// answer and must not be rendered as "you have no deadline".
func Status(provider, currentVersion string, now time.Time) report.Support {
	minor := catalog.MinorOf(currentVersion)
	if minor == "" {
		return report.Support{}
	}
	p := normalizeProvider(provider)

	if w, ok := calendar[p+"|"+minor]; ok {
		s := report.Support{
			StandardSupportEnd: w.standardEnd,
			ExtendedSupportEnd: w.extendedEnd,
			VendorManaged:      true,
			DataSourced:        true,
		}
		forced := w.extendedEnd
		if forced == "" {
			forced = w.standardEnd
		}
		s.ForcedUpgradeDate = forced
		if d, ok := daysUntil(forced, now); ok {
			s.DaysUntilForcedUpgrade = &d
		}
		s.CostWarning = w.costNote
		if cost, ok := annualExtendedCost(p, w.standardEnd, now); ok {
			s.AnnualExtendedSupportCostEstimate = &cost
			if !publishedRate[p] {
				s.CostWarning += " (rate estimated, not a published price)"
			}
		}
		return s
	}

	if eol, ok := upstreamEOL[minor]; ok {
		s := report.Support{
			StandardSupportEnd: eol,
			ForcedUpgradeDate:  eol,
			VendorManaged:      false,
			DataSourced:        true,
			CostWarning:        "Community support only. After this date there are no upstream patches, including for security fixes.",
		}
		if d, ok := daysUntil(eol, now); ok {
			s.DaysUntilForcedUpgrade = &d
		}
		return s
	}

	return report.Support{}
}

// PatchCurrency reports whether the cluster runs the newest patch of its own minor.
//
// Returns nil when the minor is not in the table, rather than claiming currency we cannot
// establish.
func PatchCurrency(currentVersion string) *report.PatchCurrency {
	minor := catalog.MinorOf(currentVersion)
	latest, ok := latestPatch[minor]
	if !ok {
		return nil
	}
	current := strings.TrimPrefix(strings.TrimSpace(currentVersion), "v")
	if i := strings.IndexAny(current, "-+_"); i >= 0 {
		current = current[:i]
	}
	return &report.PatchCurrency{
		CurrentPatch: current,
		LatestPatch:  latest,
		UpToDate:     catalog.CompareVersions(current, latest) >= 0,
	}
}

// annualExtendedCost is the yearly cost of staying past standard support.
//
// Zero before standard support ends: the cost is real only once the clock has run out, and
// quoting it early makes an upgrade look more urgent than it is.
func annualExtendedCost(provider, standardEnd string, now time.Time) (float64, bool) {
	rate, ok := hourlyExtendedRate[provider]
	if !ok {
		return 0, false
	}
	end, err := time.Parse("2006-01-02", standardEnd)
	if err != nil {
		return 0, false
	}
	if now.Before(end) {
		return 0, true
	}
	return math.Round(rate*hoursPerYear*100) / 100, true
}

// daysUntil is whole days from now to a date, clamped at zero — a deadline that has passed is
// zero days away, never negative.
func daysUntil(date string, now time.Time) (int, bool) {
	d, err := time.Parse("2006-01-02", date)
	if err != nil {
		return 0, false
	}
	days := int(d.Sub(now).Hours() / 24)
	if days < 0 {
		days = 0
	}
	return days, true
}

// normalizeProvider maps the many names for three clouds onto our three keys.
func normalizeProvider(p string) string {
	up := strings.ToUpper(strings.TrimSpace(p))
	var letters strings.Builder
	for _, r := range up {
		if r >= 'A' && r <= 'Z' {
			letters.WriteRune(r)
		}
	}
	switch letters.String() {
	case "EKS", "AWS":
		return "EKS"
	case "GKE", "GCP", "GOOGLE":
		return "GKE"
	case "AKS", "AZURE":
		return "AKS"
	default:
		return ""
	}
}

// Describe renders the support clock as the one line the report prints.
func Describe(s report.Support, currentVersion string) string {
	if !s.DataSourced {
		return "Support timeline unknown: this cluster's provider could not be identified, so no end-of-support date is available."
	}
	minor := catalog.MinorOf(currentVersion)
	var b strings.Builder
	if s.VendorManaged {
		fmt.Fprintf(&b, "Standard support for %s ends %s", minor, s.StandardSupportEnd)
		if s.ExtendedSupportEnd != "" {
			fmt.Fprintf(&b, ", extended support ends %s", s.ExtendedSupportEnd)
		}
	} else {
		fmt.Fprintf(&b, "Upstream support for %s ends %s", minor, s.StandardSupportEnd)
	}
	if s.DaysUntilForcedUpgrade != nil {
		if *s.DaysUntilForcedUpgrade == 0 {
			b.WriteString(". That date has passed")
		} else {
			fmt.Fprintf(&b, " (%d days)", *s.DaysUntilForcedUpgrade)
		}
	}
	if s.AnnualExtendedSupportCostEstimate != nil && *s.AnnualExtendedSupportCostEstimate > 0 {
		fmt.Fprintf(&b, ". Staying past standard support costs about $%.0f per cluster per year",
			*s.AnnualExtendedSupportCostEstimate)
	}
	b.WriteString(".")
	return b.String()
}
