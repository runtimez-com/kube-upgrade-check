package support

import (
	"testing"
	"time"

	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func at(y, m, d int) time.Time { return time.Date(y, time.Month(m), d, 0, 0, 0, 0, time.UTC) }

// An unrecognised provider is not the same as no information. The upstream community end-of-life
// date is real and still applies, so it is reported and marked as not vendor-managed rather than
// discarded.
func TestUnknownProviderFallsBackToUpstreamDates(t *testing.T) {
	s := Status("", "v1.33.5+k3s1", at(2026, 9, 1))
	if s.VendorManaged {
		t.Error("with no recognised provider there is no vendor schedule to claim")
	}
	if !s.DataSourced || s.StandardSupportEnd == "" {
		t.Errorf("the upstream end-of-life date is real data and should be reported: %+v", s)
	}
	if s.AnnualExtendedSupportCostEstimate != nil {
		t.Error("there is no extended support to price without a vendor")
	}
}

// A minor outside both tracks is the case where nothing at all is known, and the report has to
// be able to say that rather than imply there is no deadline.
func TestUnknownMinorReportsNothing(t *testing.T) {
	s := Status("", "v1.20.0", at(2026, 9, 1))
	if s.DataSourced || s.StandardSupportEnd != "" {
		t.Errorf("nothing should be claimed for a minor in neither table: %+v", s)
	}
	if got := Describe(s, "v1.20.0"); !contains(got, "could not be identified") {
		t.Errorf("the report must say the timeline is unknown: %s", got)
	}
}

func TestUnparseableVersionReportsNothing(t *testing.T) {
	s := Status("EKS", "not-a-version", at(2026, 9, 1))
	if s.DataSourced || s.StandardSupportEnd != "" || s.DaysUntilForcedUpgrade != nil {
		t.Errorf("nothing should be claimed for an unreadable version: %+v", s)
	}
}

func TestManagedProviderCarriesBothDatesAndTheClock(t *testing.T) {
	s := Status("EKS", "v1.33.13-eks-a1b2", at(2026, 9, 1))
	if !s.VendorManaged || !s.DataSourced {
		t.Errorf("EKS 1.33 should be vendor-managed and sourced: %+v", s)
	}
	if s.StandardSupportEnd == "" || s.ExtendedSupportEnd == "" {
		t.Errorf("both dates should be present: %+v", s)
	}
	// The forced date is the last one that matters, which is the end of extended support.
	if s.ForcedUpgradeDate != s.ExtendedSupportEnd {
		t.Errorf("forced upgrade should track extended support, got %q vs %q",
			s.ForcedUpgradeDate, s.ExtendedSupportEnd)
	}
	if s.DaysUntilForcedUpgrade == nil || *s.DaysUntilForcedUpgrade <= 0 {
		t.Errorf("expected days remaining, got %v", s.DaysUntilForcedUpgrade)
	}
}

// A deadline that has passed is zero days away, never a negative number.
func TestPastDeadlineClampsAtZero(t *testing.T) {
	s := Status("EKS", "1.25", at(2030, 1, 1))
	if s.DaysUntilForcedUpgrade == nil || *s.DaysUntilForcedUpgrade != 0 {
		t.Errorf("a passed deadline should be 0 days, got %v", s.DaysUntilForcedUpgrade)
	}
}

// Quoting the cost before standard support ends makes an upgrade look more urgent than it is.
func TestExtendedCostOnlyAppliesOnceStandardSupportHasEnded(t *testing.T) {
	before := Status("EKS", "1.33", at(2026, 1, 1))
	if before.AnnualExtendedSupportCostEstimate == nil || *before.AnnualExtendedSupportCostEstimate != 0 {
		t.Errorf("no cost is owed before standard support ends, got %v", before.AnnualExtendedSupportCostEstimate)
	}
	after := Status("EKS", "1.33", at(2027, 1, 1))
	if after.AnnualExtendedSupportCostEstimate == nil || *after.AnnualExtendedSupportCostEstimate < 5000 {
		t.Errorf("expected the published EKS rate to apply, got %v", after.AnnualExtendedSupportCostEstimate)
	}
}

// A number presented as fact when it is a guess is worse than no number.
func TestEstimatedRatesAreLabelledAsEstimates(t *testing.T) {
	eks := Status("EKS", "1.33", at(2027, 1, 1))
	if contains(eks.CostWarning, "estimated") {
		t.Errorf("the EKS rate is published and must not be labelled an estimate: %q", eks.CostWarning)
	}
	gke := Status("GKE", "1.33", at(2027, 6, 1))
	if !contains(gke.CostWarning, "estimated") {
		t.Errorf("a guessed rate must say so: %q", gke.CostWarning)
	}
}

func TestProviderAliases(t *testing.T) {
	for _, alias := range []string{"EKS", "eks", "AWS", "aws"} {
		if got := normalizeProvider(alias); got != "EKS" {
			t.Errorf("normalizeProvider(%q) = %q, want EKS", alias, got)
		}
	}
	for _, alias := range []string{"GKE", "gcp", "Google"} {
		if got := normalizeProvider(alias); got != "GKE" {
			t.Errorf("normalizeProvider(%q) = %q, want GKE", alias, got)
		}
	}
	if got := normalizeProvider("openshift"); got != "" {
		t.Errorf("an unknown provider must not be mapped, got %q", got)
	}
}

func TestPatchCurrency(t *testing.T) {
	if pc := PatchCurrency("v1.33.5+k3s1"); pc == nil || pc.UpToDate {
		t.Errorf("1.33.5 is behind 1.33.13: %+v", pc)
	}
	if pc := PatchCurrency("v1.33.13-eks-a1b2"); pc == nil || !pc.UpToDate {
		t.Errorf("1.33.13 is current: %+v", pc)
	}
	// A minor we have no data for must report nothing rather than claim currency.
	if pc := PatchCurrency("v1.20.0"); pc != nil {
		t.Errorf("expected no claim for an untracked minor, got %+v", pc)
	}
}

func TestDescribeReadsAsProse(t *testing.T) {
	s := Status("EKS", "v1.33.13-eks", at(2026, 9, 1))
	got := Describe(s, "v1.33.13-eks")
	for _, want := range []string{"Standard support for 1.33 ends", "days"} {
		if !contains(got, want) {
			t.Errorf("expected %q in: %s", want, got)
		}
	}
	unknown := Describe(report.Support{}, "v1.33.0")
	if !contains(unknown, "could not be identified") {
		t.Errorf("an unknown provider should say so plainly: %s", unknown)
	}
}

func contains(haystack, needle string) bool {
	return len(haystack) >= len(needle) && (haystack == needle ||
		len(needle) == 0 || indexOf(haystack, needle) >= 0)
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}
