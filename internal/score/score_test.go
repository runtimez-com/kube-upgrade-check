package score

import (
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

func f(sev catalog.Severity, impact int) report.Finding {
	return report.Finding{Severity: sev, ScoreImpact: impact}
}

func TestCompute(t *testing.T) {
	cases := []struct {
		name      string
		findings  []report.Finding
		wantScore int
		wantLevel string
	}{
		{"nothing found", nil, 0, LevelLow},
		{"one critical floors at 81", []report.Finding{f(catalog.SeverityCritical, 40)}, 81, LevelCritical},
		{"one high floors at 61", []report.Finding{f(catalog.SeverityHigh, 20)}, 61, LevelHigh},
		{"impacts sum", []report.Finding{f(catalog.SeverityMedium, 8), f(catalog.SeverityMedium, 8)}, 16, LevelLow},
		{
			"advisories cannot exceed the info ceiling",
			[]report.Finding{f(catalog.SeverityInfo, 0), f(catalog.SeverityInfo, 0), f(catalog.SeverityInfo, 0)},
			0, LevelLow,
		},
		{
			"many mediums cap at the medium ceiling",
			[]report.Finding{
				f(catalog.SeverityMedium, 8), f(catalog.SeverityMedium, 8), f(catalog.SeverityMedium, 8),
				f(catalog.SeverityMedium, 8), f(catalog.SeverityMedium, 8), f(catalog.SeverityMedium, 8),
				f(catalog.SeverityMedium, 8), f(catalog.SeverityMedium, 8), f(catalog.SeverityMedium, 8),
			},
			60, LevelMedium,
		},
		{
			"a low finding cannot reach medium",
			[]report.Finding{f(catalog.SeverityLow, 3), f(catalog.SeverityLow, 3), f(catalog.SeverityLow, 3),
				f(catalog.SeverityLow, 3), f(catalog.SeverityLow, 3), f(catalog.SeverityLow, 3),
				f(catalog.SeverityLow, 3), f(catalog.SeverityLow, 3), f(catalog.SeverityLow, 3),
				f(catalog.SeverityLow, 3), f(catalog.SeverityLow, 3)},
			30, LevelLow,
		},
		{
			"criticals accumulate to the top",
			[]report.Finding{f(catalog.SeverityCritical, 40), f(catalog.SeverityCritical, 40), f(catalog.SeverityCritical, 40)},
			100, LevelCritical,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, level := Compute(tc.findings)
			if got != tc.wantScore || level != tc.wantLevel {
				t.Errorf("Compute() = %d/%s, want %d/%s", got, level, tc.wantScore, tc.wantLevel)
			}
		})
	}
}

// An INFO finding must never lift the score. Advisories are printed to be read, not to alarm.
func TestInfoFindingsNeverRaiseTheScore(t *testing.T) {
	base, _ := Compute([]report.Finding{f(catalog.SeverityMedium, 8)})
	withInfo, _ := Compute([]report.Finding{f(catalog.SeverityMedium, 8), f(catalog.SeverityInfo, 0)})
	if withInfo != base {
		t.Errorf("adding an INFO finding changed the score from %d to %d", base, withInfo)
	}
}

// An unrecognised severity ranks 0. Capping at 0 would turn a real finding into a clean score,
// which is the one direction this function must never fail in.
func TestUnknownSeverityDoesNotClampTheScoreToZero(t *testing.T) {
	got, level := Compute([]report.Finding{{Severity: catalog.Severity("WEIRD"), ScoreImpact: 40}})
	if got == 0 {
		t.Errorf("an unrecognised severity produced a clean score of 0/%s", level)
	}
	if got != 40 {
		t.Errorf("expected the impact to stand, got %d", got)
	}
}
