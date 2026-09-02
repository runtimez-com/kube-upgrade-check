// Package score turns findings into the 0-100 upgrade risk score.
//
// It is a port of the hosted product's scoring so the two agree: the same cluster scanned by
// either lands in the same band. The arithmetic is deliberately blunt — a score is a sorting
// aid, and the findings underneath it are the real answer.
package score

import (
	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
)

// Level bands. These match the hosted product's thresholds exactly.
const (
	LevelLow      = "LOW"
	LevelMedium   = "MEDIUM"
	LevelHigh     = "HIGH"
	LevelCritical = "CRITICAL"
)

// LevelFor maps a score to its band.
func LevelFor(score int) string {
	switch {
	case score <= 30:
		return LevelLow
	case score <= 60:
		return LevelMedium
	case score <= 80:
		return LevelHigh
	default:
		return LevelCritical
	}
}

// Compute returns the score and its band.
//
// Three stages, in this order:
//
//   - Sum the per-finding impacts, capped at 100. Every upgrade finding sits in one risk
//     dimension, so the hosted product's weighted average over dimensions reduces to this sum.
//   - Apply a severity floor. One CRITICAL finding means the answer is at least 81 no matter
//     how few findings there are, because "one thing is definitely broken" is not a low-risk
//     upgrade. HIGH floors at 61.
//   - Apply a severity ceiling. A cluster whose worst finding is advisory cannot score above
//     10, however many advisories there are — otherwise a long list of things worth reading
//     would read as a crisis.
func Compute(findings []report.Finding) (int, string) {
	if len(findings) == 0 {
		return 0, LevelLow
	}

	sum := 0
	worst := 0
	for _, f := range findings {
		if f.ScoreImpact > 0 {
			sum += f.ScoreImpact
		}
		if r := f.Severity.Rank(); r > worst {
			worst = r
		}
	}
	if sum > 100 {
		sum = 100
	}

	switch {
	case worst == catalog.SeverityCritical.Rank() && sum < 81:
		sum = 81
	case worst == catalog.SeverityHigh.Rank() && sum < 61:
		sum = 61
	}

	if ceiling := ceilingFor(worst); sum > ceiling {
		sum = ceiling
	}
	return sum, LevelFor(sum)
}

// ceilingFor is the top of the band the worst finding can justify.
//
// An unrecognised severity ranks 0, and capping at 0 would silently turn a real finding into a
// clean score. Since we cannot tell how serious it is, nothing is capped: the sum stands, and
// the finding is visible in the list either way.
func ceilingFor(worstRank int) int {
	switch worstRank {
	case catalog.SeverityCritical.Rank():
		return 100
	case catalog.SeverityHigh.Rank():
		return 80
	case catalog.SeverityMedium.Rank():
		return 60
	case catalog.SeverityLow.Rank():
		return 30
	case catalog.SeverityInfo.Rank():
		return 10
	default:
		return 100
	}
}
