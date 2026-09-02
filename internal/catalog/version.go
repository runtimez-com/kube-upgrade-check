// Package catalog loads the embedded upgrade rule catalogs and the version math every
// evaluator needs.
//
// The catalogs are data, not code: adding an add-on or a breaking-change rule is a JSON file
// in catalog/, never a Go change. That is deliberate — it is what lets a contributor who
// found a vendor's compatibility table send a pull request without learning this codebase.
package catalog

import (
	"strconv"
	"strings"
)

// LatestKnownMinor caps every version ladder. A target beyond it is not refused — the
// catalogs simply have nothing to say about it, and saying so is more honest than
// extrapolating.
const LatestKnownMinor = "1.37"

// MinorKey turns "1.33" or "v1.33.13-eks-a1b2c3" into a sortable 1033.
//
// Returns 0 when the input carries no parseable major.minor, and callers must treat 0 as
// "unknown", never as "very old" — a rule that fires because a version failed to parse is
// worse than one that stays silent.
func MinorKey(version string) int {
	major, minor, ok := majorMinor(version)
	if !ok {
		return 0
	}
	return major*1000 + minor
}

// MinorOf returns the "1.33" form, or "" when the input is unparseable.
func MinorOf(version string) string {
	major, minor, ok := majorMinor(version)
	if !ok {
		return ""
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(minor)
}

// NextMinor returns the minor one step up, e.g. "1.33" -> "1.34".
func NextMinor(version string) string {
	major, minor, ok := majorMinor(version)
	if !ok {
		return ""
	}
	return strconv.Itoa(major) + "." + strconv.Itoa(minor+1)
}

// MinorSkew is target minus current in minor versions.
//
// The boolean says whether both sides parsed. Returning a bare 0 for an unreadable version made
// it indistinguishable from a node already at the target, so a node reporting a version we could
// not read was silently treated as fine.
func MinorSkew(current, target string) (int, bool) {
	c, t := MinorKey(current), MinorKey(target)
	if c == 0 || t == 0 {
		return 0, false
	}
	return t - c, true
}

// UpgradeTargets lists every minor from one past current up to the catalog ceiling.
//
// Bounded twice: at LatestKnownMinor, and at 12 hops, so a cluster reporting a nonsense
// version cannot spin this into a huge ladder.
func UpgradeTargets(current string) []string {
	key := MinorKey(current)
	if key == 0 {
		return nil
	}
	ceiling := MinorKey(LatestKnownMinor)
	var out []string
	for next := NextMinor(current); next != "" && MinorKey(next) <= ceiling && len(out) < 12; next = NextMinor(next) {
		out = append(out, next)
	}
	return out
}

// majorMinor parses a Kubernetes version string.
//
// Real clusters report "v1.33.13-eks-a1b2c3", "1.31.5+rke2r1", and — on GKE and EKS — a
// minor of "31+". The trailing plus means "at least", and dropping it is correct here:
// treating "31+" as unparseable would blind every rule on a managed cluster.
func majorMinor(version string) (int, int, bool) {
	s := strings.TrimSpace(version)
	s = strings.TrimPrefix(s, "v")
	if s == "" {
		return 0, 0, false
	}
	// Cut any pre-release or build suffix before splitting on dots.
	if i := strings.IndexAny(s, "-+_ "); i >= 0 {
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) < 2 {
		return 0, 0, false
	}
	major, err := strconv.Atoi(strings.TrimSuffix(parts[0], "+"))
	if err != nil {
		return 0, 0, false
	}
	minor, err := strconv.Atoi(strings.TrimSuffix(parts[1], "+"))
	if err != nil {
		return 0, 0, false
	}
	return major, minor, true
}
