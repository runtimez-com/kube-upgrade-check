package catalog

import (
	"strconv"
	"strings"
)

// Add-on versions are not Kubernetes versions. Vendors ship "1.0.5", "v2.11.3", "1.16.0-beta.0",
// and their compatibility tables mix precisions freely: Karpenter documents both a "1.0.x"
// window and a "1.0.5" one, and the more specific row must win or 1.0.0-1.0.4 silently
// inherit a Kubernetes minor they were never tested on.

// Components splits an add-on version into its numeric parts.
//
// Stops at the first non-numeric part, so "1.16.0-beta.0" yields [1 16 0] and "latest"
// yields nothing.
func Components(version string) []int {
	s := strings.TrimSpace(version)
	s = strings.TrimPrefix(s, "v")
	if i := strings.IndexAny(s, "-+_"); i >= 0 {
		s = s[:i]
	}
	if s == "" {
		return nil
	}
	var out []int
	for _, part := range strings.Split(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			break
		}
		out = append(out, n)
	}
	return out
}

// IsParseable reports whether a version carries at least a major and a minor.
//
// One component is not enough: an image tagged "1" or "3" tells us nothing a support window
// can be matched against, and guessing would be worse than declining.
func IsParseable(version string) bool { return len(Components(version)) >= 2 }

// CompareVersions orders two add-on versions, padding the shorter with zeros so 1.6 == 1.6.0.
//
// An unparseable version sorts below everything, which keeps sorts stable without ever
// letting an unknown version win a "highest version" comparison.
func CompareVersions(a, b string) int {
	ca, cb := Components(a), Components(b)
	switch {
	case len(ca) == 0 && len(cb) == 0:
		return 0
	case len(ca) == 0:
		return -1
	case len(cb) == 0:
		return 1
	}
	n := len(ca)
	if len(cb) > n {
		n = len(cb)
	}
	for i := 0; i < n; i++ {
		x, y := 0, 0
		if i < len(ca) {
			x = ca[i]
		}
		if i < len(cb) {
			y = cb[i]
		}
		if x != y {
			if x < y {
				return -1
			}
			return 1
		}
	}
	return 0
}

// AtLeast reports version >= floor.
//
// False when either side is unparseable: a rule gated on "at least 1.0" must not fire for a
// version we could not read, because that is an accusation we cannot support.
func AtLeast(version, floor string) bool {
	if !IsParseable(version) || !IsParseable(floor) {
		return false
	}
	return CompareVersions(version, floor) >= 0
}

// IsPrefixOf reports whether every component of prefix equals the matching component of
// version.
//
// Component-wise, never string-wise: "1.1" must not match "1.13.0". A prefix longer than the
// version does not match, so "1.0.5" does not prefix "1.0".
func IsPrefixOf(prefix, version string) bool {
	cp, cv := Components(prefix), Components(version)
	if len(cp) == 0 || len(cp) > len(cv) {
		return false
	}
	for i, p := range cp {
		if cv[i] != p {
			return false
		}
	}
	return true
}

// Specificity is the component count, used to pick the most specific matching window.
func Specificity(version string) int { return len(Components(version)) }
