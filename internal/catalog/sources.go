package catalog

import "strconv"

// Scoping says which version ladder a rule source's files are stamped with, and therefore
// which hop selects its rules.
//
// The three cases mirror the hosted product's configuration for the same catalog
// (generated-rules.hop-scoped-sources / always-on-sources), so a rule selected there for a
// cluster is the rule selected here.
type Scoping int

const (
	// ScopedToKubernetesHop: the files are Kubernetes minors and the rule runs when its minor
	// lies in (current, target]. The "kubernetes" release notes, and kube-proxy, whose own
	// version tracks the control plane's.
	ScopedToKubernetesHop Scoping = iota
	// ScopedToAddonHop: the files are the ADD-ON's minors, and a rule is meaningless without
	// the add-on's own hop (installed, required]. No hop — not installed, version unreadable,
	// or nothing forces a move — means the source is not evaluated, and that is stated, never
	// silently cleared.
	ScopedToAddonHop
	// AlwaysOn: hop-independent policy (version skew) whose predicates compare against the
	// target at evaluation time anyway.
	AlwaysOn
)

// SourceScoping classifies a k8s-rules/<source> directory.
//
// Any source that is not one of the two Kubernetes-versioned ones and not the skew policy is
// an add-on: an add-on directory dropped into the catalog is hop-scoped without a code change,
// which is the same default the hosted product applies when it enables a new source.
func SourceScoping(sourceID string) Scoping {
	switch sourceID {
	case "kubernetes", "kube-proxy":
		return ScopedToKubernetesHop
	case "kubernetes-skew-policy":
		return AlwaysOn
	default:
		return ScopedToAddonHop
	}
}

// AddonMinor is the "major.minor" of an add-on version, or "" when it does not parse. Rule
// files are stamped with minors, and the hop's two ends are compared at that precision.
func AddonMinor(version string) string {
	c := Components(version)
	if len(c) < 2 {
		return ""
	}
	return strconv.Itoa(c[0]) + "." + strconv.Itoa(c[1])
}
