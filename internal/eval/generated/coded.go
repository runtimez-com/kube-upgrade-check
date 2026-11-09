package generated

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/inventory"
)

// targets splits an `a|b` target into its alternatives: the value may sit under either path.
func targets(target string) []string {
	var out []string
	for _, t := range strings.Split(target, "|") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// noneMatches settles SPEC_PATH_NONE_MATCHES, the absence form of SPEC_PATH_MATCHES: an object is
// hit when its path resolves and no value there matches. The AWS LBC's "apply the CRDs by hand
// under Helm" notes are a field missing from the installed CRD's crdSpecFields[], and its default
// flips are a flag missing from the controller's containers[].args[].
//
// Only an object whose path RESOLVED can be judged: an unresolved path is a projection gap, never
// "the value is absent", which would accuse every object. The subject is narrowed by objectName
// and/or objectImage; a narrowed scan that finds no subject declines, never clears. Mirrors the
// backend's GeneratedRuleEvaluator.specPathNoneMatches.
func noneMatches(inv *inventory.Inventory, d catalog.Detection) outcome {
	pattern, err := regexp.Compile(d.Value)
	if err != nil {
		return declinedFor(d.ObjectKind, "rule value is not a valid regex: "+d.Value, "")
	}
	rows, applies, _, decline := subject(inv, d)
	if decline.isDeclined {
		return decline
	}
	if !applies {
		return clear()
	}
	subj := ""
	if d.ObjectName != "" {
		subj += " named /" + d.ObjectName + "/"
	}
	if d.ObjectImage != "" {
		subj += " running " + d.ObjectImage
	}
	var scoped []row
	for _, r := range rows {
		if d.ObjectImage == "" || anyContains(images(r.spec), d.ObjectImage) {
			scoped = append(scoped, r)
		}
	}
	if len(scoped) == 0 && subj != "" {
		return declinedFor(d.ObjectKind, "no "+d.ObjectKind+subj+" is in this scan — the object this rule reads "+
			"was not collected or does not exist; absence is not clean", verifyList(d.ObjectKind))
	}
	var hits []row
	judged := 0
	for _, r := range scoped {
		var leaves []string
		resolved := false
		for _, path := range targets(d.Target) {
			for _, section := range []map[string]any{r.spec, r.status} {
				l, ok := resolveAt(section, strings.Split(path, "."))
				leaves = append(leaves, l...)
				resolved = resolved || ok
			}
		}
		if !resolved {
			continue
		}
		judged++
		hit := true
		for _, v := range leaves {
			if pattern.MatchString(v) {
				hit = false
				break
			}
		}
		if hit {
			hits = append(hits, r)
		}
	}
	if len(hits) > 0 {
		return fired(fmt.Sprintf("no value at %s matches /%s/ on %d %s object(s)%s",
			d.Target, d.Value, len(hits), d.ObjectKind, subj), refs(hits), len(hits))
	}
	if judged == 0 {
		return declinedFor(d.ObjectKind, "path "+d.Target+" is not in the collected projection of "+d.ObjectKind+subj,
			verifyList(d.ObjectKind))
	}
	return clear()
}

// resolveAt walks segments ("[]" fans out over an array) and collects the scalar leaves as text,
// with the same map-leaf reading as leavesAt. resolved reports whether the path RESOLVED: a leaf
// was reached, or a "[]" segment found an EMPTY array (present but holding nothing reads clean);
// a non-empty array whose elements all dead-end does not, so a leaf that is never projected reads
// as a gap rather than as clean. Mirrors the backend's collectAtPath.
func resolveAt(node any, segments []string) (leaves []string, resolved bool) {
	if node == nil {
		return nil, false
	}
	if len(segments) == 0 {
		switch n := node.(type) {
		case []any:
			return nil, false // an array leaf must be stepped into with "[]"
		case map[string]any:
			if n == nil {
				return nil, false
			}
		}
		return leavesAt(node, nil), true
	}
	m, ok := node.(map[string]any)
	if !ok || m == nil {
		return nil, false
	}
	seg := segments[0]
	each := strings.HasSuffix(seg, "[]")
	child, ok := m[strings.TrimSuffix(seg, "[]")]
	if !ok || child == nil {
		return nil, false
	}
	if !each {
		return resolveAt(child, segments[1:])
	}
	list, ok := child.([]any)
	if !ok {
		return nil, false
	}
	resolved = len(list) == 0
	for _, e := range list {
		l, ok := resolveAt(e, segments[1:])
		leaves = append(leaves, l...)
		resolved = resolved || ok
	}
	return leaves, resolved
}

func anyContains(items []string, sub string) bool {
	for _, s := range items {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// ---------- CODED_CHECK ----------

// codedChecks are the checks a CODED_CHECK rule names by target: a condition across several
// fields of ONE object that the regex vocabulary cannot state. Each returns nil when the
// projection lacks what it reads (never judged), empty when clean, else what is wrong, one line
// each. Mirrors the backend's CodedChecks; catalog.CodedCheckIDs lists the same ids.
var codedChecks = map[string]func(spec map[string]any) []string{
	"karpenter-kubelet-fields-unsupported": karpenterKubeletUnsupported,
}

// codedCheck runs the check a rule names on every object of its kind. Mirrors the backend's
// GeneratedRuleEvaluator.codedCheck.
func codedCheck(inv *inventory.Inventory, d catalog.Detection) outcome {
	check := codedChecks[d.Target]
	if check == nil {
		return declinedFor(d.ObjectKind, "no coded check named "+d.Target, "")
	}
	rows, applies, _, decline := subject(inv, d)
	if decline.isDeclined {
		return decline
	}
	if !applies {
		return clear()
	}
	if len(rows) == 0 && d.ObjectName != "" {
		return declinedFor(d.ObjectKind, "no "+d.ObjectKind+" named /"+d.ObjectName+"/ was found, and this rule "+
			"asks about that object's content; absence is not clean", verifyList(d.ObjectKind))
	}
	var hits []row
	var why []string
	unjudged := 0
	for _, r := range rows {
		found := check(r.spec)
		if found == nil {
			unjudged++
			continue
		}
		if len(found) == 0 {
			continue
		}
		hits = append(hits, r)
		if len(why) < 5 {
			why = append(why, r.ref+": "+strings.Join(found, "; "))
		}
	}
	if len(hits) > 0 {
		evidence := "coded check " + d.Target + " — " + strings.Join(why, " · ")
		if len(hits) > len(why) {
			evidence += fmt.Sprintf(" (%d objects affected; first %d described)", len(hits), len(why))
		}
		return fired(evidence, refs(hits), len(hits))
	}
	if unjudged > 0 {
		return declinedFor(d.ObjectKind, fmt.Sprintf("%d of %d %s lack the fields coded check %s reads",
			unjudged, len(rows), d.ObjectKind, d.Target), verifyList(d.ObjectKind))
	}
	return clear()
}

// mappedKubelet is every spec.kubelet field Karpenter 1.15's validateKubeletFieldsSupported lets a
// non-AL2023 family keep.
var mappedKubelet = map[string]bool{
	"clusterDNS": true, "maxPods": true, "podsPerCore": true, "systemReserved": true, "kubeReserved": true,
	"evictionHard": true, "evictionSoft": true, "evictionSoftGracePeriod": true, "evictionMaxPodGracePeriod": true,
	"imageGCHighThresholdPercent": true, "imageGCLowThresholdPercent": true, "cpuCFSQuota": true,
}

// karpenterKubeletUnsupported is what Karpenter 1.15 rejects on a projected EC2NodeClass: kubelet
// fields outside mappedKubelet, podsPerCore on Bottlerocket, more than one clusterDNS entry. The
// family is amiFamily, else the alias family. Empty for AL2023, Custom, no kubelet, or a family
// the spec does not name; nil when the row carries no kubeletKeys. Mirrors the backend's
// KarpenterPrRules.unsupportedKubeletInProjection.
func karpenterKubeletUnsupported(spec map[string]any) []string {
	if spec == nil {
		return nil
	}
	keyList, ok := spec["kubeletKeys"].([]any)
	if !ok {
		return nil
	}
	family := ""
	if f, _ := spec["amiFamily"].(string); strings.TrimSpace(f) != "" {
		family = strings.ToLower(f)
	} else if a, _ := spec["amiAliasFamily"].(string); strings.TrimSpace(a) != "" {
		family = strings.ToLower(a)
	}
	keys := map[string]bool{}
	for _, k := range keyList {
		if s, ok := k.(string); ok {
			keys[s] = true
		}
	}
	if family == "" || len(keys) == 0 || family == "al2023" || family == "custom" {
		return []string{}
	}
	var unmapped []string
	for k := range keys {
		if !mappedKubelet[k] || (k == "podsPerCore" && family == "bottlerocket") {
			unmapped = append(unmapped, k)
		}
	}
	sort.Strings(unmapped)
	out := []string{}
	if len(unmapped) > 0 {
		out = append(out, "spec.kubelet sets "+strings.Join(unmapped, ", ")+", which this family does not apply")
	}
	if keys["clusterDNS"] {
		n := 1
		switch c := spec["kubeletClusterDnsCount"].(type) {
		case int:
			n = c
		case float64:
			n = int(c)
		}
		if n > 1 {
			out = append(out, fmt.Sprintf("spec.kubelet.clusterDNS has %d entries; this family accepts one", n))
		}
	}
	if len(out) > 0 {
		out[0] = "AMI family " + family + ": " + out[0]
	}
	return out
}
