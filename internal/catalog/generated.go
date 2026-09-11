package catalog

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"
)

// ---------- k8s-rules/<source>/<version>.json ----------

// GeneratedRule is one rule extracted from a release note by the backend's rule pipeline and
// checked in as data. Each carries the note it came from verbatim, so a finding can show the
// sentence it rests on, and a detection that says how the rule is settled against a cluster.
//
// The source and version are not in the file body: the directory is the source
// ("kubernetes", or an add-on id) and the file name is the version the rule applies at, and
// a rule that carried them twice could disagree with where it sits.
type GeneratedRule struct {
	RuleID           string     `json:"ruleId"`
	SourceID         string     `json:"-"`
	AppliesAtVersion string     `json:"-"`
	Severity         Severity   `json:"severity"`
	Title            string     `json:"title"`
	Quote            string     `json:"quote"`
	Remediation      string     `json:"remediation"`
	VerifyCommand    string     `json:"verifyCommand"`
	Detection        Detection  `json:"detection"`
	Scope            *ScopeHint `json:"scope"`
	// Gate is a precondition on ANOTHER kind that a detectable rule needs before its detection
	// means anything (Argo CD's selector-format change only bites clusters whose cluster Secret
	// carries auto-label-cluster-info). No object satisfies it: the rule clears with the
	// precondition stated. Its kind could not be read: the rule declines.
	Gate *Gate `json:"gate"`
	// CoversNotes names further upstream notes this one rule answers. Coverage bookkeeping for
	// the authoring side; nothing here reads it.
	CoversNotes []string `json:"coversNotes"`
	// Enabled is absent for almost every rule; a rule switched off in the catalog stays listed
	// there so the decision is visible, and is skipped here.
	Enabled *bool `json:"enabled"`
}

// IsEnabled reports whether the rule is evaluated at all. Absent means enabled.
func (r GeneratedRule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// Slug is the rule id minus its source and version segments: "rtz-coredns-1.7-cpu-flag-removed"
// yields "cpu-flag-removed". A vendor that repeats a note per release ships it under one slug at
// several versions, and a hop crossing them fires each on the same objects; the slug is what
// lets the evaluator count that as one finding.
func (r GeneratedRule) Slug() string {
	prefix := "rtz-" + r.SourceID + "-" + r.AppliesAtVersion + "-"
	if strings.HasPrefix(r.RuleID, prefix) {
		return strings.TrimPrefix(r.RuleID, prefix)
	}
	// A hand-numbered id: drop the leading "rtz-<source>-" and the first dotted segment.
	rest := strings.TrimPrefix(r.RuleID, "rtz-"+r.SourceID+"-")
	if i := strings.Index(rest, "-"); i > 0 && strings.Contains(rest[:i], ".") {
		return rest[i+1:]
	}
	return rest
}

// Gate is the precondition schema: the scope-hint vocabulary, plus the reason it exists.
type Gate struct {
	Kind       string `json:"kind"`
	ObjectKind string `json:"objectKind"`
	Namespace  string `json:"namespace"`
	ObjectName string `json:"objectName"`
	Target     string `json:"target"`
	Value      string `json:"value"`
	Reason     string `json:"reason"`
}

// Detection says how a rule is decided. Kind names the predicate; the other fields are its
// parameters and which ones matter depends on the kind.
type Detection struct {
	Kind       string `json:"kind"`
	ObjectKind string `json:"objectKind"` // "Deployment|DaemonSet" fans out to both
	Namespace  string `json:"namespace"`
	ObjectName string `json:"objectName"` // regex over metadata.name
	Target     string `json:"target"`
	Value      string `json:"value"`
	Reason     string `json:"reason"` // NOT_DETECTABLE: why no predicate can settle it
}

// ScopeHint is the weaker predicate attached to a NOT_DETECTABLE rule. It names the objects
// worth reviewing; it settles nothing, so a hint that matches broadly is a longer list, never a
// false claim.
type ScopeHint struct {
	Kind       string `json:"kind"`
	ObjectKind string `json:"objectKind"`
	Namespace  string `json:"namespace"`
	ObjectName string `json:"objectName"` // regex over metadata.name, narrows the candidates
	Target     string `json:"target"`
	Value      string `json:"value"`
}

// Detection kinds, in the vocabulary the backend's pipeline emits.
const (
	DetectNotDetectable          = "NOT_DETECTABLE"
	DetectAPIVersionInUse        = "API_VERSION_IN_USE"
	DetectKindPresent            = "KIND_PRESENT"
	DetectAnnotationKeyPresent   = "ANNOTATION_KEY_PRESENT"
	DetectLabelKeyPresent        = "LABEL_KEY_PRESENT"
	DetectSpecFieldPresent       = "SPEC_FIELD_PRESENT"
	DetectSpecFieldEquals        = "SPEC_FIELD_EQUALS"
	DetectSpecPathMatches        = "SPEC_PATH_MATCHES"
	DetectCRDServedVersion       = "CRD_SERVED_VERSION"
	DetectImageRepositoryPresent = "IMAGE_REPOSITORY_PRESENT"
	DetectVersionSkewExceeds     = "VERSION_SKEW_EXCEEDS"
)

// KnownDetectionKinds is every kind the pipeline can emit. A rule naming anything else is a
// catalog defect, caught by `catalog validate` rather than by an evaluator's default branch.
var KnownDetectionKinds = map[string]bool{
	DetectNotDetectable: true, DetectAPIVersionInUse: true, DetectKindPresent: true,
	DetectAnnotationKeyPresent: true, DetectLabelKeyPresent: true, DetectSpecFieldPresent: true,
	DetectSpecFieldEquals: true, DetectSpecPathMatches: true, DetectCRDServedVersion: true,
	DetectImageRepositoryPresent: true, DetectVersionSkewExceeds: true,
}

// ObjectKinds splits a "Deployment|DaemonSet" object kind into its members.
func (d Detection) ObjectKinds() []string {
	var out []string
	for _, k := range strings.Split(d.ObjectKind, "|") {
		if k = strings.TrimSpace(k); k != "" {
			out = append(out, k)
		}
	}
	return out
}

// Validate reports what is wrong with a rule's shape, or nil.
func (r GeneratedRule) Validate() error {
	if r.RuleID == "" {
		return fmt.Errorf("rule has no ruleId")
	}
	d := r.Detection
	if !KnownDetectionKinds[d.Kind] {
		return fmt.Errorf("%s: unknown detection kind %q", r.RuleID, d.Kind)
	}
	switch d.Kind {
	case DetectNotDetectable:
		if d.Reason == "" {
			return fmt.Errorf("%s: NOT_DETECTABLE without a reason", r.RuleID)
		}
	case DetectAPIVersionInUse, DetectCRDServedVersion:
		if d.Target == "" {
			return fmt.Errorf("%s: %s without a target", r.RuleID, d.Kind)
		}
	case DetectKindPresent:
		if d.ObjectKind == "" {
			return fmt.Errorf("%s: KIND_PRESENT without an objectKind", r.RuleID)
		}
	case DetectVersionSkewExceeds:
		// Names a component (kubelet, kube-proxy) and the minors it may lag by; no object kind.
		if d.Target == "" || d.Value == "" {
			return fmt.Errorf("%s: VERSION_SKEW_EXCEEDS needs a target component and a value", r.RuleID)
		}
	default:
		if d.ObjectKind == "" || d.Target == "" {
			return fmt.Errorf("%s: %s needs objectKind and target", r.RuleID, d.Kind)
		}
		if (d.Kind == DetectSpecFieldEquals || d.Kind == DetectSpecPathMatches) && d.Value == "" {
			return fmt.Errorf("%s: %s needs a value", r.RuleID, d.Kind)
		}
	}
	if r.Scope != nil && (r.Scope.Kind == "" || r.Scope.ObjectKind == "") {
		return fmt.Errorf("%s: scope hint needs kind and objectKind", r.RuleID)
	}
	if r.Gate != nil && (r.Gate.Kind == "" || r.Gate.ObjectKind == "" || r.Gate.Reason == "") {
		return fmt.Errorf("%s: gate needs kind, objectKind and a reason", r.RuleID)
	}
	return nil
}

// loadGeneratedRules reads every k8s-rules/<source>/<version>.json. Files whose name starts with
// "_" are the pipeline's build-gate sidecars, not rule sets.
func loadGeneratedRules(fsys fs.FS, root string) ([]GeneratedRule, error) {
	matches, err := fs.Glob(fsys, path(root, "k8s-rules/*/*.json"))
	if err != nil {
		return nil, fmt.Errorf("glob k8s-rules: %w", err)
	}
	var out []GeneratedRule
	for _, name := range matches {
		parts := strings.Split(name, "/")
		file := parts[len(parts)-1]
		if strings.HasPrefix(file, "_") {
			continue
		}
		source := parts[len(parts)-2]
		version := strings.TrimSuffix(file, ".json")
		if MinorKey(version) == 0 && source == "kubernetes" {
			return nil, fmt.Errorf("%s: file name %q is not a Kubernetes minor", name, version)
		}
		var rules []GeneratedRule
		if err := readJSON(fsys, name, &rules); err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for i := range rules {
			rules[i].SourceID = source
			rules[i].AppliesAtVersion = version
			if err := rules[i].Validate(); err != nil {
				return nil, fmt.Errorf("%s: %w", name, err)
			}
			if seen[rules[i].RuleID] {
				return nil, fmt.Errorf("%s: duplicate ruleId %s", name, rules[i].RuleID)
			}
			seen[rules[i].RuleID] = true
		}
		out = append(out, rules...)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].SourceID != out[j].SourceID {
			return out[i].SourceID < out[j].SourceID
		}
		if a, b := MinorKey(out[i].AppliesAtVersion), MinorKey(out[j].AppliesAtVersion); a != b {
			return a < b
		}
		return out[i].RuleID < out[j].RuleID
	})
	return out, nil
}
