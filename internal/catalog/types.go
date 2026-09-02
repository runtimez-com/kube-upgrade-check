package catalog

// Severity is the finding severity ladder, ordered so a numeric comparison works.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityMedium   Severity = "MEDIUM"
	SeverityLow      Severity = "LOW"
	SeverityInfo     Severity = "INFO"
)

// Rank orders severities; 0 means unrecognised, which callers must never treat as harmless.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityInfo:
		return 1
	default:
		return 0
	}
}

// ScoreImpact is the per-severity contribution to the 0-100 score. INFO contributes nothing
// by contract: an advisory item can cap a score through its ceiling, never raise one.
func (s Severity) ScoreImpact() int {
	switch s {
	case SeverityCritical:
		return 40
	case SeverityHigh:
		return 20
	case SeverityMedium:
		return 8
	case SeverityLow:
		return 3
	default:
		return 0
	}
}

// ---------- k8s-deprecations/removed-apis.json ----------

// DeprecationRule is one removed or deprecated API row.
type DeprecationRule struct {
	APIVersion   string `json:"apiVersion"`
	Kind         string `json:"kind"`
	DeprecatedIn string `json:"deprecatedIn"`
	RemovedIn    string `json:"removedIn"`
	Replacement  string `json:"replacement"`
	RuleID       string `json:"ruleId"`
	Title        string `json:"title"`
	Remediation  string `json:"remediation"`
	Provisional  bool   `json:"provisional"`
	SourceNote   string `json:"sourceNote"`
}

// Lifecycle is the detector table row: the same version facts without the rule prose, and
// with wildcard kinds allowed so a whole group/version can be covered by one row.
type Lifecycle struct {
	APIVersion   string `json:"apiVersion"`
	Kind         string `json:"kind"`
	DeprecatedIn string `json:"deprecatedIn"`
	RemovedIn    string `json:"removedIn"`
	Replacement  string `json:"replacement"`
	Provisional  bool   `json:"provisional"`
}

type removedAPIsFile struct {
	CatalogRules  []DeprecationRule `json:"catalogRules"`
	DetectorTable []Lifecycle       `json:"detectorTable"`
}

// ---------- k8s-config-breakers/config-breakers.json ----------

// ConfigBreakerRule is a control-plane flag or kubelet config setting that a target version
// removes, locks, or rejects.
type ConfigBreakerRule struct {
	RuleID              string   `json:"ruleId"`
	Source              string   `json:"source"`    // componentFlag | kubeletConfig
	Component           string   `json:"component"` // comma-separated set
	Selectors           []string `json:"selectors"`
	Condition           string   `json:"condition"`
	Value               string   `json:"value"`
	DeprecatedInVersion string   `json:"deprecatedInVersion"`
	AppliesFromVersion  string   `json:"appliesFromVersion"`
	Severity            Severity `json:"severity"`
	DeprecatedSeverity  Severity `json:"deprecatedSeverity"`
	Title               string   `json:"title"`
	Remediation         string   `json:"remediation"`
	Provisional         bool     `json:"provisional"`
	Detectable          *bool    `json:"detectable"` // pointer: absent means true
}

// IsDetectable reports whether this rule can be evaluated from collected data at all.
// Absent in JSON means true, so a new rule is checked unless it opts out.
func (r ConfigBreakerRule) IsDetectable() bool { return r.Detectable == nil || *r.Detectable }

// Components splits the comma-separated component set.
func (r ConfigBreakerRule) Components() []string { return splitCSV(r.Component) }

type configBreakersFile struct {
	Rules []ConfigBreakerRule `json:"rules"`
}

// ---------- k8s-plugins/removed-volume-plugins.json ----------

// VolumePluginRule is an in-tree volume plugin that a target version disables or removes.
type VolumePluginRule struct {
	VolumeSourceKey      string   `json:"volumeSourceKey"`
	DeprecatedIn         string   `json:"deprecatedIn"`
	RemovedIn            string   `json:"removedIn"`
	DisabledByDefaultIn  string   `json:"disabledByDefaultIn"`
	Replacement          string   `json:"replacement"`
	Severity             Severity `json:"severity"`
	Remediation          string   `json:"remediation"`
	Provisional          bool     `json:"provisional"`
	Provisioner          string   `json:"provisioner"`
	ReplacementCSIDriver string   `json:"replacementCsiDriver"`
}

// BreakIn is the version at which the plugin actually stops working.
//
// A plugin disabled by default breaks then, not at its formal removal — gitRepo stops
// mounting in 1.33 though it is only deleted later, and anchoring on removal would report it
// three minors too late.
func (r VolumePluginRule) BreakIn() string {
	if r.DisabledByDefaultIn != "" {
		return r.DisabledByDefaultIn
	}
	return r.RemovedIn
}

type volumePluginsFile struct {
	Plugins []VolumePluginRule `json:"plugins"`
}

// ---------- k8s-node-runtime/node-runtime-rules.json ----------

// NodeRuntimeRule is a node-level breaking change: container runtime, cgroup version,
// kubelet flags.
type NodeRuntimeRule struct {
	RuleID           string   `json:"ruleId"`
	Kind             string   `json:"kind"`
	StatusField      string   `json:"statusField"`
	Condition        string   `json:"condition"`
	Value            string   `json:"value"`
	RemovedInVersion string   `json:"removedInVersion"`
	Severity         Severity `json:"severity"`
	Title            string   `json:"title"`
	Remediation      string   `json:"remediation"`
	Provisional      bool     `json:"provisional"`
	Detectable       *bool    `json:"detectable"`
}

// IsDetectable reports whether the rule can be checked from node status.
func (r NodeRuntimeRule) IsDetectable() bool { return r.Detectable == nil || *r.Detectable }

type nodeRuntimeFile struct {
	Rules []NodeRuntimeRule `json:"rules"`
}

// ---------- k8s-advisory/advisory-breakers.json ----------

// AdvisoryRule is a change worth reading about on the way to a version, with no way to check
// it from the cluster. It always reports as INFO and never moves the score.
type AdvisoryRule struct {
	RuleID        string `json:"ruleId"`
	Version       string `json:"version"`
	Title         string `json:"title"`
	Remediation   string `json:"remediation"`
	VerifyCommand string `json:"verifyCommand"`
	Provisional   bool   `json:"provisional"`
}

type advisoryFile struct {
	Rules []AdvisoryRule `json:"rules"`
}

// ---------- k8s-addons/*.json ----------

// AddonDetect says which container images identify an add-on.
type AddonDetect struct {
	ImageSuffixes []string `json:"imageSuffixes"`
}

// AddonSource records where a catalog's facts were transcribed from, and when.
//
// LastVerified is what makes staleness reportable: these are hand-read vendor tables, and a
// catalog nobody has checked in a year should say so rather than imply currency.
type AddonSource struct {
	URL          string `json:"url"`
	Ref          string `json:"ref"`
	LastVerified string `json:"lastVerified"`
	Note         string `json:"note"`
}

// SupportWindow is one vendor-published row: this add-on version supports these Kubernetes
// minors.
type SupportWindow struct {
	Version string `json:"version"`
	MinK8s  string `json:"minK8s"`
	MaxK8s  string `json:"maxK8s"`
}

// AddonRule is a predicate-backed check against cluster objects, carrying the vendor's own
// words so a finding can be trusted without taking our word for it.
type AddonRule struct {
	RuleID                    string         `json:"ruleId"`
	Kind                      string         `json:"kind"`
	Severity                  Severity       `json:"severity"`
	ScoreImpact               int            `json:"scoreImpact"`
	AppliesWhenVersionAtLeast string         `json:"appliesWhenVersionAtLeast"`
	AppliesWhenVersionBelow   string         `json:"appliesWhenVersionBelow"`
	Params                    map[string]any `json:"params"`
	Title                     string         `json:"title"`
	Recommendation            string         `json:"recommendation"`
	Quote                     string         `json:"quote"`
	SourceURL                 string         `json:"sourceUrl"`
}

// UpgradeNote is a vendor's own breaking-change note for one add-on version.
type UpgradeNote struct {
	Version       string `json:"version"`
	Title         string `json:"title"`
	Quote         string `json:"quote"`
	SourceURL     string `json:"sourceUrl"`
	VerifyCommand string `json:"verifyCommand"`
}

// Addon is one catalog file.
type Addon struct {
	AddonID        string          `json:"addonId"`
	DisplayName    string          `json:"displayName"`
	Detect         AddonDetect     `json:"detect"`
	Source         AddonSource     `json:"source"`
	SupportWindows []SupportWindow `json:"supportWindows"`
	// LatestKnownVersion carries the ceiling for add-ons that publish no compatibility
	// matrix at all. Without it, an add-on with no windows has no version anchor and its
	// upgrade notes never render.
	LatestKnownVersion string        `json:"latestKnownVersion"`
	InventoryKinds     []string      `json:"inventoryKinds"`
	Rules              []AddonRule   `json:"rules"`
	UpgradeNotes       []UpgradeNote `json:"upgradeNotes"`
}

// ---------- k8s-adoption/adoption-suggestions.json ----------

// AdoptionRule is inverse polarity: a feature the target version makes available that this
// cluster is not using yet. Never a break, never scored.
type AdoptionRule struct {
	RuleID             string `json:"ruleId"`
	AvailableInVersion string `json:"availableInVersion"`
	PredicateKey       string `json:"predicateKey"`
	// FieldPresence says which way the predicate reads: true means "the field is absent,
	// so the feature is unused", false means the reverse.
	FieldPresence bool   `json:"fieldPresence"`
	Title         string `json:"title"`
	Benefit       string `json:"benefit"`
	Remediation   string `json:"remediation"`
}

type adoptionFile struct {
	Rules []AdoptionRule `json:"rules"`
}
