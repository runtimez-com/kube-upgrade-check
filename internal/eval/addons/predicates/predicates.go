// Package predicates holds the checks an add-on catalog rule can ask for.
//
// A predicate answers one question about cluster objects and returns either evidence or
// nothing. It never decides severity, never scores, and never throws: the catalog owns the
// judgement, the predicate owns the observation.
//
// The rule they all share is that silence means "I cannot answer", not "the answer is no". A
// resource kind that could not be read, a field the collector never populated, a malformed
// pattern in the catalog: each of those makes a predicate decline. Firing on absent data would
// accuse someone based on a gap in our own collection, and reporting absent data as clean
// would be the false all-clear this whole tool exists to prevent.
package predicates

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// maxNamed bounds how many objects one piece of evidence lists before it collapses to a count.
const maxNamed = 10

// Context is the cluster data a predicate may inspect.
//
// KindWasRead is the load-bearing part: it distinguishes a kind that was read and had no
// objects from one that could not be read at all.
type Context struct {
	// AddonID and Label identify the add-on for evidence text.
	Label string
	// InstalledVersion may be empty when it could not be resolved.
	InstalledVersion string

	// CRDNames holds every CustomResourceDefinition name, lowercased. Empty means the CRD
	// list itself was not readable, which is why predicates decline on an empty set rather
	// than concluding a CRD is missing.
	CRDNames map[string]bool
	// CRDServedVersions maps a lowercased CRD name to the versions it still serves.
	CRDServedVersions map[string]map[string]bool
	// CRDFlags holds curated booleans about how a CRD was installed. A flag that is absent is
	// unknown, which is not the same as false.
	CRDFlags map[string]map[string]bool

	// Rows holds custom resource instances by kind. A kind that could not be read is ABSENT
	// from this map; a kind that was read and had none maps to an empty slice.
	Rows map[string][]Row
	// Labels holds gate objects by kind, for rules that condition on another object's labels.
	Labels map[string][]Row
}

// Row is one custom resource instance as a predicate sees it.
type Row struct {
	Kind           string
	Namespace      string
	Name           string
	Labels         map[string]string
	AnnotationKeys []string
	Spec           map[string]any
}

// Ref is the "namespace/name" form used in evidence.
func (r Row) Ref() string {
	if r.Namespace == "" {
		return r.Name
	}
	return r.Namespace + "/" + r.Name
}

// KindWasRead reports whether a kind was successfully collected.
func (c Context) KindWasRead(kind string) bool {
	_, ok := c.Rows[NormalizeKind(kind)]
	return ok
}

// RowsOf returns the instances of a kind, or nothing when it was not read.
func (c Context) RowsOf(kind string) []Row { return c.Rows[NormalizeKind(kind)] }

// NormalizeKind strips the scoping suffix a catalog may attach to a kind.
//
// A shared core kind is written "ConfigMap@namespace" to say the read should stay inside the
// add-on's own namespace. That suffix is an instruction to the collector, not part of the kind,
// and a predicate comparing the raw string against collected data matches nothing at all. Three
// shipped rules were silently inert for exactly this reason: they passed validation, they read
// as covered, and they could never fire.
func NormalizeKind(declared string) string {
	kind, _, _ := strings.Cut(declared, "@")
	return strings.TrimSpace(kind)
}

// VersionText renders the installed version for evidence, saying so when it is unknown.
func (c Context) VersionText() string {
	if strings.TrimSpace(c.InstalledVersion) == "" {
		return "(version unresolved)"
	}
	return c.InstalledVersion
}

// Outcome is what a predicate concluded.
type Outcome int

const (
	// Fired means the condition holds and Evidence says why.
	Fired Outcome = iota
	// Clear means the check ran against real data and the condition does not hold.
	Clear
	// Declined means the check could not run: a kind that was not readable, a field the
	// collector never populated, a pattern the catalog wrote wrong.
	//
	// Keeping this apart from Clear is the whole point. Collapsing them lets an unreadable
	// cluster report the same clean result as a healthy one, which is the failure this tool
	// exists to prevent.
	Declined
)

// Result is a predicate's conclusion plus the words to explain it.
type Result struct {
	Outcome  Outcome
	Evidence string
	// Reason explains a Declined outcome in terms the reader can act on.
	Reason string
}

func fired(format string, args ...any) Result {
	return Result{Outcome: Fired, Evidence: fmt.Sprintf(format, args...)}
}

func clear() Result { return Result{Outcome: Clear} }

func declined(format string, args ...any) Result {
	return Result{Outcome: Declined, Reason: fmt.Sprintf(format, args...)}
}

// Predicate is one catalog-selectable check.
type Predicate interface {
	Kind() string
	Evaluate(ctx Context, params map[string]any) Result
}

// Registry maps each predicate kind to its implementation.
//
// The catalog validator checks every rule's kind against this map, so a rule naming a predicate
// nobody implemented fails the build rather than shipping as a rule that silently never fires.
func Registry() map[string]Predicate {
	list := []Predicate{
		crdAbsent{}, crdServedVersion{}, crFieldAbsent{},
		crdFlagSet{}, crSelectorFormat{}, crAnnotationKey{}, crSpecListContains{},
	}
	out := make(map[string]Predicate, len(list))
	for _, p := range list {
		out[p.Kind()] = p
	}
	return out
}

// ---------- crdAbsent ----------

type crdAbsent struct{}

func (crdAbsent) Kind() string { return "crdAbsent" }

// Evaluate fires when a CRD the running add-on needs is not installed.
func (crdAbsent) Evaluate(ctx Context, params map[string]any) Result {
	name := strings.ToLower(str(params, "crdName"))
	if name == "" {
		return declined("the rule names no CRD to look for")
	}
	// An empty CRD list cannot tell "not installed" from "not readable", so it never fires.
	if len(ctx.CRDNames) == 0 {
		return declined("no CustomResourceDefinitions could be read, so a missing CRD cannot be told apart from an unreadable list")
	}
	if ctx.CRDNames[name] {
		return clear()
	}
	return fired("%s %s is running, but the CRD %s that it requires is not installed in this cluster.",
		ctx.Label, ctx.VersionText(), name)
}

// ---------- crdServedVersion ----------

type crdServedVersion struct{}

func (crdServedVersion) Kind() string { return "crdServedVersion" }

// Evaluate fires when named CRDs still serve an API version the add-on upgrade removes.
func (crdServedVersion) Evaluate(ctx Context, params map[string]any) Result {
	names := strList(params, "crdNames")
	served := strings.TrimSpace(str(params, "servedVersion"))
	if len(names) == 0 || served == "" {
		return declined("the rule names no CRD or no version to look for")
	}
	if len(ctx.CRDServedVersions) == 0 {
		return declined("no CustomResourceDefinitions could be read, so their served versions are unknown")
	}
	var hits []string
	for _, raw := range names {
		name := strings.ToLower(strings.TrimSpace(raw))
		if versions, ok := ctx.CRDServedVersions[name]; ok && versions[served] {
			hits = append(hits, name)
		}
	}
	if len(hits) == 0 {
		return clear()
	}
	verb := "serve"
	if len(hits) == 1 {
		verb = "serves"
	}
	return fired("%s still %s %s in this cluster.", strings.Join(hits, ", "), verb, served)
}

// ---------- crdFlagSet ----------

type crdFlagSet struct{}

func (crdFlagSet) Kind() string { return "crdFlagSet" }

// Evaluate fires when a curated boolean about how a CRD was installed is present and true.
//
// Only a true flag fires. A true value proves how the object was applied; a false one proves
// only that this particular signal is absent, and a Helm-managed install sets neither.
func (crdFlagSet) Evaluate(ctx Context, params map[string]any) Result {
	name := strings.ToLower(str(params, "crdName"))
	flags := strList(params, "anyOfFlags")
	if name == "" || len(flags) == 0 {
		return declined("the rule names no CRD or no flags to look for")
	}
	if len(ctx.CRDNames) == 0 {
		return declined("no CustomResourceDefinitions could be read")
	}
	if !ctx.CRDNames[name] {
		return clear()
	}

	var matched []string
	readable := false
	for _, flag := range flags {
		value, ok := ctx.CRDFlags[name][strings.TrimSpace(flag)]
		if !ok {
			continue
		}
		readable = true
		if value {
			matched = append(matched, flag)
		}
	}
	// Not one flag was readable, so this question simply cannot be answered here.
	if !readable {
		return declined("none of the install markers on %s were collected, so how it was applied is unknown", name)
	}
	if len(matched) == 0 {
		return clear()
	}
	return fired("The CRD %s carries %s, which shows how it was installed.",
		name, strings.Join(matched, " and "))
}

// ---------- crAnnotationKey ----------

type crAnnotationKey struct{}

func (crAnnotationKey) Kind() string { return "crAnnotationKey" }

// Evaluate fires when objects of a kind carry an annotation key matching a pattern.
//
// Keys only, never values: the annotations this matches hold raw web-server configuration, and
// printing a value into a finding would put it in a terminal and then in a ticket.
func (crAnnotationKey) Evaluate(ctx Context, params map[string]any) Result {
	kind := NormalizeKind(str(params, "crKind"))
	patternText := str(params, "annotationKeyPattern")
	if kind == "" || patternText == "" {
		return declined("the rule names no kind or no annotation pattern")
	}
	if !ctx.KindWasRead(kind) {
		return declined("%s objects could not be read", kind)
	}
	pattern, err := regexp.Compile(patternText)
	if err != nil {
		// A malformed catalog pattern must not accuse anyone.
		return declined("the rule's annotation pattern is not valid, so nothing was checked")
	}

	offenders := map[string]bool{}
	keys := map[string]bool{}
	for _, row := range ctx.RowsOf(kind) {
		for _, key := range row.AnnotationKeys {
			if pattern.MatchString(key) {
				offenders[row.Ref()] = true
				keys[key] = true
			}
		}
	}
	if len(offenders) == 0 {
		return clear()
	}
	return fired("%d %s carry %s: %s.",
		len(offenders), plural(kind, len(offenders)), joinSorted(keys, " and "), namedList(offenders))
}

// ---------- crSpecListContains ----------

type crSpecListContains struct{}

func (crSpecListContains) Kind() string { return "crSpecListContains" }

// Evaluate fires when a projected list field on an object contains one of the named values.
func (crSpecListContains) Evaluate(ctx Context, params map[string]any) Result {
	kind := NormalizeKind(str(params, "crKind"))
	field := strings.TrimSpace(str(params, "field"))
	anyOf := strList(params, "anyOf")
	if kind == "" || field == "" || len(anyOf) == 0 {
		return declined("the rule names no kind, field or values to look for")
	}
	if !ctx.KindWasRead(kind) {
		return declined("%s objects could not be read", kind)
	}
	want := map[string]bool{}
	for _, v := range anyOf {
		if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
			want[v] = true
		}
	}

	offenders := map[string]bool{}
	matched := map[string]bool{}
	for _, row := range ctx.RowsOf(kind) {
		values, ok := row.Spec[field].([]any)
		// An absent field means the collector never populated it for this object. Skipping it
		// is right; judging it would turn a projection gap into a verdict. Present-and-empty
		// means it was populated and found nothing, which is genuinely clean.
		if !ok {
			continue
		}
		for _, raw := range values {
			value, isString := raw.(string)
			if !isString {
				continue
			}
			value = strings.ToLower(strings.TrimSpace(value))
			if want[value] {
				offenders[row.Ref()] = true
				matched[value] = true
			}
		}
	}
	if len(offenders) == 0 {
		return clear()
	}
	return fired("%d %s set %s to %s: %s.",
		len(offenders), plural(kind, len(offenders)), field, joinSorted(matched, " and "), namedList(offenders))
}

// ---------- crFieldAbsent ----------

type crFieldAbsent struct{}

func (crFieldAbsent) Kind() string { return "crFieldAbsent" }

// Evaluate fires when objects are missing keys a later add-on version requires.
//
// Offenders are grouped by kind rather than pooled. A derived object inherits the field from
// the object that created it, so one misconfigured parent on a large fleet produces one parent
// plus hundreds of children. Pooling them would report hundreds of resources for a single
// object anyone actually has to edit.
func (crFieldAbsent) Evaluate(ctx Context, params map[string]any) Result {
	kinds := strList(params, "crKinds")
	field := strings.TrimSpace(str(params, "field"))
	required := strList(params, "requiredKeys")
	if len(kinds) == 0 || field == "" || len(required) == 0 {
		return declined("the rule names no kinds, field or required keys")
	}

	type group struct {
		kind      string
		offenders []string
	}
	var groups []group

	for _, declared := range kinds {
		kind := NormalizeKind(declared)
		if kind == "" {
			continue
		}
		// Declining the whole rule, not just this kind: answering from the kinds that did read
		// would present a partial answer with a complete one's confidence.
		if !ctx.KindWasRead(kind) {
			return declined("%s objects could not be read", kind)
		}
		g := group{kind: kind}
		for _, row := range ctx.RowsOf(kind) {
			target, ok := row.Spec[field].(map[string]any)
			if !ok {
				continue
			}
			var missing []string
			for _, key := range required {
				value, present := target[strings.TrimSpace(key)]
				if !present || value == nil || strings.TrimSpace(fmt.Sprintf("%v", value)) == "" {
					missing = append(missing, field+"."+strings.TrimSpace(key))
				}
			}
			if len(missing) > 0 {
				g.offenders = append(g.offenders, fmt.Sprintf("%s (missing %s)", row.Ref(), strings.Join(missing, ", ")))
			}
		}
		if len(g.offenders) > 0 {
			groups = append(groups, g)
		}
	}
	if len(groups) == 0 {
		return clear()
	}

	var clauses []string
	for _, g := range groups {
		sort.Strings(g.offenders)
		shown := g.offenders
		more := ""
		if len(shown) > maxNamed {
			more = fmt.Sprintf(" (+%d more)", len(shown)-maxNamed)
			shown = shown[:maxNamed]
		}
		clauses = append(clauses, fmt.Sprintf("%d %s: %s%s",
			len(g.offenders), plural(g.kind, len(g.offenders)), strings.Join(shown, "; "), more))
	}
	return fired("Missing required %s fields. %s.", field, strings.Join(clauses, ", "))
}

// ---------- crSelectorFormat ----------

type crSelectorFormat struct{}

func (crSelectorFormat) Kind() string { return "crSelectorFormat" }

// Evaluate fires when a field's value does not match the format a later version requires.
func (crSelectorFormat) Evaluate(ctx Context, params map[string]any) Result {
	kinds := strList(params, "crKinds")
	field := strings.TrimSpace(str(params, "field"))
	patternText := str(params, "expectedPattern")
	if len(kinds) == 0 || field == "" || patternText == "" {
		return declined("the rule names no kinds, field or expected pattern")
	}
	// Every declared kind must have been read; a partially-read inventory cannot support a
	// complete-sounding answer.
	var declared []string
	for _, raw := range kinds {
		kind := NormalizeKind(raw)
		if kind == "" {
			continue
		}
		if !ctx.KindWasRead(kind) {
			return declined("%s objects could not be read", kind)
		}
		declared = append(declared, kind)
	}
	if len(declared) == 0 {
		return declined("the rule names no usable kinds")
	}

	expected, err := regexp.Compile(patternText)
	if err != nil {
		return declined("the rule's expected pattern is not valid, so nothing was checked")
	}
	if !gateSatisfied(ctx, params) {
		return clear()
	}

	// Every declared kind is scanned. Demanding that all of them be readable and then examining
	// only the first would make the extra kinds a precondition for an answer they never inform.
	offenders := map[string]bool{}
	stale := map[string]bool{}
	for _, kind := range declared {
		for _, row := range ctx.RowsOf(kind) {
			values, ok := row.Spec[field].(map[string]any)
			if !ok {
				continue
			}
			for key := range values {
				if !expected.MatchString(key) {
					offenders[kind+" "+row.Ref()] = true
					stale[key] = true
				}
			}
		}
	}
	if len(offenders) == 0 {
		return clear()
	}
	return fired("%d object(s) across %s use %s keys that do not match the expected format (%s): %s.",
		len(offenders), strings.Join(declared, ", "), field,
		joinSorted(stale, ", "), namedList(offenders))
}

// gateSatisfied applies an optional guard on another object's labels, so a rule can be scoped
// to clusters where a particular component is present.
func gateSatisfied(ctx Context, params map[string]any) bool {
	gateKind := strings.TrimSpace(str(params, "gateKind"))
	gateLabel := strings.TrimSpace(str(params, "gateLabel"))
	if gateKind == "" || gateLabel == "" {
		return true
	}
	want := str(params, "gateLabelEquals")
	for _, row := range ctx.Labels[gateKind] {
		value, ok := row.Labels[gateLabel]
		if !ok {
			continue
		}
		if want == "" || value == want {
			return true
		}
	}
	return false
}

// ---------- shared helpers ----------

func str(params map[string]any, key string) string {
	if v, ok := params[key].(string); ok {
		return v
	}
	return ""
}

func strList(params map[string]any, key string) []string {
	raw, ok := params[key].([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, v := range raw {
		if s, ok := v.(string); ok && strings.TrimSpace(s) != "" {
			out = append(out, s)
		}
	}
	return out
}

func plural(kind string, n int) string {
	if n == 1 {
		return kind
	}
	return kind + "s"
}

func joinSorted(set map[string]bool, sep string) string {
	keys := make([]string, 0, len(set))
	for k := range set {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, sep)
}

// namedList renders offenders, collapsing to a count past the display limit so one finding
// cannot fill a terminal.
func namedList(set map[string]bool) string {
	names := make([]string, 0, len(set))
	for name := range set {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) <= maxNamed {
		return strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s (+%d more)", strings.Join(names[:maxNamed], ", "), len(names)-maxNamed)
}
