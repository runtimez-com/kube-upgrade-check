package inventory

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// The release-note rules were written against the projection the runtimez agent ships to the
// hosted product: a curated, keys-not-values view of each object (runtimez_agent CONTRACT.md).
// A rule that reads cert-manager's `rotationPolicySet` or CoreDNS's `corednsPluginOptions`
// reads a DERIVED key, not a field of the raw object. For both products to settle the same rule
// the same way, this tool derives the same keys from the raw object it listed.
//
// The projectors below cover every derived key a shipped rule, hint or gate names. Kinds with
// no projector keep the top-level raw keys the rules ask for (the `Projection.Keep` list), which
// is exact for a raw field such as ServiceEntry.resolution or Service.ports[].name.
//
// Values that could carry a secret never leave here: ConfigMap and Secret contribute key NAMES
// only, a Corefile contributes directive and option names, an issuer contributes which blocks
// it configures. The report is printed to terminals and pasted into tickets.

// projector derives the spec the rules read from one raw object. The object is the whole
// unstructured item (metadata, spec, data, ...), and base is the top-level raw spec keys the
// caller already kept, which the projector extends.
type projector func(obj map[string]any, base map[string]any) map[string]any

var projectors = map[string]projector{
	"Deployment":  projectWorkload,
	"StatefulSet": projectWorkload,
	"DaemonSet":   projectWorkload,
	"ReplicaSet":  projectWorkload,
	"Job":         projectWorkload,
	"CronJob":     projectWorkload,
	"Pod":         projectWorkload,

	"ConfigMap": projectConfigMap,
	"Secret":    projectSecret,

	"Middleware":      projectMiddleware,
	"IngressRoute":    projectIngressRoute,
	"IngressRouteTCP": projectIngressRoute,

	"Issuer":        projectIssuer,
	"ClusterIssuer": projectIssuer,
	"Certificate":   projectCertificate,

	"Application":    projectApplication,
	"ApplicationSet": projectApplicationSet,
	"AppProject":     projectAppProject,

	"NodePool":     projectNodePool,
	"NodeClaim":    projectNodeClaim,
	"EC2NodeClass": projectEC2NodeClass,
}

// HasProjector reports whether a kind's rows are derived rather than raw.
func HasProjector(kind string) bool { _, ok := projectors[kind]; return ok }

// projectSpec is the spec recorded for one listed object: the raw top-level keys the projection
// asked for, extended by the kind's projector when it has one.
func projectSpec(kind string, obj map[string]any, projection *Projection) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	var base map[string]any
	if spec != nil {
		base = project(spec, projection)
	} else {
		base = map[string]any{}
	}
	if p, ok := projectors[kind]; ok {
		return p(obj, base)
	}
	if spec == nil {
		return nil
	}
	return base
}

// ---------- workloads ----------

// projectWorkload flattens the pod template the way the agent does: containers with their
// image, command and args; native sidecars (initContainers with restartPolicy Always) as a
// second list; volumes as name plus source-type keys; the scheduling fields; and the two
// booleans the Karpenter rules read, written on every row so a rule can clear on them.
func projectWorkload(obj map[string]any, base map[string]any) map[string]any {
	out := base
	kind, _ := obj["kind"].(string)
	spec, _ := obj["spec"].(map[string]any)
	var pod map[string]any
	switch kind {
	case "Pod":
		pod = spec
	case "CronJob":
		pod = mapAt(spec, "jobTemplate", "spec", "template", "spec")
	default:
		pod = mapAt(spec, "template", "spec")
	}
	// The raw template is never carried; a rule on `template` reads nothing.
	delete(out, "template")
	delete(out, "jobTemplate")
	if pod == nil {
		return out
	}
	out["containers"] = projectContainers(listAt(pod, "containers"), false)
	out["initContainers"] = projectContainers(listAt(pod, "initContainers"), true)
	if volumes, ok := pod["volumes"].([]any); ok {
		out["volumes"] = projectVolumes(volumes)
	}
	if ns, ok := pod["nodeSelector"].(map[string]any); ok && len(ns) > 0 {
		out["nodeSelector"] = ns
	}
	if tolerations := listAt(pod, "tolerations"); len(tolerations) > 0 {
		var kept []any
		for _, t := range tolerations {
			m, ok := t.(map[string]any)
			if !ok {
				continue
			}
			kept = append(kept, pick(m, "key", "operator", "value", "effect"))
		}
		out["tolerations"] = kept
	}
	out["topologySpreadConstraintsPresent"] = len(listAt(pod, "topologySpreadConstraints")) > 0
	out["hasResourceClaims"] = len(listAt(pod, "resourceClaims")) > 0
	return out
}

// projectContainers keeps name, image, command and args. sidecarsOnly keeps only the native
// sidecars (restartPolicy: Always), which is what the agent's initContainers list holds; plain
// run-to-completion init containers are absent by design.
func projectContainers(list []any, sidecarsOnly bool) []any {
	out := []any{}
	for _, c := range list {
		m, ok := c.(map[string]any)
		if !ok {
			continue
		}
		if sidecarsOnly {
			if rp, _ := m["restartPolicy"].(string); rp != "Always" {
				continue
			}
		}
		out = append(out, pick(m, "name", "image", "command", "args"))
	}
	return out
}

// projectVolumes is each volume's name plus one `<sourceKey>: true` per volume source it sets
// (`gitRepo: true`), which is how an in-tree volume plugin is recognised.
func projectVolumes(list []any) []any {
	out := []any{}
	for _, v := range list {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		vm := map[string]any{"name": m["name"], "hostPath": false}
		for k := range m {
			if k != "name" {
				vm[k] = true
			}
		}
		out = append(out, vm)
	}
	return out
}

// ---------- ConfigMap / Secret ----------

var kubeProxyModePattern = regexp.MustCompile(`(?m)^\s*mode:\s*"?([A-Za-z0-9_-]*)"?\s*$`)

// projectConfigMap is key names only. Two curated single-token projections ride on kube-system
// ConfigMaps: the proxy mode of kube-proxy's config, and the Corefile's directive and option
// names for a ConfigMap whose name contains "coredns". The values are never read further.
func projectConfigMap(obj map[string]any, base map[string]any) map[string]any {
	out := map[string]any{}
	data, _ := obj["data"].(map[string]any)
	binary, _ := obj["binaryData"].(map[string]any)
	out["keys"] = toAny(sortedKeys(data, binary))

	meta, _ := obj["metadata"].(map[string]any)
	ns, _ := meta["namespace"].(string)
	name, _ := meta["name"].(string)
	if ns != "kube-system" || data == nil {
		return out
	}
	if strings.HasPrefix(name, "kube-proxy") {
		for _, v := range orderedValues(data) {
			if m := kubeProxyModePattern.FindStringSubmatch(v); m != nil && m[1] != "" {
				out["kubeProxyMode"] = m[1]
				break
			}
		}
	}
	if strings.Contains(name, "coredns") {
		var plugins []string
		seen := map[string]bool{}
		for _, v := range orderedValues(data) {
			for _, p := range corefilePlugins(v) {
				if !seen[p] {
					seen[p] = true
					plugins = append(plugins, p)
				}
			}
		}
		if len(plugins) > 0 {
			out["corednsPlugins"] = toAny(plugins)
			out["corednsPluginOptions"] = corefilePluginOptions(orderedValues(data))
		}
	}
	return out
}

// maxCorefileOptionsPerPlugin bounds the option keys kept per plugin block.
const maxCorefileOptionsPerPlugin = 32

var corefileToken = regexp.MustCompile(`^[A-Za-z0-9_]+$`)

// corefilePluginOptions is the option KEY names inside each server-block plugin's block, keyed
// by the plugin name in lower case. A line at depth 2 belongs to the plugin whose block opened
// at depth 1; its first token is the key (`pods insecure` yields `pods`, `aws_access_key AKIA…`
// yields `aws_access_key`) and the rest of the line, which may be a credential, is never read.
// A plugin without a block contributes an empty list, so the projection resolves on every row.
func corefilePluginOptions(values []string) map[string]any {
	options := map[string]any{}
	order := []string{}
	for _, value := range values {
		depth := 0
		current := ""
		for _, raw := range strings.Split(value, "\n") {
			line := strings.TrimSpace(raw)
			if line != "" && !strings.HasPrefix(line, "#") {
				switch {
				case depth == 1 && !strings.HasPrefix(line, "}"):
					token := strings.TrimSuffix(strings.Fields(line)[0], "{")
					current = ""
					if corefileToken.MatchString(token) && len(order) < maxCorefileTokens {
						current = strings.ToLower(token)
						if _, ok := options[current]; !ok {
							options[current] = []any{}
							order = append(order, current)
						}
					}
				case depth == 2 && current != "" && !strings.HasPrefix(line, "}"):
					key := strings.TrimSuffix(strings.Fields(line)[0], "{")
					keys := options[current].([]any)
					if corefileToken.MatchString(key) && len(keys) < maxCorefileOptionsPerPlugin && !containsAny(keys, key) {
						options[current] = append(keys, key)
					}
				}
			}
			depth += strings.Count(line, "{") - strings.Count(line, "}")
			if depth < 0 {
				depth = 0
			}
		}
	}
	return options
}

// projectSecret is key names and the type. data and stringData never leave here.
func projectSecret(obj map[string]any, base map[string]any) map[string]any {
	data, _ := obj["data"].(map[string]any)
	stringData, _ := obj["stringData"].(map[string]any)
	out := map[string]any{"keys": toAny(sortedKeys(data, stringData))}
	if t, ok := obj["type"].(string); ok {
		out["type"] = t
	}
	return out
}

// ---------- Traefik ----------

// projectMiddleware is the top-level spec key names only: which middleware types the object
// configures, never their configuration (basicAuth users, forwardAuth headers).
func projectMiddleware(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	return map[string]any{"types": toAny(sortedKeys(spec))}
}

// projectIngressRoute keeps entry points, each route's kind, match expression, service and
// middleware REFERENCES, and a presence-only tls flag.
func projectIngressRoute(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{}
	if spec == nil {
		return out
	}
	if eps, ok := spec["entryPoints"].([]any); ok {
		out["entryPoints"] = eps
	}
	routes := []any{}
	for _, r := range listAt(spec, "routes") {
		m, ok := r.(map[string]any)
		if !ok {
			continue
		}
		route := pick(m, "kind", "match")
		if match, ok := route["match"].(string); ok && len(match) > 512 {
			route["match"] = match[:512]
		}
		services := []any{}
		for _, s := range listAt(m, "services") {
			if sm, ok := s.(map[string]any); ok {
				services = append(services, pick(sm, "name", "namespace", "kind", "port"))
			}
		}
		route["services"] = services
		middlewares := []any{}
		for _, s := range listAt(m, "middlewares") {
			if sm, ok := s.(map[string]any); ok {
				middlewares = append(middlewares, pick(sm, "name", "namespace"))
			}
		}
		route["middlewares"] = middlewares
		routes = append(routes, route)
	}
	out["routes"] = routes
	if _, ok := spec["tls"]; ok {
		out["tls"] = true
	}
	return out
}

// ---------- cert-manager ----------

var certManagerIssuerTypes = []string{"acme", "ca", "vault", "venafi", "selfSigned"}

// projectIssuer is which issuer blocks are configured, which ACME solver keys are (plus the
// ingress / gatewayHTTPRoute key under http01), and every serviceAccountRef.name at any depth.
// All three on every row, empty when none. Never a server URL, path, zone or Secret name.
func projectIssuer(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{"types": []any{}, "solverTypes": []any{}, "serviceAccountRefs": []any{}}
	if spec == nil {
		return out
	}
	types := []any{}
	for _, t := range certManagerIssuerTypes {
		if spec[t] != nil {
			types = append(types, t)
		}
	}
	out["types"] = types
	solverTypes := []any{}
	for _, s := range listAt(mapAt(spec, "acme"), "solvers") {
		solver, ok := s.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range sortedKeys(solver) {
			if !containsAny(solverTypes, k) {
				solverTypes = append(solverTypes, k)
			}
			if k == "http01" {
				for _, k2 := range sortedKeys(mapAt(solver, "http01")) {
					if !containsAny(solverTypes, k2) {
						solverTypes = append(solverTypes, k2)
					}
				}
			}
		}
	}
	out["solverTypes"] = solverTypes
	refs := []any{}
	collectServiceAccountRefs(spec, &refs, 0)
	out["serviceAccountRefs"] = refs
	return out
}

func collectServiceAccountRefs(node any, out *[]any, depth int) {
	if depth > 12 {
		return
	}
	switch v := node.(type) {
	case map[string]any:
		if ref, ok := v["serviceAccountRef"].(map[string]any); ok {
			if name, _ := ref["name"].(string); name != "" && !containsAny(*out, name) {
				*out = append(*out, name)
			}
		}
		for _, k := range sortedKeys(v) {
			collectServiceAccountRefs(v[k], out, depth+1)
		}
	case []any:
		for _, e := range v {
			collectServiceAccountRefs(e, out, depth+1)
		}
	}
}

// projectCertificate is the two presence booleans the 1.18 default flips fire on (written on
// every row, since they fire on ABSENCE), the key algorithm and size, and the issuer reference.
func projectCertificate(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{}
	if spec == nil {
		return out
	}
	pk, _ := spec["privateKey"].(map[string]any)
	rotation := pk["rotationPolicy"]
	out["rotationPolicySet"] = rotation != nil
	out["rotationPolicy"] = enumString(rotation)
	out["revisionHistoryLimitSet"] = spec["revisionHistoryLimit"] != nil
	out["privateKeyAlgorithm"] = enumString(pk["algorithm"])
	if size, ok := pk["size"].(float64); ok {
		out["privateKeySize"] = int(size)
	} else if size, ok := pk["size"].(int64); ok {
		out["privateKeySize"] = int(size)
	}
	if ref, ok := spec["issuerRef"].(map[string]any); ok {
		out["issuerRef"] = pick(ref, "group", "kind", "name")
	} else if spec["issuerRef"] == nil {
		out["issuerRef"] = map[string]any{}
	}
	return out
}

// ---------- Argo CD ----------

func projectApplication(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{}
	if spec == nil {
		return out
	}
	if p, ok := spec["project"]; ok && p != nil {
		out["project"] = fmt.Sprint(p)
	}
	var sources []map[string]any
	if single, ok := spec["source"].(map[string]any); ok {
		sources = append(sources, single)
	}
	for _, s := range listAt(spec, "sources") {
		if m, ok := s.(map[string]any); ok {
			sources = append(sources, m)
		}
	}
	helm, helmVersion := false, ""
	for _, src := range sources {
		if h, ok := src["helm"].(map[string]any); ok {
			helm = true
			if helmVersion == "" && h["version"] != nil {
				helmVersion = fmt.Sprint(h["version"])
			}
		}
	}
	out["helm"], out["helmVersion"] = helm, helmVersion
	automated, managedNamespaceMetadata := false, false
	syncOptions := []any{}
	if policy, ok := spec["syncPolicy"].(map[string]any); ok {
		automated = policy["automated"] != nil
		managedNamespaceMetadata = policy["managedNamespaceMetadata"] != nil
		for _, o := range listAt(policy, "syncOptions") {
			if o != nil && len(syncOptions) < 20 {
				syncOptions = append(syncOptions, fmt.Sprint(o))
			}
		}
	}
	out["automated"], out["managedNamespaceMetadata"], out["syncOptions"] = automated, managedNamespaceMetadata, syncOptions
	hydrator, isHydrator := spec["sourceHydrator"].(map[string]any)
	out["sourceHydrator"] = isHydrator
	if isHydrator {
		path := ""
		if ss, ok := hydrator["syncSource"].(map[string]any); ok && ss["path"] != nil {
			path = fmt.Sprint(ss["path"])
		}
		out["hydratorPath"] = path
	}
	return out
}

const clusterVersionLabel = "argocd.argoproj.io/kubernetes-version"

func projectApplicationSet(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{}
	if spec == nil {
		return out
	}
	selectors := []any{}
	collectClusterVersionSelectors(spec["generators"], &selectors, 0)
	out["clusterGeneratorVersionSelectors"] = selectors
	apply, applySet := spec["applyNestedSelectors"].(bool)
	if applySet {
		out["applyNestedSelectors"] = apply
	}
	nested := hasNestedSelectors(spec["generators"], 0)
	out["nestedSelectorsPresent"] = nested
	out["nestedSelectorsUnapplied"] = nested && !(applySet && apply)
	return out
}

func collectClusterVersionSelectors(generators any, out *[]any, depth int) {
	list, ok := generators.([]any)
	if depth > 4 || !ok {
		return
	}
	for _, g := range list {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		if sel := mapAt(gm, "clusters", "selector"); sel != nil {
			if v, ok := mapAt(sel, "matchLabels")[clusterVersionLabel]; ok && v != nil {
				*out = append(*out, fmt.Sprint(v))
			}
			for _, e := range listAt(sel, "matchExpressions") {
				em, ok := e.(map[string]any)
				if !ok || fmt.Sprint(em["key"]) != clusterVersionLabel {
					continue
				}
				for _, v := range listAt(em, "values") {
					if v != nil {
						*out = append(*out, fmt.Sprint(v))
					}
				}
			}
		}
		for _, nest := range []string{"matrix", "merge"} {
			if nm, ok := gm[nest].(map[string]any); ok {
				collectClusterVersionSelectors(nm["generators"], out, depth+1)
			}
		}
	}
}

func hasNestedSelectors(generators any, depth int) bool {
	list, ok := generators.([]any)
	if depth > 4 || !ok {
		return false
	}
	for _, g := range list {
		gm, ok := g.(map[string]any)
		if !ok {
			continue
		}
		if depth > 0 && gm["selector"] != nil {
			return true
		}
		for _, nest := range []string{"matrix", "merge"} {
			if nm, ok := gm[nest].(map[string]any); ok && hasNestedSelectors(nm["generators"], depth+1) {
				return true
			}
		}
	}
	return false
}

func projectAppProject(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{}
	if spec == nil {
		return out
	}
	out["signatureKeys"] = len(listAt(spec, "signatureKeys")) > 0
	out["sourceIntegrity"] = spec["sourceIntegrity"] != nil
	out["destinationServiceAccounts"] = len(listAt(spec, "destinationServiceAccounts")) > 0
	return out
}

// ---------- Karpenter ----------

func projectNodePool(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{}
	if spec == nil {
		return out
	}
	if ref, ok := mapAt(spec, "template", "spec")["nodeClassRef"].(map[string]any); ok {
		out["nodeClassRef"] = pick(ref, "group", "kind", "name")
		out["nodeClassRefComplete"] = refComplete(ref)
	}
	out["disruptionBudgetsPresent"] = len(listAt(mapAt(spec, "disruption"), "budgets")) > 0
	out["templateResourcesPresent"] = len(mapAt(spec, "template", "spec", "resources")) > 0
	return out
}

func projectNodeClaim(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{}
	if ref, ok := spec["nodeClassRef"].(map[string]any); ok {
		out["nodeClassRef"] = pick(ref, "group", "kind", "name")
		out["nodeClassRefComplete"] = refComplete(ref)
	}
	return out
}

func refComplete(ref map[string]any) bool {
	g, _ := ref["group"].(string)
	k, _ := ref["kind"].(string)
	return strings.TrimSpace(g) != "" && strings.TrimSpace(k) != ""
}

func projectEC2NodeClass(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{}
	if spec == nil {
		return out
	}
	out["amiFamily"] = enumString(spec["amiFamily"])
	out["instanceStorePolicy"] = enumString(spec["instanceStorePolicy"])
	out["capacityReservationSelectorTermsPresent"] = len(listAt(spec, "capacityReservationSelectorTerms")) > 0
	return out
}

// ---------- CustomResourceDefinition ----------

// CRDSpec is the projected view of a definition the rules read: its group, kind, plural and
// scope, the versions with their served/storage flags, and the two client-side-apply markers
// the typed collector recorded.
func CRDSpec(crd CRD) map[string]any {
	out := map[string]any{
		"lastAppliedConfigurationPresent": crd.LastAppliedConfigurationPresent,
		"clientSideApplyManager":          crd.ClientSideApplyManager,
	}
	spec := crd.Spec
	if spec == nil {
		return out
	}
	for _, k := range []string{"group", "scope"} {
		if v, ok := spec[k]; ok {
			out[k] = v
		}
	}
	if names := mapAt(spec, "names"); names != nil {
		for _, k := range []string{"kind", "plural"} {
			if v, ok := names[k]; ok {
				out[k] = v
			}
		}
	}
	versions := []any{}
	for _, v := range listAt(spec, "versions") {
		if m, ok := v.(map[string]any); ok {
			versions = append(versions, pick(m, "name", "served", "storage"))
		}
	}
	out["versions"] = versions
	return out
}

// ---------- helpers ----------

func mapAt(m map[string]any, path ...string) map[string]any {
	cur := m
	for _, seg := range path {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func listAt(m map[string]any, key string) []any {
	if m == nil {
		return nil
	}
	list, _ := m[key].([]any)
	return list
}

func pick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok && v != nil {
			out[k] = v
		}
	}
	return out
}

func sortedKeys(maps ...map[string]any) []string {
	out := []string{}
	for _, m := range maps {
		for k := range m {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func orderedValues(m map[string]any) []string {
	var out []string
	for _, k := range sortedKeys(m) {
		if s, ok := m[k].(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func toAny(items []string) []any {
	out := make([]any, 0, len(items))
	for _, s := range items {
		out = append(out, s)
	}
	return out
}

func containsAny(list []any, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

var enumPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)

// enumString is a short identifier-shaped value, or "" when absent or not shaped like one.
func enumString(v any) string {
	if v == nil {
		return ""
	}
	s := fmt.Sprint(v)
	if !enumPattern.MatchString(s) {
		return ""
	}
	return s
}
