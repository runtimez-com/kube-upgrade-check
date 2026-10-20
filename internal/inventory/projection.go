package inventory

import (
	"fmt"
	"regexp"
	"sort"
	"strconv"
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

	// Gateway API routes: the spec the rules read is their STATUS parents (Argo CD 3.1 health).
	"HTTPRoute":  projectRouteStatusParents,
	"GRPCRoute":  projectRouteStatusParents,
	"AppProject": projectAppProject,

	"NodePool":     projectNodePool,
	"NodeClaim":    projectNodeClaim,
	"EC2NodeClass": projectEC2NodeClass,

	"DestinationRule": projectDestinationRule,
	"EnvoyFilter":     projectEnvoyFilter,

	"Service": projectService,
	// StorageClass has no spec: provisioner and the binding fields are top-level. Same four keys
	// the agent's ResourceMapper writes (parameters are not collected by either).
	"StorageClass": projectStorageClass,
}

// statusProjectors derive the status a rule reads, for kinds whose raw status is not the shape
// the hosted product's agent ships. raw is the whole status, kept the caller's projected keys.
var statusProjectors = map[string]func(raw map[string]any, kept map[string]any) map[string]any{
	"Application":         projectApplicationStatus,
	"PodDisruptionBudget": projectPDBStatus,
}

// projectStatus is the status recorded for one listed object.
func projectStatus(kind string, raw map[string]any, projection *Projection) map[string]any {
	kept := project(raw, projection)
	if p, ok := statusProjectors[kind]; ok {
		return p(raw, kept)
	}
	return kept
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
	// The agent carries a controller's selector as its matchLabels map, so a rule on `selector`
	// reads `key=value` leaves. The raw {matchLabels: {...}} would only ever yield "matchLabels"
	// and clear the Istio gateway-name rules on every workload.
	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "ReplicaSet":
		if sel, ok := out["selector"].(map[string]any); ok {
			if labels, ok := sel["matchLabels"].(map[string]any); ok {
				out["selector"] = labels
			} else {
				delete(out, "selector")
			}
		}
	}
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
	// The three booleans the hand-authored kubernetes corpus (1.32–1.37) reads, derived the way
	// the agent derives them: matchLabelKeys on any spread constraint (1.34 selector merge),
	// seLinuxOptions on the pod or any container (1.37 SELinuxMount), and env/envFrom that
	// reference a ConfigMap or Secret (1.34 static-pod API references).
	out["hasTopologySpreadMatchLabelKeys"] = anyListItem(listAt(pod, "topologySpreadConstraints"), func(m map[string]any) bool {
		return len(listAt(m, "matchLabelKeys")) > 0
	})
	hasSELinux := mapAt(pod, "securityContext", "seLinuxOptions") != nil
	hasEnvAPIRefs := false
	for _, key := range []string{"containers", "initContainers", "ephemeralContainers"} {
		for _, c := range listAt(pod, key) {
			m, ok := c.(map[string]any)
			if !ok {
				continue
			}
			if mapAt(m, "securityContext", "seLinuxOptions") != nil {
				hasSELinux = true
			}
			if len(listAt(m, "envFrom")) > 0 {
				hasEnvAPIRefs = true
			}
			for _, e := range listAt(m, "env") {
				em, ok := e.(map[string]any)
				if !ok {
					continue
				}
				if mapAt(em, "valueFrom", "configMapKeyRef") != nil || mapAt(em, "valueFrom", "secretKeyRef") != nil {
					hasEnvAPIRefs = true
				}
			}
		}
	}
	out["hasSeLinuxOptions"] = hasSELinux
	out["hasEnvApiRefs"] = hasEnvAPIRefs
	// hostUsers is carried as the pod template sets it (the agent puts the raw Boolean on Pod and
	// on each workload template): the 1.30 rule matches `false`, so a row that never set it must
	// not carry a value that reads as either answer.
	if hu, ok := pod["hostUsers"].(bool); ok {
		out["hostUsers"] = hu
	}
	return out
}

// anyListItem reports whether any map item of the list satisfies pred.
func anyListItem(list []any, pred func(map[string]any) bool) bool {
	for _, item := range list {
		if m, ok := item.(map[string]any); ok && pred(m) {
			return true
		}
	}
	return false
}

// ---------- Service ----------

// projectService keeps the raw keys the rules ask for (type, trafficDistribution, ...) and adds
// hasExternalIPs the way the agent does — the addresses themselves are never carried.
func projectService(obj map[string]any, base map[string]any) map[string]any {
	out := base
	spec, _ := obj["spec"].(map[string]any)
	delete(out, "externalIPs")
	out["hasExternalIPs"] = len(listAt(spec, "externalIPs")) > 0
	return out
}

func projectStorageClass(obj map[string]any, base map[string]any) map[string]any {
	out := base
	for _, k := range []string{"provisioner", "reclaimPolicy", "volumeBindingMode", "allowVolumeExpansion"} {
		if v, ok := obj[k]; ok {
			out[k] = v
		}
	}
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
		c := pick(m, "name", "image", "command", "args", "imagePullPolicy")
		// securityContext is procMount only — the 1.30 hint reads containers[].securityContext.procMount;
		// the rest of the container security context is not something a rule asks for by value.
		if pm, ok := mapAt(m, "securityContext")["procMount"].(string); ok && pm != "" {
			c["securityContext"] = map[string]any{"procMount": pm}
		}
		// env is NAMES only, the way the agent ships it: the Istio flag-removal rules read
		// `containers[].env[].name` on the istiod Deployment. A value is never carried, and a
		// valueFrom entry contributes its name and nothing about what it references.
		if env := envNames(listAt(m, "env")); len(env) > 0 {
			c["env"] = env
		}
		out = append(out, c)
	}
	return out
}

func envNames(list []any) []any {
	out := []any{}
	for _, e := range list {
		m, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name != "" {
			out = append(out, map[string]any{"name": name})
		}
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

// ---------- Istio ----------

// projectDestinationRule mirrors the agent's DestinationRule row: host, and a trafficPolicy that
// is written on EVERY row (present-but-empty reads clean) as the NAMES of its top-level blocks
// (tls, connectionPool, outlierDetection, ...), tls's mode enum and key names, outlierDetection's
// key names, and connectionPool.tcp.connectTimeout. caCertificates (a file path), credentialName
// (a Secret name), sni and subjectAltNames stay on the cluster.
func projectDestinationRule(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	out := map[string]any{}
	if host, ok := spec["host"].(string); ok {
		out["host"] = host
	}
	tp := map[string]any{"keys": toAny(sortedKeys(mapAt(spec, "trafficPolicy")))}
	if tpMap := mapAt(spec, "trafficPolicy"); tpMap != nil {
		if tls := mapAt(tpMap, "tls"); tls != nil {
			t := map[string]any{"keys": toAny(sortedKeys(tls))}
			if mode, ok := tls["mode"].(string); ok {
				t["mode"] = mode
			}
			tp["tls"] = t
		}
		if od := mapAt(tpMap, "outlierDetection"); od != nil {
			tp["outlierDetection"] = map[string]any{"keys": toAny(sortedKeys(od))}
		}
		if ct, ok := mapAt(tpMap, "connectionPool", "tcp")["connectTimeout"]; ok && ct != nil {
			tp["connectionPool"] = map[string]any{"tcp": map[string]any{"connectTimeout": fmt.Sprint(ct)}}
		}
	}
	out["trafficPolicy"] = tp
	return out
}

// projectEnvoyFilter mirrors the agent's EnvoyFilter row: each configPatch as its applyTo and
// operation enums plus the Envoy filter NAMES it matches (filter/subFilter names under match,
// and patch.value.name); the patch value itself — inline Lua, typed configs — never leaves.
// workloadSelectorKeys are the label KEYS the filter selects on.
func projectEnvoyFilter(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	patches := []any{}
	for _, p := range listAt(spec, "configPatches") {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		patch := map[string]any{}
		if applyTo, ok := pm["applyTo"].(string); ok {
			patch["applyTo"] = applyTo
		}
		if op, ok := mapAt(pm, "patch")["operation"].(string); ok {
			patch["operation"] = op
		}
		names := []any{}
		collectEnvoyFilterNames(mapAt(pm, "match"), &names)
		if name, ok := mapAt(pm, "patch", "value")["name"].(string); ok && name != "" {
			names = append(names, name)
		}
		patch["filterNames"] = names
		patches = append(patches, patch)
	}
	return map[string]any{
		"configPatches":        patches,
		"workloadSelectorKeys": toAny(sortedKeys(mapAt(spec, "workloadSelector", "labels"))),
	}
}

// collectEnvoyFilterNames walks an EnvoyFilter match block (listener → filterChain → filter →
// subFilter) and collects every filter.name / subFilter.name, names only.
func collectEnvoyFilterNames(node map[string]any, out *[]any) {
	for _, k := range sortedKeys(node) {
		child, ok := node[k].(map[string]any)
		if !ok {
			continue
		}
		if k == "filter" || k == "subFilter" {
			if name, ok := child["name"].(string); ok && name != "" {
				*out = append(*out, name)
			}
		}
		collectEnvoyFilterNames(child, out)
	}
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
	if labels, _ := meta["labels"].(map[string]any); name == "argocd-cm" && fmt.Sprint(labels["app.kubernetes.io/part-of"]) == "argocd" {
		out["argocdSettings"] = argocdSettings(data)
	}
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

// argocd-cm keys whose DEFAULT the Argo CD 3.0 upgrade note changes.
const (
	argocdTrackingKey  = "application.resourceTrackingMethod"
	argocdInClusterKey = "cluster.inClusterEnabled"
)

var argocdTrackingMethods = map[string]bool{"label": true, "annotation": true, "annotation+label": true}

// argocdSettings is the two argocd-cm settings the 3.0 rules read, each shipped only as one of
// Argo's own tokens (nothing else in argocd-cm is read). resourceTrackingMethod is "" when the
// key is absent and omitted when it is not label / annotation / annotation+label;
// inClusterEnabled is true when absent (Argo's default) and omitted when not a strict boolean,
// so an unreadable value is never "off". Same reading as the agent's ResourceMapper.
func argocdSettings(data map[string]any) map[string]any {
	out := map[string]any{}
	if v, ok := data[argocdTrackingKey]; !ok || v == nil {
		out["resourceTrackingMethod"] = ""
	} else if t := strings.TrimSpace(fmt.Sprint(v)); argocdTrackingMethods[t] {
		out["resourceTrackingMethod"] = t
	}
	if v, ok := data[argocdInClusterKey]; !ok || v == nil {
		out["inClusterEnabled"] = true
	} else if b, err := strconv.ParseBool(strings.TrimSpace(fmt.Sprint(v))); err == nil {
		out["inClusterEnabled"] = b
	}
	return out
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
	// The cluster Argo CD runs in, as Argo names it (3.0: with cluster.inClusterEnabled false these
	// Applications go Unknown). The server URL never leaves here, only this boolean.
	server, name := "", ""
	if dest, ok := spec["destination"].(map[string]any); ok {
		if dest["server"] != nil {
			server = fmt.Sprint(dest["server"])
		}
		if dest["name"] != nil {
			name = fmt.Sprint(dest["name"])
		}
	}
	out["destinationInCluster"] = inClusterServer.MatchString(server) || name == "in-cluster"
	// Any config-management-plugin env entry with an empty value (3.0: plugins now receive empty
	// env vars). A presence bit: env names and values are application content.
	pluginEnvEmpty := false
	for _, src := range sources {
		plugin, _ := src["plugin"].(map[string]any)
		for _, e := range listAt(plugin, "env") {
			if em, ok := e.(map[string]any); ok && (em["value"] == nil || em["value"] == "") {
				pluginEnvEmpty = true
			}
		}
	}
	out["pluginEnvEmpty"] = pluginEnvEmpty
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

// inClusterServer is Argo CD's in-cluster API address, trailing slash tolerated.
var inClusterServer = regexp.MustCompile(`^https://kubernetes\.default\.svc/?$`)

// argocdSourceTypes is Argo CD's ApplicationSourceType enum.
var argocdSourceTypes = map[string]bool{"Helm": true, "Kustomize": true, "Directory": true, "Plugin": true}

// projectApplicationStatus adds sourceTypes: how the repo-server rendered each source
// (status.sourceType, or status.sourceTypes[] for a multi-source app), Argo's enum only,
// [] when the controller set none. Lets a Helm or Kustomize note name an auto-detected chart or
// kustomization that has no helm/kustomize block in its spec.
func projectApplicationStatus(raw map[string]any, kept map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range kept {
		out[k] = v
	}
	types := []string{}
	add := func(v any) {
		if s := fmt.Sprint(v); v != nil && argocdSourceTypes[s] && !containsString(types, s) {
			types = append(types, s)
		}
	}
	add(raw["sourceType"])
	for _, v := range listAt(raw, "sourceTypes") {
		add(v)
	}
	out["sourceTypes"] = toAny(types)
	return out
}

// maxPDBConditions bounds the conditions kept per budget, as the agent does.
const maxPDBConditions = 5

// projectPDBStatus writes conditions as "type:status:reason" strings (reason "" when unset), so a
// rule can test the combination Argo CD's 2.13 PDB health check reads: any False condition whose
// reason is not InsufficientPods is Degraded. [] when there are none. Each part is stripped of
// ":" and capped at 64, so a reason can never forge a different split.
func projectPDBStatus(raw map[string]any, kept map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range kept {
		out[k] = v
	}
	conditions := []string{}
	for _, c := range listAt(raw, "conditions") {
		cm, ok := c.(map[string]any)
		if !ok || cm["type"] == nil {
			continue
		}
		if len(conditions) >= maxPDBConditions {
			break
		}
		conditions = append(conditions, pdbConditionPart(cm["type"])+":"+pdbConditionPart(cm["status"])+":"+pdbConditionPart(cm["reason"]))
	}
	out["conditions"] = toAny(conditions)
	return out
}

func pdbConditionPart(v any) string {
	if v == nil {
		return ""
	}
	s := strings.NewReplacer(":", "", "\r", "", "\n", " ").Replace(fmt.Sprint(v))
	if r := []rune(s); len(r) > 64 {
		s = string(r[:64])
	}
	return s
}

// projectRouteStatusParents is an HTTPRoute's or GRPCRoute's status parents: which controller
// and parent each entry is about, and its Accepted / ResolvedRefs conditions as booleans. An
// Unknown condition is left absent, as Argo CD's health check ignores it.
func projectRouteStatusParents(obj map[string]any, base map[string]any) map[string]any {
	out := map[string]any{}
	for k, v := range base {
		out[k] = v
	}
	parents := []any{}
	status, _ := obj["status"].(map[string]any)
	for i, p := range listAt(status, "parents") {
		if i >= maxRouteParents {
			out["statusParentsTruncated"] = true
			break
		}
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		parent := map[string]any{}
		if pm["controllerName"] != nil {
			parent["controllerName"] = fmt.Sprint(pm["controllerName"])
		}
		if ref, ok := pm["parentRef"].(map[string]any); ok {
			for _, k := range []string{"namespace", "name", "sectionName"} {
				if ref[k] != nil {
					parent[k] = fmt.Sprint(ref[k])
				}
			}
		}
		for _, c := range listAt(pm, "conditions") {
			cm, ok := c.(map[string]any)
			if !ok {
				continue
			}
			st := fmt.Sprint(cm["status"])
			if st != "True" && st != "False" {
				continue
			}
			switch fmt.Sprint(cm["type"]) {
			case "Accepted":
				parent["accepted"] = st == "True"
			case "ResolvedRefs":
				parent["resolvedRefs"] = st == "True"
			}
		}
		parents = append(parents, parent)
	}
	out["statusParents"] = parents
	return out
}

// maxRouteParents bounds the status parents kept per route, as the agent does.
const maxRouteParents = 32

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
	out["nestedSelectorsUnapplied"] = nested && (!applySet || !apply)
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

func containsString(items []string, s string) bool {
	for _, item := range items {
		if item == s {
			return true
		}
	}
	return false
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
