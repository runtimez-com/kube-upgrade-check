package inventory

import "strings"

// ---------- Cilium ----------
//
// The Cilium release-note rules read features[]: NAMES of the shapes each rule asks about, one per
// rule's jq verify predicate. This is a port of the hosted agent's CiliumProjection, so the CLI and
// the product decide every Cilium policy rule the same way. Nothing else of the object is kept: no
// FQDN, CIDR, port, L7 rule, header or TLS secret reference.

// projectCiliumPolicy covers CiliumNetworkPolicy and CiliumClusterwideNetworkPolicy.
func projectCiliumPolicy(obj map[string]any, base map[string]any) map[string]any {
	return map[string]any{"projection": 1, "features": toAny(ciliumPolicyFeatures(obj["spec"], obj["specs"]))}
}

func projectCiliumLocalRedirectPolicy(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	f := []string{}
	if skip, _ := spec["skipRedirectFromBackend"].(bool); !skip {
		f = append(f, "redirectsFromBackend")
	}
	if fe := mapAt(spec, "redirectFrontend"); fe != nil && fe["addressMatcher"] != nil {
		f = append(f, "addressMatcher")
	}
	return map[string]any{"projection": 1, "features": toAny(f)}
}

func projectCiliumLBIPPool(obj map[string]any, base map[string]any) map[string]any {
	spec, _ := obj["spec"].(map[string]any)
	f := []string{}
	if spec["allowFirstLastIPs"] == nil {
		f = append(f, "allowFirstLastIPsUnset")
	}
	if spec["cidrs"] != nil {
		f = append(f, "cidrs")
	}
	meta, _ := obj["metadata"].(map[string]any)
	for _, e := range listAt(meta, "managedFields") {
		// the status subresource is the operator's write (1.17 patches pool status with its v2alpha1
		// client), never the user's manifest the 1.19 note is about
		if m, ok := e.(map[string]any); ok && m["apiVersion"] == "cilium.io/v2alpha1" && (m["subresource"] == nil || m["subresource"] == "") {
			f = append(f, "writtenV2alpha1")
			break
		}
	}
	return map[string]any{"projection": 1, "features": toAny(f)}
}

// ciliumPolicyFeatures mirrors CiliumProjection.policyFeatures; each check names the rule predicate
// it ports. "RULES" is [(.spec // empty), (.specs[]?)] | map(((.ingress // []) + (.egress // []) +
// (.ingressDeny // []) + (.egressDeny // []))[]).
func ciliumPolicyFeatures(spec, specs any) []string {
	seen := map[string]bool{}
	var out []string
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			out = append(out, name)
		}
	}
	var blocks []map[string]any
	if s, ok := spec.(map[string]any); ok {
		blocks = append(blocks, s)
	}
	blocks = append(blocks, maps(specs)...)
	// 1.20 empty-policies-rejected: .spec == null and .specs == null
	if spec == nil && specs == nil {
		add("empty")
	}
	// 1.14/1.15 reserved-init: tostring | test("reserved:init"), over the policy body
	for _, b := range blocks {
		if mentions(b, "reserved:init", 0) {
			add("reservedInit")
			break
		}
	}
	// 1.14 deny: any((.ingressDeny // []) + (.egressDeny // []) | length != 0)
	for _, b := range blocks {
		if len(listAt(b, "ingressDeny")) > 0 || len(listAt(b, "egressDeny")) > 0 {
			add("denyRules")
			break
		}
	}
	// 1.14 deny precedence (hint): a deny rule carrying a CIDR
	for _, b := range blocks {
		for _, dir := range []string{"ingressDeny", "egressDeny"} {
			for _, r := range maps(b[dir]) {
				for _, k := range []string{"fromCIDR", "fromCIDRSet", "toCIDR", "toCIDRSet"} {
					if len(listAt(r, k)) > 0 {
						add("denyCidr")
					}
				}
			}
		}
	}
	var rules []map[string]any
	for _, b := range blocks {
		for _, dir := range []string{"ingress", "egress", "ingressDeny", "egressDeny"} {
			rules = append(rules, maps(b[dir])...)
		}
	}
	for _, r := range rules {
		if len(listAt(r, "toFQDNs")) > 0 {
			add("toFQDNs")
		}
		if r["auth"] != nil {
			add("legacyAuth")
		}
		if a := mapAt(r, "authentication"); a != nil && a["mode"] == "required" {
			add("authRequired")
		}
		if len(listAt(r, "fromRequires")) > 0 || len(listAt(r, "toRequires")) > 0 {
			add("requires")
		}
		if fullRangeCIDR(r) {
			add("fullRangeCidr")
		}
		if emptySlice(r) {
			add("emptySlice")
		}
		if cidrGroupRef(r) {
			add("cidrGroupRef")
		}
		if overLimitOrMixedRules(r) {
			add("invalidShape")
		}
		if doubleStarDNS(r) {
			add("dnsDoubleStar")
		}
		for _, p := range maps(r["toPorts"]) {
			if p["terminatingTLS"] != nil {
				add("terminatingTLS")
			}
			if p["terminatingTLS"] != nil || p["originatingTLS"] != nil {
				add("tlsInterception")
			}
			if rl, ok := p["rules"].(map[string]any); ok {
				if rl["kafka"] != nil {
					add("kafka")
				}
				_, kafka := rl["kafka"]
				_, l7 := rl["l7"]
				_, l7proto := rl["l7proto"]
				if kafka || l7 || l7proto {
					add("proxylib")
				}
				if proto, ok := rl["l7proto"].(string); ok && (strings.HasPrefix(proto, "cassandra") || strings.HasPrefix(proto, "memcache")) {
					add("l7CassandraMemcached")
				}
			}
		}
	}
	if out == nil {
		out = []string{}
	}
	return out
}

func maps(v any) []map[string]any {
	var out []map[string]any
	if l, ok := v.([]any); ok {
		for _, e := range l {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
	}
	return out
}

func fullRangeCIDR(r map[string]any) bool {
	var cidrs []any
	cidrs = append(cidrs, listAt(r, "toCIDR")...)
	for _, s := range maps(r["toCIDRSet"]) {
		if s["cidr"] != nil {
			cidrs = append(cidrs, s["cidr"])
		}
	}
	for _, c := range cidrs {
		if c == "0.0.0.0/0" || c == "::/0" {
			return true
		}
	}
	return false
}

func emptySlice(r map[string]any) bool {
	for _, k := range []string{"fromEndpoints", "fromCIDR", "fromCIDRSet", "fromEntities", "toEndpoints", "toCIDR", "toCIDRSet", "toEntities"} {
		if l, ok := r[k].([]any); ok && len(l) == 0 {
			return true
		}
	}
	return false
}

func cidrGroupRef(r map[string]any) bool {
	for _, k := range []string{"fromCIDRSet", "toCIDRSet"} {
		for _, s := range maps(r[k]) {
			if s["cidrGroupRef"] != nil {
				return true
			}
		}
	}
	return false
}

// overLimitOrMixedRules follows the v1.16.0 CRD (pkg/policy/api l4.go, icmp.go): MaxItems=40 per
// PortRule.ports and per ICMPRule.fields; OneOf over http / kafka / dns / l7proto (l7 is not one).
func overLimitOrMixedRules(r map[string]any) bool {
	for _, p := range maps(r["toPorts"]) {
		if len(listAt(p, "ports")) > 40 {
			return true
		}
		if rl, ok := p["rules"].(map[string]any); ok {
			n := 0
			for _, k := range []string{"http", "kafka", "dns", "l7proto"} {
				if rl[k] != nil {
					n++
				}
			}
			if n > 1 {
				return true
			}
		}
	}
	for _, icmp := range maps(r["icmps"]) {
		if len(listAt(icmp, "fields")) > 40 {
			return true
		}
	}
	return false
}

func doubleStarDNS(r map[string]any) bool {
	dns := maps(r["toFQDNs"])
	for _, p := range maps(r["toPorts"]) {
		if rl, ok := p["rules"].(map[string]any); ok {
			dns = append(dns, maps(rl["dns"])...)
		}
	}
	for _, d := range dns {
		if s, ok := d["matchPattern"].(string); ok && strings.HasPrefix(s, "**.") {
			return true
		}
	}
	return false
}

// mentions reports whether any map key or string value under v contains needle; depth-capped
// like the agent's.
func mentions(v any, needle string, depth int) bool {
	if v == nil || depth > 24 {
		return false
	}
	switch t := v.(type) {
	case string:
		return strings.Contains(t, needle)
	case map[string]any:
		for k, e := range t {
			if strings.Contains(k, needle) || mentions(e, needle, depth+1) {
				return true
			}
		}
	case []any:
		for _, e := range t {
			if mentions(e, needle, depth+1) {
				return true
			}
		}
	}
	return false
}
