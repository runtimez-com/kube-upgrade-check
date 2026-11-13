package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

// The Cilium projectors keep only feature NAMES, each the port of one release-note rule's jq
// predicate, and never a value of the policy.
func TestCiliumPolicyProjection_featuresOnly_noValueLeaves(t *testing.T) {
	obj := map[string]any{
		"spec": map[string]any{
			"endpointSelector": map[string]any{"matchLabels": map[string]any{"k8s:app": "payments"}},
			"egress": []any{
				map[string]any{"toFQDNs": []any{map[string]any{"matchName": "vault.internal.example.com"}}},
				map[string]any{"toCIDR": []any{"0.0.0.0/0"}, "toRequires": []any{map[string]any{}},
					"toPorts": []any{map[string]any{
						"ports":          []any{map[string]any{"port": "8443"}},
						"terminatingTLS": map[string]any{"secret": map[string]any{"name": "payments-tls-key"}},
						"rules":          map[string]any{"kafka": []any{map[string]any{"topic": "orders"}}},
					}}},
			},
		},
	}
	out := projectCiliumPolicy(obj, nil)
	got := map[string]bool{}
	for _, f := range out["features"].([]any) {
		got[f.(string)] = true
	}
	for _, want := range []string{"toFQDNs", "fullRangeCidr", "requires", "terminatingTLS", "tlsInterception", "kafka", "proxylib"} {
		if !got[want] {
			t.Errorf("missing feature %s in %v", want, out["features"])
		}
	}
	for _, not := range []string{"denyRules", "empty", "dnsDoubleStar", "l7CassandraMemcached", "reservedInit"} {
		if got[not] {
			t.Errorf("unexpected feature %s", not)
		}
	}
	b, _ := json.Marshal(out)
	for _, secret := range []string{"vault.internal", "8443", "payments-tls-key", "orders", "payments"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("projection leaked %q: %s", secret, b)
		}
	}
}

func TestCiliumPolicyProjection_nearMisses(t *testing.T) {
	feats := func(spec any, specs any) []string { return ciliumPolicyFeatures(spec, specs) }
	if f := feats(nil, nil); len(f) != 1 || f[0] != "empty" {
		t.Errorf("no spec and no specs is empty, got %v", f)
	}
	if f := feats(map[string]any{"egress": []any{map[string]any{"toCIDR": []any{"0.0.0.0/1"}}}}, nil); len(f) != 0 {
		t.Errorf("a narrower range is not full-range: %v", f)
	}
	if f := feats(map[string]any{"egress": []any{map[string]any{"toPorts": []any{map[string]any{"rules": map[string]any{"l7proto": "cassandra\nx"}}}}}}, nil); !contains(f, "l7CassandraMemcached") {
		t.Errorf("jq test(\"^(cassandra|memcache)\") is a prefix match: %v", f)
	}
}

func TestCiliumRedirectAndPoolProjection(t *testing.T) {
	lrp := projectCiliumLocalRedirectPolicy(map[string]any{"spec": map[string]any{
		"redirectFrontend": map[string]any{"addressMatcher": map[string]any{"ip": "169.254.20.10"}}}}, nil)
	if f := lrp["features"].([]any); len(f) != 2 || f[0] != "redirectsFromBackend" || f[1] != "addressMatcher" {
		t.Errorf("lrp features %v", f)
	}
	pool := projectCiliumLBIPPool(map[string]any{
		"metadata": map[string]any{"managedFields": []any{map[string]any{"apiVersion": "cilium.io/v2alpha1"}}},
		"spec":     map[string]any{"cidrs": []any{map[string]any{"cidr": "10.0.0.0/24"}}}}, nil)
	if f := pool["features"].([]any); len(f) != 3 {
		t.Errorf("pool features %v", f)
	}
	b, _ := json.Marshal(pool)
	if strings.Contains(string(b), "10.0.0.0") {
		t.Errorf("pool projection leaked a CIDR: %s", b)
	}
}

func contains(items []string, s string) bool {
	for _, i := range items {
		if i == s {
			return true
		}
	}
	return false
}
