package inventory

import (
	"encoding/json"
	"strings"
	"testing"
)

func obj(kind, ns, name string, body map[string]any) map[string]any {
	out := map[string]any{"kind": kind, "metadata": map[string]any{"namespace": ns, "name": name}}
	for k, v := range body {
		out[k] = v
	}
	return out
}

func leaves(t *testing.T, spec map[string]any, key string) []any {
	t.Helper()
	list, ok := spec[key].([]any)
	if !ok {
		t.Fatalf("%s is not a list: %+v", key, spec[key])
	}
	return list
}

// The Corefile projection is what the CoreDNS rules read: directive names at server-block
// level, and option KEY names per plugin, never the option values (an upstream, a credential).
func TestConfigMapProjectsCorefileNamesNeverValues(t *testing.T) {
	corefile := `.:53 {
    errors
    kubernetes cluster.local in-addr.arpa {
        pods insecure
        resyncperiod 30s
        upstream 8.8.8.8
    }
    route53 example.org.:Z1 {
        aws_access_key AKIAFAKEKEY SECRET
    }
    forward . 1.1.1.1
}
`
	spec := projectSpec("ConfigMap", obj("ConfigMap", "kube-system", "coredns", map[string]any{
		"data": map[string]any{"Corefile": corefile, "extra": "x"},
	}), nil)
	if got := spec["keys"]; len(got.([]any)) != 2 {
		t.Errorf("keys = %v", got)
	}
	plugins := leaves(t, spec, "corednsPlugins")
	if len(plugins) != 4 || plugins[1] != "kubernetes" || plugins[2] != "route53" {
		t.Errorf("plugins = %v", plugins)
	}
	options := spec["corednsPluginOptions"].(map[string]any)
	if k := options["kubernetes"].([]any); len(k) != 3 || k[1] != "resyncperiod" || k[2] != "upstream" {
		t.Errorf("kubernetes options = %v", k)
	}
	if r := options["route53"].([]any); len(r) != 1 || r[0] != "aws_access_key" {
		t.Errorf("route53 options = %v", r)
	}
	if f := options["forward"].([]any); len(f) != 0 {
		t.Errorf("a plugin without a block has an empty entry, got %v", f)
	}
	b, _ := json.Marshal(spec)
	for _, secret := range []string{"AKIAFAKEKEY", "SECRET", "8.8.8.8", "1.1.1.1", "30s"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("a Corefile value leaked into the projection: %s in %s", secret, b)
		}
	}
	// A user ConfigMap that merely mentions coredns, outside kube-system, gets keys only.
	other := projectSpec("ConfigMap", obj("ConfigMap", "apps", "my-coredns", map[string]any{
		"data": map[string]any{"Corefile": corefile}}), nil)
	if _, ok := other["corednsPlugins"]; ok {
		t.Error("the Corefile projection is pinned to kube-system")
	}
}

func TestKubeProxyModeAndSecretKeysOnly(t *testing.T) {
	spec := projectSpec("ConfigMap", obj("ConfigMap", "kube-system", "kube-proxy", map[string]any{
		"data": map[string]any{"config.conf": "apiVersion: kubeproxy.config.k8s.io/v1alpha1\nmode: \"ipvs\"\nipvs:\n  scheduler: rr\n"},
	}), nil)
	if spec["kubeProxyMode"] != "ipvs" {
		t.Errorf("kubeProxyMode = %v", spec["kubeProxyMode"])
	}
	secret := projectSpec("Secret", obj("Secret", "argocd", "cluster-prod", map[string]any{
		"type": "Opaque",
		"data": map[string]any{"config": "eyJ0bHMiOnRydWV9", "server": "aHR0cHM6Ly9r"},
	}), nil)
	b, _ := json.Marshal(secret)
	if strings.Contains(string(b), "eyJ0") || strings.Contains(string(b), "aHR0") {
		t.Fatalf("Secret data leaked: %s", b)
	}
	if keys := secret["keys"].([]any); len(keys) != 2 || keys[0] != "config" || secret["type"] != "Opaque" {
		t.Errorf("secret projection = %s", b)
	}
}

// A workload's pod template is flattened to the agent's shape, on every workload kind.
func TestWorkloadProjectsThePodTemplate(t *testing.T) {
	template := map[string]any{"spec": map[string]any{
		"containers": []any{map[string]any{"name": "coredns", "image": "coredns/coredns:1.4.0",
			"args": []any{"-conf", "/etc/coredns/Corefile", "-cpu", "2"}, "env": []any{map[string]any{"name": "SECRET", "value": "x"}}}},
		"initContainers": []any{
			map[string]any{"name": "init", "image": "busybox"},
			map[string]any{"name": "sidecar", "image": "proxy:1", "restartPolicy": "Always"},
		},
		"volumes":            []any{map[string]any{"name": "cfg", "configMap": map[string]any{"name": "coredns"}}},
		"nodeSelector":       map[string]any{"karpenter.sh/capacity-type": "on-demand"},
		"tolerations":        []any{map[string]any{"key": "node.kubernetes.io/unschedulable", "operator": "Exists", "tolerationSeconds": 30}},
		"resourceClaims":     []any{map[string]any{"name": "gpu"}},
		"serviceAccountName": "coredns",
	}}
	for _, tc := range []struct {
		kind string
		spec map[string]any
	}{
		{"Deployment", map[string]any{"replicas": 2, "template": template}},
		{"DaemonSet", map[string]any{"template": template}},
		{"CronJob", map[string]any{"schedule": "* * * * *", "jobTemplate": map[string]any{"spec": map[string]any{"template": template}}}},
		{"Pod", template["spec"].(map[string]any)},
	} {
		spec := projectSpec(tc.kind, obj(tc.kind, "kube-system", "coredns", map[string]any{"spec": tc.spec}), &Projection{Keep: []string{"containers", "replicas"}})
		containers := leaves(t, spec, "containers")
		c := containers[0].(map[string]any)
		if len(containers) != 1 || c["image"] != "coredns/coredns:1.4.0" || len(c["args"].([]any)) != 4 {
			t.Errorf("%s containers = %v", tc.kind, containers)
		}
		if _, leaked := c["env"]; leaked {
			t.Errorf("%s: env is not projected", tc.kind)
		}
		if side := leaves(t, spec, "initContainers"); len(side) != 1 || side[0].(map[string]any)["name"] != "sidecar" {
			t.Errorf("%s: only native sidecars are kept, got %v", tc.kind, side)
		}
		if v := leaves(t, spec, "volumes")[0].(map[string]any); v["name"] != "cfg" || v["configMap"] != true {
			t.Errorf("%s volumes = %v", tc.kind, v)
		}
		if spec["nodeSelector"].(map[string]any)["karpenter.sh/capacity-type"] != "on-demand" {
			t.Errorf("%s nodeSelector = %v", tc.kind, spec["nodeSelector"])
		}
		if tol := leaves(t, spec, "tolerations")[0].(map[string]any); tol["key"] != "node.kubernetes.io/unschedulable" || tol["tolerationSeconds"] != nil {
			t.Errorf("%s tolerations = %v", tc.kind, tol)
		}
		if spec["hasResourceClaims"] != true || spec["topologySpreadConstraintsPresent"] != false {
			t.Errorf("%s booleans = %v / %v", tc.kind, spec["hasResourceClaims"], spec["topologySpreadConstraintsPresent"])
		}
		if _, raw := spec["template"]; raw {
			t.Errorf("%s: the raw template must not be carried", tc.kind)
		}
		if tc.kind == "Deployment" && spec["replicas"] != 2 {
			t.Errorf("a kept raw key survives: %v", spec["replicas"])
		}
	}
}

func TestIssuerAndCertificateProjection(t *testing.T) {
	issuer := projectSpec("ClusterIssuer", obj("ClusterIssuer", "", "letsencrypt", map[string]any{"spec": map[string]any{
		"acme": map[string]any{"server": "https://acme.example/directory", "email": "ops@example.com",
			"solvers": []any{
				map[string]any{"http01": map[string]any{"gatewayHTTPRoute": map[string]any{"parentRefs": []any{}}}},
				map[string]any{"dns01": map[string]any{"route53": map[string]any{"auth": map[string]any{"kubernetes": map[string]any{
					"serviceAccountRef": map[string]any{"name": "cert-manager"}}}}}},
			}},
	}}), nil)
	if types := issuer["types"].([]any); len(types) != 1 || types[0] != "acme" {
		t.Errorf("types = %v", types)
	}
	solvers := issuer["solverTypes"].([]any)
	joined := strings.Join(toStrings(solvers), ",")
	if joined != "http01,gatewayHTTPRoute,dns01" {
		t.Errorf("solverTypes = %v", solvers)
	}
	if refs := issuer["serviceAccountRefs"].([]any); len(refs) != 1 || refs[0] != "cert-manager" {
		t.Errorf("serviceAccountRefs = %v", refs)
	}
	b, _ := json.Marshal(issuer)
	if strings.Contains(string(b), "example") {
		t.Errorf("issuer identity leaked: %s", b)
	}

	cert := projectSpec("Certificate", obj("Certificate", "web", "tls", map[string]any{"spec": map[string]any{
		"dnsNames": []any{"www.example.com"}, "secretName": "tls-secret", "issuerRef": map[string]any{"kind": "ClusterIssuer", "name": "letsencrypt"},
		"privateKey": map[string]any{"algorithm": "RSA", "size": float64(3072)},
	}}), nil)
	if cert["rotationPolicySet"] != false || cert["revisionHistoryLimitSet"] != false || cert["privateKeySize"] != 3072 || cert["privateKeyAlgorithm"] != "RSA" {
		t.Errorf("certificate = %+v", cert)
	}
	b, _ = json.Marshal(cert)
	if strings.Contains(string(b), "example.com") || strings.Contains(string(b), "tls-secret") {
		t.Errorf("certificate identity leaked: %s", b)
	}
	bare := projectSpec("Certificate", obj("Certificate", "web", "bare", map[string]any{"spec": map[string]any{
		"privateKey": map[string]any{"rotationPolicy": "Always"}, "revisionHistoryLimit": 2}}), nil)
	if bare["rotationPolicySet"] != true || bare["revisionHistoryLimitSet"] != true || bare["rotationPolicy"] != "Always" {
		t.Errorf("set flags = %+v", bare)
	}
	if _, ok := bare["privateKeySize"]; ok {
		t.Error("an absent size is omitted, since 0 is a key length")
	}
}

func TestArgoCDProjection(t *testing.T) {
	app := projectSpec("Application", obj("Application", "argocd", "shop", map[string]any{"spec": map[string]any{
		"project": "default",
		"source":  map[string]any{"repoURL": "git@github.com:acme/shop.git", "helm": map[string]any{"version": "v3", "values": "secret: x"}},
		"syncPolicy": map[string]any{"automated": map[string]any{}, "syncOptions": []any{"ApplyOutOfSyncOnly=true", "CreateNamespace=true"},
			"managedNamespaceMetadata": map[string]any{"labels": map[string]any{"a": "b"}}},
		"sourceHydrator": map[string]any{"syncSource": map[string]any{"path": "./"}},
	}}), nil)
	if app["helm"] != true || app["helmVersion"] != "v3" || app["automated"] != true || app["managedNamespaceMetadata"] != true ||
		app["sourceHydrator"] != true || app["hydratorPath"] != "./" || len(app["syncOptions"].([]any)) != 2 {
		t.Errorf("application = %+v", app)
	}
	b, _ := json.Marshal(app)
	if strings.Contains(string(b), "github") || strings.Contains(string(b), "secret") {
		t.Errorf("application source leaked: %s", b)
	}
	plain := projectSpec("Application", obj("Application", "argocd", "plain", map[string]any{"spec": map[string]any{
		"source": map[string]any{"repoURL": "x", "path": "."}}}), nil)
	if plain["helm"] != false || plain["helmVersion"] != "" || plain["sourceHydrator"] != false || len(plain["syncOptions"].([]any)) != 0 {
		t.Errorf("the booleans and helmVersion are written on every Application: %+v", plain)
	}
	if _, ok := plain["hydratorPath"]; ok {
		t.Error("hydratorPath is written with the hydrator only")
	}

	set := projectSpec("ApplicationSet", obj("ApplicationSet", "argocd", "fleet", map[string]any{"spec": map[string]any{
		"generators": []any{map[string]any{"matrix": map[string]any{"generators": []any{
			map[string]any{"clusters": map[string]any{"selector": map[string]any{"matchLabels": map[string]any{"argocd.argoproj.io/kubernetes-version": "1.32"}}}},
			map[string]any{"list": map[string]any{}, "selector": map[string]any{"matchLabels": map[string]any{"env": "prod"}}},
		}}}},
	}}), nil)
	if sel := set["clusterGeneratorVersionSelectors"].([]any); len(sel) != 1 || sel[0] != "1.32" {
		t.Errorf("selectors = %v", sel)
	}
	if set["nestedSelectorsPresent"] != true || set["nestedSelectorsUnapplied"] != true {
		t.Errorf("nested selectors = %+v", set)
	}
	project := projectSpec("AppProject", obj("AppProject", "argocd", "default", map[string]any{"spec": map[string]any{
		"signatureKeys": []any{map[string]any{"keyID": "ABCDEF"}}}}), nil)
	if project["signatureKeys"] != true || project["destinationServiceAccounts"] != false || project["sourceIntegrity"] != false {
		t.Errorf("project = %+v", project)
	}
}

func TestTraefikAndKarpenterProjection(t *testing.T) {
	mw := projectSpec("Middleware", obj("Middleware", "web", "auth", map[string]any{"spec": map[string]any{
		"basicAuth": map[string]any{"secret": "users"}, "stripPrefix": map[string]any{"prefixes": []any{"/x"}}}}), nil)
	if types := mw["types"].([]any); len(types) != 2 || types[0] != "basicAuth" || len(mw) != 1 {
		t.Errorf("middleware = %+v", mw)
	}
	route := projectSpec("IngressRoute", obj("IngressRoute", "web", "shop", map[string]any{"spec": map[string]any{
		"entryPoints": []any{"websecure"}, "tls": map[string]any{"secretName": "tls"},
		"routes": []any{map[string]any{"kind": "Rule", "match": "PathPrefix(`/shop`)", "priority": 5,
			"services": []any{map[string]any{"name": "shop", "port": 80}}, "middlewares": []any{map[string]any{"name": "auth"}}}},
	}}), nil)
	r := route["routes"].([]any)[0].(map[string]any)
	if route["tls"] != true || r["match"] != "PathPrefix(`/shop`)" || r["priority"] != nil || len(r["services"].([]any)) != 1 {
		t.Errorf("ingressroute = %+v", route)
	}
	pool := projectSpec("NodePool", obj("NodePool", "", "default", map[string]any{"spec": map[string]any{
		"template": map[string]any{"spec": map[string]any{"nodeClassRef": map[string]any{"name": "default"},
			"resources": map[string]any{"requests": map[string]any{"cpu": "1"}}}}}}), nil)
	if pool["nodeClassRefComplete"] != false || pool["templateResourcesPresent"] != true {
		t.Errorf("nodepool = %+v", pool)
	}
	class := projectSpec("EC2NodeClass", obj("EC2NodeClass", "", "br", map[string]any{"spec": map[string]any{
		"amiFamily": "Bottlerocket", "role": "KarpenterNodeRole", "userData": "#!/bin/bash secret"}}), nil)
	if class["amiFamily"] != "Bottlerocket" || class["instanceStorePolicy"] != "" || class["capacityReservationSelectorTermsPresent"] != false {
		t.Errorf("nodeclass = %+v", class)
	}
	b, _ := json.Marshal(class)
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "Role") {
		t.Errorf("nodeclass leaked: %s", b)
	}
}

func TestCRDSpecCarriesGroupVersionsAndApplyMarkers(t *testing.T) {
	spec := CRDSpec(CRD{Name: "middlewares.traefik.io", LastAppliedConfigurationPresent: true, Spec: map[string]any{
		"group": "traefik.io", "scope": "Namespaced", "names": map[string]any{"kind": "Middleware", "plural": "middlewares"},
		"versions": []any{map[string]any{"name": "v1alpha1", "served": true, "storage": true, "schema": map[string]any{"big": true}}},
	}})
	if spec["group"] != "traefik.io" || spec["kind"] != "Middleware" || spec["lastAppliedConfigurationPresent"] != true || spec["clientSideApplyManager"] != false {
		t.Errorf("crd = %+v", spec)
	}
	v := spec["versions"].([]any)[0].(map[string]any)
	if v["name"] != "v1alpha1" || v["schema"] != nil {
		t.Errorf("versions = %+v", v)
	}
}

func toStrings(list []any) []string {
	out := make([]string, 0, len(list))
	for _, x := range list {
		out = append(out, x.(string))
	}
	return out
}

// keys[] is walked by the evaluator as a JSON array; a Go []string would never resolve.
func TestProjectedListsAreJSONArrays(t *testing.T) {
	cm := projectSpec("ConfigMap", obj("ConfigMap", "argocd", "argocd-cm", map[string]any{"data": map[string]any{"repositories": "x"}}), nil)
	if _, ok := cm["keys"].([]any); !ok {
		t.Errorf("ConfigMap keys must be []any, got %T", cm["keys"])
	}
	sec := projectSpec("Secret", obj("Secret", "argocd", "s", map[string]any{"data": map[string]any{"project": "x"}}), nil)
	if _, ok := sec["keys"].([]any); !ok {
		t.Errorf("Secret keys must be []any, got %T", sec["keys"])
	}
}
