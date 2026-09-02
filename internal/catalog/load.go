package catalog

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	root "github.com/runtimez-com/kube-upgrade-check"
)

// Catalog is every loaded rule family. Load it once and pass it down; nothing here mutates
// after loading.
type Catalog struct {
	DeprecationRules []DeprecationRule
	DetectorTable    []Lifecycle
	ConfigBreakers   []ConfigBreakerRule
	VolumePlugins    []VolumePluginRule
	NodeRuntime      []NodeRuntimeRule
	Advisories       []AdvisoryRule
	Addons           []Addon
	AdoptionRules    []AdoptionRule

	// deprecationByKey and lifecycleByKey are the lookup indexes built at load time.
	deprecationByKey map[string]DeprecationRule
	lifecycleByKey   map[string]Lifecycle
}

// Load reads the catalogs embedded in the binary.
func Load() (*Catalog, error) { return loadFS(root.CatalogFS, "catalog") }

// LoadDir reads catalogs from a directory instead of the embedded copy, so a contributor can
// test a new add-on JSON without rebuilding.
func LoadDir(dir string) (*Catalog, error) { return loadFS(os.DirFS(dir), ".") }

func loadFS(fsys fs.FS, root string) (*Catalog, error) {
	c := &Catalog{}

	var apis removedAPIsFile
	if err := readJSON(fsys, path(root, "k8s-deprecations/removed-apis.json"), &apis); err != nil {
		return nil, err
	}
	c.DeprecationRules, c.DetectorTable = apis.CatalogRules, apis.DetectorTable

	var breakers configBreakersFile
	if err := readJSON(fsys, path(root, "k8s-config-breakers/config-breakers.json"), &breakers); err != nil {
		return nil, err
	}
	c.ConfigBreakers = breakers.Rules

	var plugins volumePluginsFile
	if err := readJSON(fsys, path(root, "k8s-plugins/removed-volume-plugins.json"), &plugins); err != nil {
		return nil, err
	}
	c.VolumePlugins = plugins.Plugins

	var nodes nodeRuntimeFile
	if err := readJSON(fsys, path(root, "k8s-node-runtime/node-runtime-rules.json"), &nodes); err != nil {
		return nil, err
	}
	c.NodeRuntime = nodes.Rules

	var adv advisoryFile
	if err := readJSON(fsys, path(root, "k8s-advisory/advisory-breakers.json"), &adv); err != nil {
		return nil, err
	}
	c.Advisories = adv.Rules

	var adopt adoptionFile
	if err := readJSON(fsys, path(root, "k8s-adoption/adoption-suggestions.json"), &adopt); err != nil {
		return nil, err
	}
	c.AdoptionRules = adopt.Rules

	// Add-ons are directory-scanned so that adding one is a file, not a code change.
	entries, err := fs.ReadDir(fsys, path(root, "k8s-addons"))
	if err != nil {
		return nil, fmt.Errorf("read k8s-addons: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		var a Addon
		if err := readJSON(fsys, path(root, "k8s-addons/"+e.Name()), &a); err != nil {
			return nil, err
		}
		if a.AddonID == "" {
			return nil, fmt.Errorf("k8s-addons/%s: missing addonId", e.Name())
		}
		c.Addons = append(c.Addons, a)
	}
	sort.Slice(c.Addons, func(i, j int) bool { return c.Addons[i].AddonID < c.Addons[j].AddonID })

	c.index()
	return c, nil
}

func (c *Catalog) index() {
	c.deprecationByKey = make(map[string]DeprecationRule, len(c.DeprecationRules))
	for _, r := range c.DeprecationRules {
		if r.APIVersion == "" || r.Kind == "" {
			continue
		}
		c.deprecationByKey[r.APIVersion+"|"+r.Kind] = r
	}
	c.lifecycleByKey = make(map[string]Lifecycle, len(c.DetectorTable))
	for _, l := range c.DetectorTable {
		if l.APIVersion == "" || l.Kind == "" {
			continue
		}
		c.lifecycleByKey[l.APIVersion+"/"+l.Kind] = l
	}
}

// DeprecationFor looks up a rule by exact apiVersion and kind. No wildcards: a rule carries
// prose naming a specific kind, and applying it to a whole group would put the wrong kind in
// the report.
func (c *Catalog) DeprecationFor(apiVersion, kind string) (DeprecationRule, bool) {
	r, ok := c.deprecationByKey[apiVersion+"|"+kind]
	return r, ok
}

// LifecycleFor looks up version facts for an apiVersion and kind, falling back to the
// group's wildcard row.
//
// The wildcard exists because some group versions were removed wholesale; the fallback is
// what lets one row cover every kind in them.
func (c *Catalog) LifecycleFor(apiVersion, kind string) (Lifecycle, bool) {
	if l, ok := c.lifecycleByKey[apiVersion+"/"+kind]; ok {
		return l, true
	}
	l, ok := c.lifecycleByKey[apiVersion+"/*"]
	return l, ok
}

// AddonByID finds a loaded add-on.
func (c *Catalog) AddonByID(id string) (Addon, bool) {
	for _, a := range c.Addons {
		if a.AddonID == id {
			return a, true
		}
	}
	return Addon{}, false
}

// StaleAddons names add-ons whose source was last verified longer ago than the horizon, or
// never.
//
// Unknown age counts as stale — a missing date is not evidence of freshness. Findings are
// never suppressed for staleness; a possibly-outdated ceiling still beats no signal at all.
func (c *Catalog) StaleAddons(ids []string, now time.Time, staleAfterDays int) []string {
	want := make(map[string]bool, len(ids))
	for _, id := range ids {
		want[id] = true
	}
	var stale []string
	for _, a := range c.Addons {
		if !want[a.AddonID] {
			continue
		}
		verified, err := time.Parse("2006-01-02", strings.TrimSpace(a.Source.LastVerified))
		if err != nil || now.Sub(verified) > time.Duration(staleAfterDays)*24*time.Hour {
			stale = append(stale, a.AddonID)
		}
	}
	sort.Strings(stale)
	return stale
}

func readJSON(fsys fs.FS, name string, out any) error {
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return fmt.Errorf("read %s: %w", name, err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		return fmt.Errorf("parse %s: %w", name, err)
	}
	return nil
}

func path(root, rel string) string {
	if root == "." || root == "" {
		return rel
	}
	return filepath.ToSlash(filepath.Join(root, rel))
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
