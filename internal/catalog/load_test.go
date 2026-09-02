package catalog

import (
	"testing"
	"time"
)

// The counts here are the catalog as it stands. They are asserted as lower bounds where the
// catalog is expected to grow, and exactly where a change would mean something was lost.
func TestLoadEmbedded(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	checks := []struct {
		name string
		got  int
		min  int
	}{
		{"deprecation rules", len(c.DeprecationRules), 97},
		{"detector table", len(c.DetectorTable), 80},
		{"config breakers", len(c.ConfigBreakers), 382},
		{"volume plugins", len(c.VolumePlugins), 17},
		{"node runtime", len(c.NodeRuntime), 8},
		{"advisories", len(c.Advisories), 34},
		{"addons", len(c.Addons), 7},
		{"adoption", len(c.AdoptionRules), 13},
	}
	for _, ch := range checks {
		if ch.got < ch.min {
			t.Errorf("%s: loaded %d, want at least %d", ch.name, ch.got, ch.min)
		}
	}

	// Every rule needs the fields the evaluators read; a silently half-parsed rule is worse
	// than a missing one because it still renders.
	for _, r := range c.DeprecationRules {
		if r.RuleID == "" || r.APIVersion == "" || r.Kind == "" || r.RemovedIn == "" {
			t.Errorf("deprecation rule incomplete: %+v", r)
			break
		}
	}
	for _, r := range c.ConfigBreakers {
		if r.RuleID == "" || r.Source == "" || r.Condition == "" || r.AppliesFromVersion == "" {
			t.Errorf("config breaker incomplete: %+v", r)
			break
		}
	}
}

func TestDeprecationLookup(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := c.DeprecationFor("extensions/v1beta1", "Ingress")
	if !ok {
		t.Fatal("extensions/v1beta1 Ingress not found")
	}
	if r.RemovedIn != "1.22" || r.Replacement != "networking.k8s.io/v1" {
		t.Errorf("got removedIn=%q replacement=%q", r.RemovedIn, r.Replacement)
	}
	if _, ok := c.DeprecationFor("apps/v1", "Deployment"); ok {
		t.Error("apps/v1 Deployment must not match a removal rule")
	}
}

func TestLifecycleWildcardFallback(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	// At least one wildcard row must exist, and it must answer for a kind it never names.
	var wildcardGV string
	for _, l := range c.DetectorTable {
		if l.Kind == "*" {
			wildcardGV = l.APIVersion
			break
		}
	}
	if wildcardGV == "" {
		t.Skip("no wildcard rows in the detector table")
	}
	if _, ok := c.LifecycleFor(wildcardGV, "SomeKindNobodyNamed"); !ok {
		t.Errorf("wildcard row for %s did not answer for an unnamed kind", wildcardGV)
	}
}

func TestVolumePluginBreakInPrefersDisabledByDefault(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, p := range c.VolumePlugins {
		if p.DisabledByDefaultIn == "" {
			continue
		}
		found = true
		if p.BreakIn() != p.DisabledByDefaultIn {
			t.Errorf("%s: BreakIn()=%q, want the disabled-by-default version %q",
				p.VolumeSourceKey, p.BreakIn(), p.DisabledByDefaultIn)
		}
	}
	if !found {
		t.Skip("no plugin currently carries disabledByDefaultIn")
	}
}

func TestStaleAddonsCountsUnknownAgeAsStale(t *testing.T) {
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{"karpenter"}
	// Far future: everything is past any horizon.
	if got := c.StaleAddons(ids, time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC), 180); len(got) != 1 {
		t.Errorf("expected karpenter stale in 2099, got %v", got)
	}
	// A catalog with no lastVerified must report stale, never fresh.
	c2 := &Catalog{Addons: []Addon{{AddonID: "x"}}}
	if got := c2.StaleAddons([]string{"x"}, time.Now(), 180); len(got) != 1 {
		t.Errorf("missing lastVerified must count as stale, got %v", got)
	}
}
