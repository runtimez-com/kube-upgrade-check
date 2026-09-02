package cli

import (
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
)

// The shipped catalog must always pass its own validator, or CI is checking nothing.
func TestShippedCatalogValidates(t *testing.T) {
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	if problems := validate(cat); len(problems) > 0 {
		t.Errorf("the shipped catalog has %d problems:\n  %s",
			len(problems), strings.Join(problems, "\n  "))
	}
}

// The validator is what stops a broken rule shipping as a rule that silently never fires, so it
// has to actually catch each class of breakage.
func TestValidatorCatchesBrokenRules(t *testing.T) {
	cases := []struct {
		name string
		cat  *catalog.Catalog
		want string
	}{
		{
			"a predicate nobody implements",
			&catalog.Catalog{Addons: []catalog.Addon{{
				AddonID: "x", Detect: catalog.AddonDetect{ImageSuffixes: []string{"x/y"}},
				LatestKnownVersion: "1.0",
				Rules: []catalog.AddonRule{{
					RuleID: "r", Kind: "noSuchPredicate", Severity: catalog.SeverityHigh,
					Quote: "q", SourceURL: "https://example.com",
				}},
			}}},
			"nothing implements",
		},
		{
			"a finding with no vendor quote",
			&catalog.Catalog{Addons: []catalog.Addon{{
				AddonID: "x", Detect: catalog.AddonDetect{ImageSuffixes: []string{"x/y"}},
				LatestKnownVersion: "1.0",
				Rules: []catalog.AddonRule{{
					RuleID: "r", Kind: "crdAbsent", Severity: catalog.SeverityHigh,
					SourceURL: "https://example.com",
				}},
			}}},
			"no quote or no sourceUrl",
		},
		{
			"an add-on with no version anchor",
			&catalog.Catalog{Addons: []catalog.Addon{{
				AddonID: "x", Detect: catalog.AddonDetect{ImageSuffixes: []string{"x/y"}},
			}}},
			"no version anchor",
		},
		{
			"an add-on that can never be detected",
			&catalog.Catalog{Addons: []catalog.Addon{{AddonID: "x", LatestKnownVersion: "1.0"}}},
			"never be detected",
		},
		{
			"a config breaker with no selectors",
			&catalog.Catalog{ConfigBreakers: []catalog.ConfigBreakerRule{{
				RuleID: "r", Source: "componentFlag", Condition: "present", AppliesFromVersion: "1.32",
			}}},
			"never match",
		},
		{
			"a config breaker whose version does not parse",
			&catalog.Catalog{ConfigBreakers: []catalog.ConfigBreakerRule{{
				RuleID: "r", Source: "kubeletConfig", Condition: "present",
				Selectors: []string{"x"}, AppliesFromVersion: "soon",
			}}},
			"does not parse",
		},
		{
			"an advisory with nothing the reader can run",
			&catalog.Catalog{Advisories: []catalog.AdvisoryRule{{RuleID: "r", Version: "1.34"}}},
			"nothing to check",
		},
		{
			"two rules sharing an id",
			&catalog.Catalog{Advisories: []catalog.AdvisoryRule{
				{RuleID: "dupe", Version: "1.33", VerifyCommand: "kubectl get x"},
				{RuleID: "dupe", Version: "1.34", VerifyCommand: "kubectl get y"},
			}},
			"duplicate ruleId",
		},
	}

	for _, tc := range cases {
		problems := validate(tc.cat)
		var found bool
		for _, p := range problems {
			if strings.Contains(p, tc.want) {
				found = true
			}
		}
		if !found {
			t.Errorf("%s: expected a problem mentioning %q, got %v", tc.name, tc.want, problems)
		}
	}
}
