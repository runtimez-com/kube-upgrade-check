package cli

import (
	"errors"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
)

// A typo that parsed as "never fail" would turn a CI gate into a no-op reporting success
// forever, and nobody would notice until the upgrade it was meant to stop.
func TestUnknownFailOnValueIsRejected(t *testing.T) {
	for _, bad := range []string{"hihg", "sev1", "yes", "true", "warning"} {
		if _, err := failOnThreshold(bad); err == nil {
			t.Errorf("--fail-on %q must be rejected, not ignored", bad)
		} else {
			var exit *ExitError
			if !errors.As(err, &exit) || exit.Code != ExitUsage {
				t.Errorf("--fail-on %q should be a usage error, got %v", bad, err)
			}
		}
	}
}

func TestFailOnAcceptsEverySeverityAndEmpty(t *testing.T) {
	for _, good := range []string{"low", "medium", "high", "critical", "HIGH", " high "} {
		if _, err := failOnThreshold(good); err != nil {
			t.Errorf("--fail-on %q should be accepted: %v", good, err)
		}
	}
	// Empty means no gate, which is the default and not an error.
	got, err := failOnThreshold("")
	if err != nil || got != 0 {
		t.Errorf("an empty threshold means no gate, got %d, %v", got, err)
	}
}

func TestGateFiresOnlyAtOrAboveTheThreshold(t *testing.T) {
	high, _ := failOnThreshold("high")
	findings := []catalog.Severity{catalog.SeverityMedium, catalog.SeverityHigh, catalog.SeverityCritical}

	err := gate(high, findings, "findings")
	if err == nil {
		t.Fatal("two findings are at or above high, so the gate must fire")
	}
	var exit *ExitError
	if !errors.As(err, &exit) || exit.Code != ExitPolicy {
		t.Errorf("the gate must exit with the policy code, got %v", err)
	}
	if !contains(err.Error(), "2 findings") {
		t.Errorf("the count must be reported: %v", err)
	}

	crit, _ := failOnThreshold("critical")
	if err := gate(crit, []catalog.Severity{catalog.SeverityHigh}, "findings"); err != nil {
		t.Errorf("a high finding must not trip a critical gate: %v", err)
	}
	if err := gate(0, findings, "findings"); err != nil {
		t.Errorf("no threshold means no gate: %v", err)
	}
}

// An unreadable severity must not be silently counted as harmless, nor crash the gate.
func TestGateIgnoresUnrecognisedSeverities(t *testing.T) {
	high, _ := failOnThreshold("high")
	if err := gate(high, []catalog.Severity{"WEIRD", catalog.SeverityLow}, "findings"); err != nil {
		t.Errorf("nothing here reaches the threshold: %v", err)
	}
}

func TestCodeFor(t *testing.T) {
	if got := codeFor(nil); got != ExitOK {
		t.Errorf("no error means success, got %d", got)
	}
	if got := codeFor(errors.New("plain")); got != ExitFailure {
		t.Errorf("an unclassified error is a failure, got %d", got)
	}
	if got := codeFor(&ExitError{Code: ExitAuth, Err: errors.New("x")}); got != ExitAuth {
		t.Errorf("an explicit code must be honoured, got %d", got)
	}
	if got := codeFor(usageErrorf("bad flag")); got != ExitUsage {
		t.Errorf("a usage error must exit 2, got %d", got)
	}
}

func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
