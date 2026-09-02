package cli

import (
	"fmt"
	"strings"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
)

// failOnThreshold turns a --fail-on value into a severity rank.
//
// Rejecting an unknown value matters more here than anywhere else: a typo that parsed as
// "never fail" would turn a CI gate into a no-op that reports success forever, and nobody
// would notice until the upgrade that it was meant to stop.
func failOnThreshold(s string) (int, error) {
	if strings.TrimSpace(s) == "" {
		return 0, nil
	}
	rank := catalog.Severity(strings.ToUpper(strings.TrimSpace(s))).Rank()
	if rank == 0 {
		return 0, usageErrorf("unknown --fail-on severity %q — use low, medium, high or critical", s)
	}
	return rank, nil
}

// gate returns the policy exit error when anything reached the threshold.
func gate(threshold int, severities []catalog.Severity, what string) error {
	if threshold == 0 {
		return nil
	}
	count := 0
	for _, s := range severities {
		if r := s.Rank(); r != 0 && r >= threshold {
			count++
		}
	}
	if count == 0 {
		return nil
	}
	return &ExitError{Code: ExitPolicy, Err: fmt.Errorf(
		"%d %s at or above the --fail-on threshold", count, what)}
}
