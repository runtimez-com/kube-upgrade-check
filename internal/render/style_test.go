package render

import (
	"bytes"
	"strings"
	"testing"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
)

// A pipe receiving escape codes is the most common way a pretty tool becomes an unreadable one.
func TestNoColourWhenTheOutputIsNotATerminal(t *testing.T) {
	st := newStyle(&bytes.Buffer{})
	if st.color {
		t.Error("a buffer is not a terminal and must not be coloured")
	}
	if got := st.red("danger"); got != "danger" {
		t.Errorf("styling must be a no-op without colour, got %q", got)
	}
	if st.width != defaultWidth {
		t.Errorf("a non-terminal should use the default width, got %d", st.width)
	}
}

func TestReportContainsNoEscapeCodesWhenPiped(t *testing.T) {
	out := renderWith(t, FormatTable, sample())
	if strings.Contains(out, "\033[") {
		t.Errorf("piped output must carry no escape codes:\n%q", out)
	}
}

// Severity is spelled out as well as coloured, so the report survives being piped, read aloud,
// or pasted into a ticket.
func TestSeverityIsAlwaysSpelledOut(t *testing.T) {
	st := style{color: true, width: defaultWidth}
	for _, sev := range []catalog.Severity{
		catalog.SeverityCritical, catalog.SeverityHigh, catalog.SeverityMedium,
		catalog.SeverityLow, catalog.SeverityInfo,
	} {
		got := st.severity(sev)
		if !strings.Contains(got, strings.TrimSpace(severityLabel(sev))) {
			t.Errorf("%s: colour must not replace the word, got %q", sev, got)
		}
		if !strings.Contains(got, "\033[") {
			t.Errorf("%s: expected colour when it is on, got %q", sev, got)
		}
	}
}

func TestWrapBreaksAtTheWidthAndIndentsContinuations(t *testing.T) {
	st := style{width: 40}
	got := st.wrap("one two three four five six seven eight nine ten eleven twelve", 4)
	lines := strings.Split(got, "\n")
	if len(lines) < 2 {
		t.Fatalf("expected the text to wrap, got %q", got)
	}
	for i, line := range lines {
		if i > 0 && !strings.HasPrefix(line, "    ") {
			t.Errorf("continuation %d must be indented: %q", i, line)
		}
		if len(line) > 40 {
			t.Errorf("line %d exceeds the width: %q", i, line)
		}
	}
	// Wrapping must never lose or reorder words.
	if strings.Join(strings.Fields(got), " ") !=
		"one two three four five six seven eight nine ten eleven twelve" {
		t.Errorf("wrapping changed the text: %q", got)
	}
}

func TestWrapHandlesEmptyAndShortInput(t *testing.T) {
	st := style{width: defaultWidth}
	if got := st.wrap("", 2); got != "" {
		t.Errorf("empty in, empty out, got %q", got)
	}
	if got := st.wrap("short", 2); got != "short" {
		t.Errorf("text under the width should be untouched, got %q", got)
	}
}

// Padding is computed on visible characters, or colour silently misaligns every column.
func TestVisibleLenIgnoresEscapeCodes(t *testing.T) {
	if got := visibleLen("\033[31mHIGH\033[0m"); got != 4 {
		t.Errorf("visibleLen = %d, want 4", got)
	}
	padded := padVisible("\033[31mHIGH\033[0m", 8)
	if visibleLen(padded) != 8 {
		t.Errorf("padVisible produced %d visible characters, want 8", visibleLen(padded))
	}
}

// A wrapped shell command cannot be copied safely, so long ones are cut instead.
func TestCommandsAreTruncatedNotWrapped(t *testing.T) {
	long := "kubectl get pods -A -o json | jq -r '.items[] | select(.spec.containers[].image | test(\"x\"))'"
	got := truncateCommand(long, 50)
	if strings.Contains(got, "\n") {
		t.Errorf("a command must stay on one line: %q", got)
	}
	if len([]rune(got)) > 50 {
		t.Errorf("truncation did not respect the limit: %q", got)
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("a cut command should say it was cut: %q", got)
	}
	if got := truncateCommand("kubectl get nodes", 50); got != "kubectl get nodes" {
		t.Errorf("a short command must be untouched, got %q", got)
	}
}

func TestScoreColourFollowsTheBand(t *testing.T) {
	st := style{color: true, width: defaultWidth}
	for _, tc := range []struct{ level, code string }{
		{"CRITICAL", ansiRed}, {"HIGH", ansiRed}, {"MEDIUM", ansiYellow}, {"LOW", ansiGreen},
	} {
		got := st.score(61, tc.level)
		if !strings.Contains(got, tc.code) {
			t.Errorf("%s should use its band colour, got %q", tc.level, got)
		}
		if !strings.Contains(got, "61/100") {
			t.Errorf("%s: the number must be present, got %q", tc.level, got)
		}
	}
}

func TestItoa(t *testing.T) {
	for n, want := range map[int]string{0: "0", 7: "7", 61: "61", 100: "100", -3: "-3"} {
		if got := itoa(n); got != want {
			t.Errorf("itoa(%d) = %q, want %q", n, got, want)
		}
	}
}
