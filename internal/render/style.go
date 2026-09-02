package render

import (
	"os"
	"strings"

	"golang.org/x/term"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
)

// style decides how the report is decorated.
//
// Colour is a convenience for someone reading a terminal, never a carrier of meaning: every
// severity is spelled out in words as well, so the report survives being piped to a file, read
// by a screen reader, or pasted into a ticket.
type style struct {
	color bool
	width int
}

// ANSI codes, applied only when colour is on.
const (
	ansiReset  = "\033[0m"
	ansiBold   = "\033[1m"
	ansiDim    = "\033[2m"
	ansiRed    = "\033[31m"
	ansiYellow = "\033[33m"
	ansiBlue   = "\033[34m"
	ansiCyan   = "\033[36m"
	ansiGreen  = "\033[32m"
)

// defaultWidth is used when the terminal will not say how wide it is, as in a pipe or a CI log.
const defaultWidth = 100

// minWidth stops a very narrow terminal from wrapping prose into a column of single words.
const minWidth = 60

// newStyle inspects the environment once.
//
// Three ways to end up without colour, all of them deliberate: the output is not a terminal,
// NO_COLOR is set, or TERM says the terminal cannot do it. A pipe getting escape codes is the
// most common way a pretty tool becomes an unreadable one.
func newStyle(out any) style {
	s := style{width: defaultWidth}

	file, isFile := out.(*os.File)
	if !isFile {
		return s
	}
	fd := int(file.Fd())
	if !term.IsTerminal(fd) {
		return s
	}
	if _, noColor := os.LookupEnv("NO_COLOR"); !noColor && os.Getenv("TERM") != "dumb" {
		s.color = true
	}
	if w, _, err := term.GetSize(fd); err == nil && w > minWidth {
		s.width = w
	}
	return s
}

func (s style) paint(code, text string) string {
	if !s.color || text == "" {
		return text
	}
	return code + text + ansiReset
}

func (s style) bold(text string) string  { return s.paint(ansiBold, text) }
func (s style) dim(text string) string   { return s.paint(ansiDim, text) }
func (s style) red(text string) string   { return s.paint(ansiRed, text) }
func (s style) green(text string) string { return s.paint(ansiGreen, text) }
func (s style) cyan(text string) string  { return s.paint(ansiCyan, text) }

// heading is a section title: bold, and spelled out rather than drawn, so it survives a paste.
func (s style) heading(text string) string { return s.bold(text) }

// severity colours the badge by how much attention the row deserves.
func (s style) severity(sev catalog.Severity) string {
	label := severityLabel(sev)
	switch sev {
	case catalog.SeverityCritical, catalog.SeverityHigh:
		return s.paint(ansiRed, label)
	case catalog.SeverityMedium:
		return s.paint(ansiYellow, label)
	case catalog.SeverityLow:
		return s.paint(ansiBlue, label)
	default:
		return s.dim(label)
	}
}

// score colours the headline number by band.
func (s style) score(value int, level string) string {
	text := itoa(value) + "/100 " + level
	switch level {
	case "CRITICAL", "HIGH":
		return s.paint(ansiBold+ansiRed, text)
	case "MEDIUM":
		return s.paint(ansiBold+ansiYellow, text)
	default:
		return s.paint(ansiBold+ansiGreen, text)
	}
}

// wrap breaks prose to the terminal width and indents every line after the first.
//
// The alternative is what this tool used to do: emit a two-hundred character explanation as one
// line and let the terminal fold it at column zero, which visually detaches the continuation
// from the item it belongs to.
func (s style) wrap(text string, indent int) string {
	limit := s.width - indent
	if limit < minWidth/2 {
		limit = minWidth / 2
	}
	words := strings.Fields(text)
	if len(words) == 0 {
		return ""
	}

	var (
		lines []string
		line  strings.Builder
	)
	for _, word := range words {
		switch {
		case line.Len() == 0:
			line.WriteString(word)
		case line.Len()+1+len(word) <= limit:
			line.WriteString(" ")
			line.WriteString(word)
		default:
			lines = append(lines, line.String())
			line.Reset()
			line.WriteString(word)
		}
	}
	lines = append(lines, line.String())
	return strings.Join(lines, "\n"+strings.Repeat(" ", indent))
}

// pad right-aligns a badge column so severities line up.
func pad(text string, width int) string {
	if len(text) >= width {
		return text
	}
	return text + strings.Repeat(" ", width-len(text))
}

// visibleLen is the length of a string ignoring any escape codes it carries, so padding stays
// correct once colour is applied.
func visibleLen(text string) int {
	n, inEscape := 0, false
	for _, r := range text {
		switch {
		case inEscape:
			if r == 'm' {
				inEscape = false
			}
		case r == '\033':
			inEscape = true
		default:
			n++
		}
	}
	return n
}

// padVisible pads to a visible width, ignoring escape codes.
func padVisible(text string, width int) string {
	if n := visibleLen(text); n < width {
		return text + strings.Repeat(" ", width-n)
	}
	return text
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var digits []byte
	negative := n < 0
	if negative {
		n = -n
	}
	for n > 0 {
		digits = append([]byte{byte('0' + n%10)}, digits...)
		n /= 10
	}
	if negative {
		return "-" + string(digits)
	}
	return string(digits)
}
