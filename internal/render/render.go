// Package render turns a scan into the two things a reader wants: a terminal report they can
// act on, and a machine-readable document they can gate a pipeline with.
//
// Both come from the same Result, so a column added to one can never silently miss the other.
package render

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/runtimez-com/kube-upgrade-check/internal/catalog"
	"github.com/runtimez-com/kube-upgrade-check/internal/report"
	"github.com/runtimez-com/kube-upgrade-check/internal/support"
)

// Format is the -o value.
type Format string

const (
	FormatTable Format = "table"
	FormatWide  Format = "wide"
	FormatJSON  Format = "json"
	FormatYAML  Format = "yaml"
)

// ParseFormat validates an -o value.
func ParseFormat(s string) (Format, error) {
	switch Format(strings.ToLower(strings.TrimSpace(s))) {
	case FormatTable, "":
		return FormatTable, nil
	case FormatWide:
		return FormatWide, nil
	case FormatJSON:
		return FormatJSON, nil
	case FormatYAML:
		return FormatYAML, nil
	default:
		return "", fmt.Errorf("unsupported output format %q (want table, wide, json or yaml)", s)
	}
}

// Structured reports whether the format is machine-readable, in which case nothing decorative
// may be printed.
func (f Format) Structured() bool { return f == FormatJSON || f == FormatYAML }

// Printer writes one scan's result.
type Printer struct {
	Out    io.Writer
	Format Format
}

// New builds a printer over stdout.
func New(format Format) *Printer { return &Printer{Out: os.Stdout, Format: format} }

// Print renders the result in the requested format.
func (p *Printer) Print(result report.Result) error {
	switch p.Format {
	case FormatJSON:
		enc := json.NewEncoder(p.Out)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case FormatYAML:
		// Routed through JSON so both machine formats carry identical field names. Encoding the
		// struct directly would use Go field names in YAML and the JSON tags in JSON, so the two
		// outputs of one scan would disagree about what anything is called.
		raw, err := json.Marshal(result)
		if err != nil {
			return err
		}
		var generic any
		if err := json.Unmarshal(raw, &generic); err != nil {
			return err
		}
		enc := yaml.NewEncoder(p.Out)
		enc.SetIndent(2)
		if err := enc.Encode(generic); err != nil {
			return err
		}
		return enc.Close()
	default:
		return p.printHuman(result)
	}
}

// printHuman writes the terminal report.
//
// The order is what someone reading at speed needs: what breaks, then the add-ons, then what is
// worth reading, then what could not be checked, then the deadline. The gaps sit above the
// deadline rather than at the very bottom, because a reader who stops early should still have
// seen them.
func (p *Printer) printHuman(r report.Result) error {
	w := p.Out
	st := newStyle(w)

	p.printHeader(w, st, r)

	breaks, advisories := split(r.Findings)
	p.printBreaks(w, st, r, breaks)
	p.printAddons(w, st, r)
	p.printAdvisories(w, st, advisories)
	p.printGaps(w, st, r)
	p.printFooter(w, st, r)
	return nil
}

func (p *Printer) printHeader(w io.Writer, st style, r report.Result) {
	details := []string{r.CurrentVersion}
	if r.Provider != "" {
		details = append(details, r.Provider)
	}
	details = append(details, pluralize(r.NodeCount, "node"))

	fmt.Fprintf(w, "\n  %s %s\n", st.bold(nameOr(r.Cluster, "(unnamed context)")), st.dim("("+strings.Join(details, ", ")+")"))
	fmt.Fprintf(w, "  %s %s   %s %s\n\n",
		st.dim("upgrade to"), st.bold(r.TargetVersion),
		st.dim("risk"), st.score(r.Score, r.RiskLevel))
}

func (p *Printer) printBreaks(w io.Writer, st style, r report.Result, breaks []report.Finding) {
	if len(breaks) == 0 {
		fmt.Fprintf(w, "  %s\n", st.heading("BREAKS"))
		fmt.Fprintf(w, "    %s\n", st.green("Nothing found that this upgrade breaks."))
		// Said here, not in a footnote: a clean list means nothing if half the checks could not
		// run, and this is the sentence that stops it being misread.
		if r.ScanStatus != report.ScanComplete {
			fmt.Fprintf(w, "    %s\n", st.dim(st.wrap(
				"Some checks could not run. Read COULD NOT SEE below before taking this as a clean result.", 4)))
		}
		fmt.Fprintln(w)
		return
	}

	fmt.Fprintf(w, "  %s %s\n", st.heading("BREAKS"), st.dim("("+itoa(len(breaks))+")"))
	for _, f := range breaks {
		badge := padVisible(st.severity(f.Severity), 5)
		fmt.Fprintf(w, "    %s %s\n", badge, st.wrap(headline(f), 10))
		fmt.Fprintf(w, "          %s\n", st.dim(f.RuleID))
		// The fix belongs with the problem. Wide mode adds the vendor's own words underneath.
		if f.Recommendation != "" {
			fmt.Fprintf(w, "          %s\n", st.wrap(f.Recommendation, 10))
		}
		if p.Format == FormatWide {
			if f.Quote != "" {
				fmt.Fprintf(w, "          %s\n", st.dim(st.wrap("vendor: \""+f.Quote+"\"", 10)))
			}
			if f.SourceURL != "" {
				fmt.Fprintf(w, "          %s\n", st.dim(f.SourceURL))
			}
			for _, e := range f.Evidence {
				fmt.Fprintf(w, "          %s\n", st.dim(st.wrap(e, 10)))
			}
		}
		fmt.Fprintln(w)
	}
}

func (p *Printer) printAddons(w io.Writer, st style, r report.Result) {
	if len(r.Addons) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s %s\n", st.heading("ADD-ONS"), st.dim("("+itoa(len(r.Addons))+" detected)"))

	labels := make([]string, len(r.Addons))
	nameWidth := 0
	for i, a := range r.Addons {
		labels[i] = a.DisplayName + " " + nameOr(a.InstalledVersion, "version unknown")
		if n := len(labels[i]); n > nameWidth {
			nameWidth = n
		}
	}
	// Four spaces, a two-character marker, a space, the label, two spaces. The verdict wraps
	// under itself rather than under the marker.
	const addonPrefix = 4 + 2 + 1 + 2
	for i, a := range r.Addons {
		fmt.Fprintf(w, "    %s %s  %s\n", addonMarker(st, a.Verdict), pad(labels[i], nameWidth),
			st.wrap(addonVerdict(a), nameWidth+addonPrefix))
	}
	fmt.Fprintln(w)

	if notes := addonNotes(r.Addons); len(notes) > 0 {
		fmt.Fprintf(w, "  %s %s\n", st.heading("ADD-ON UPGRADE NOTES"), st.dim("("+itoa(len(notes))+")"))
		for _, n := range notes {
			fmt.Fprintf(w, "    %s %s\n", st.dim("-"), st.wrap(n, 6))
		}
		fmt.Fprintln(w)
	}
}

func (p *Printer) printAdvisories(w io.Writer, st style, advisories []report.Finding) {
	if len(advisories) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s %s\n", st.heading("WORTH READING"), st.dim("("+itoa(len(advisories))+")"))
	fmt.Fprintf(w, "    %s\n", st.dim(st.wrap(
		"Changes on this path that no API call can check against your cluster.", 4)))
	for _, f := range advisories {
		fmt.Fprintf(w, "    %s %s\n", st.dim("-"), st.wrap(f.Title, 6))
		if f.VerifyCommand != "" {
			fmt.Fprintf(w, "      %s %s\n", st.dim("check:"), st.cyan(truncateCommand(f.VerifyCommand, st.width-14)))
		}
	}
	fmt.Fprintln(w)
}

func (p *Printer) printGaps(w io.Writer, st style, r report.Result) {
	gaps := groupGaps(unavailable(r.Coverage))
	if len(gaps) == 0 {
		return
	}
	fmt.Fprintf(w, "  %s %s\n", st.heading("COULD NOT SEE"), st.dim("("+itoa(len(gaps))+")"))
	for _, g := range gaps {
		header := g.source
		if g.rulesSkipped > 0 {
			header += st.dim(" — " + itoa(g.rulesSkipped) + " rules not checked")
		}
		fmt.Fprintf(w, "    %s %s\n", st.dim("-"), header)
		fmt.Fprintf(w, "      %s\n", st.dim(st.wrap(g.reason, 6)))
		if len(g.scopes) > 0 {
			fmt.Fprintf(w, "      %s %s\n", st.dim("affects:"), st.dim(st.wrap(strings.Join(g.scopes, ", "), 15)))
		}
		if g.verify != "" {
			fmt.Fprintf(w, "      %s %s\n", st.dim("check:"), st.cyan(truncateCommand(g.verify, st.width-14)))
		}
	}
	fmt.Fprintln(w)
}

func (p *Printer) printFooter(w io.Writer, st style, r report.Result) {
	fmt.Fprintf(w, "  %s\n", st.wrap(support.Describe(r.Support, r.CurrentVersion), 2))
	if r.PatchCurrency != nil && !r.PatchCurrency.UpToDate {
		fmt.Fprintf(w, "  %s\n", st.wrap(fmt.Sprintf(
			"This cluster runs %s; the newest patch of that minor is %s.",
			r.PatchCurrency.CurrentPatch, r.PatchCurrency.LatestPatch), 2))
	}
	fmt.Fprintf(w, "\n  %s\n\n", st.dim("Continuous checks across every cluster, with history: "+productLink))
}

// truncateCommand keeps a long one-liner on one line rather than wrapping a shell command,
// which would make it unsafe to copy.
func truncateCommand(cmd string, limit int) string {
	cmd = strings.TrimSpace(cmd)
	if limit < 40 {
		limit = 40
	}
	if len(cmd) <= limit {
		return cmd
	}
	return cmd[:limit-1] + "…"
}

// productLink is the one piece of promotion in the output, on its own line at the end.
const productLink = "https://runtimez.io/upgrade?utm_source=kube-upgrade-check"

// split separates real breaks from advisory items, which are printed apart so a list of things
// to read never dilutes a list of things that break.
//
// The "could not check" findings are dropped here rather than listed a second time: they are
// already the subject of their own section, with the reason and the command to check by hand.
func split(findings []report.Finding) (breaks, advisories []report.Finding) {
	for _, f := range findings {
		if strings.HasSuffix(f.RuleID, "-not-assessed") {
			continue
		}
		if f.EnforcementLevel == "advisory" || f.Severity == catalog.SeverityInfo {
			advisories = append(advisories, f)
			continue
		}
		breaks = append(breaks, f)
	}
	return breaks, advisories
}

// gap is one reason something could not be checked, with everything it affected.
type gap struct {
	source       string
	reason       string
	verify       string
	scopes       []string
	rulesSkipped int
}

// groupGaps folds rows that share a source and a reason into one entry.
//
// An account without broad read access produces the same denial for thirty resource types.
// Printing thirty near-identical lines buries the two gaps that are specific, and makes a
// solvable permission problem look like thirty separate ones.
func groupGaps(coverage []report.Coverage) []gap {
	order := []string{}
	byKey := map[string]*gap{}

	for _, c := range coverage {
		key := c.Source + "|" + c.Reason
		g, ok := byKey[key]
		if !ok {
			g = &gap{source: c.Source, reason: c.Reason, verify: c.VerifyCommand}
			byKey[key] = g
			order = append(order, key)
		}
		g.rulesSkipped += c.RulesSkipped
		if c.Scope != "" {
			g.scopes = append(g.scopes, c.Scope)
		}
		// One shared command beats thirty variations of it, so a per-scope command is kept
		// only while the group has a single member.
		if len(g.scopes) > 1 {
			g.verify = ""
		}
	}

	out := make([]gap, 0, len(order))
	for _, key := range order {
		g := byKey[key]
		sort.Strings(g.scopes)
		out = append(out, *g)
	}
	return out
}

func unavailable(coverage []report.Coverage) []report.Coverage {
	var out []report.Coverage
	for _, c := range coverage {
		if c.State != report.CoverageComplete {
			out = append(out, c)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Source < out[j].Source })
	return out
}

// headline is the one line a reader scans.
//
// It leads with what is wrong, not with what was observed. An early draft printed the evidence
// first, which produced rows like "Detected Ingress-NGINX v1.13.3 from DaemonSet/..." — true,
// and no help at all in answering whether this upgrade is safe.
func headline(f report.Finding) string {
	title := f.Title
	if f.ResourceName != "" && !strings.Contains(title, f.ResourceName) {
		return f.ResourceName + " — " + title
	}
	return title
}

// addonMarker distinguishes the three answers an add-on check can give.
//
// A vendor who publishes no compatibility matrix, and an add-on whose version we could not read,
// are not the same as one we know is too old. Marking both with the same alarm would overstate
// what we know; marking both as fine would understate it. The unknowns get their own marker.
func addonMarker(st style, verdict string) string {
	switch verdict {
	case "SUPPORTED":
		return st.green("ok")
	case "ABOVE_MAX", "BELOW_MIN":
		return st.red("!!")
	default:
		return st.paint(ansiYellow, "??")
	}
}

func addonVerdict(a report.AddonStatus) string {
	switch a.Verdict {
	case "SUPPORTED":
		return "supported"
	case "ABOVE_MAX":
		s := fmt.Sprintf("does not support the target (vendor ceiling: Kubernetes %s)", a.MaxK8s)
		if a.MinimumVersionFix != "" {
			s += fmt.Sprintf(" — upgrade to at least %s", a.MinimumVersionFix)
		}
		return s
	case "BELOW_MIN":
		s := fmt.Sprintf("older than the target supports (vendor floor: Kubernetes %s)", a.MinK8s)
		if a.MinimumVersionFix != "" {
			s += fmt.Sprintf(" — upgrade to at least %s", a.MinimumVersionFix)
		}
		return s
	case "NO_VENDOR_DATA":
		return "the vendor publishes no compatibility matrix, so this could not be checked"
	case "VERSION_UNRESOLVED":
		return "installed version could not be determined, so this could not be checked"
	case "VERSION_NOT_IN_CATALOG":
		return "this version is not in the vendor's table, so this could not be checked"
	default:
		return strings.ToLower(a.Verdict)
	}
}

func addonNotes(addons []report.AddonStatus) []string {
	var out []string
	for _, a := range addons {
		for _, n := range a.UpgradeNotes {
			out = append(out, fmt.Sprintf("%s %s: %s", a.DisplayName, n.Version, n.Title))
		}
	}
	return out
}

func severityLabel(s catalog.Severity) string {
	switch s {
	case catalog.SeverityCritical:
		return "CRIT"
	case catalog.SeverityHigh:
		return "HIGH"
	case catalog.SeverityMedium:
		return "MED "
	case catalog.SeverityLow:
		return "LOW "
	default:
		return "INFO"
	}
}

// pluralize keeps the summary line reading like prose rather than a data dump.
func pluralize(n int, noun string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, noun)
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func nameOr(value, whenEmpty string) string {
	if strings.TrimSpace(value) == "" {
		return whenEmpty
	}
	return value
}
