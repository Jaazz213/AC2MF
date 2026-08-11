package main

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
	"time"
)

// ---------------------------------------------------------------------------
// ANSI color codes (Windows Terminal / modern consoles support these)
// ---------------------------------------------------------------------------

const (
	colorReset  = "\033[0m"
	colorRed    = "\033[91m"
	colorOrange = "\033[38;5;208m"
	colorYellow = "\033[93m"
	colorGreen  = "\033[92m"
	colorCyan   = "\033[96m"
	colorWhite  = "\033[97m"
	colorGray   = "\033[90m"
	colorBold   = "\033[1m"
	colorDim    = "\033[2m"
)

// ScanStats tracks numbers for the summary.
type ScanStats struct {
	ProcessesScanned   int
	TasksChecked       int
	PersistenceEntries int
	ServicesAnalyzed   int
	TempFilesInspected int
	ConnectionsChecked int
	CriticalFindings   int
	HighFindings       int
	MediumFindings     int
	ScanDuration       time.Duration
}

// ---------------------------------------------------------------------------
// Progress display
// ---------------------------------------------------------------------------

// PrintProgress prints a progress message with formatting.
func PrintProgress(phase string, msg string) {
	fmt.Printf("  %s[%s]%s %s\n", colorCyan, phase, colorReset, msg)
}

// PrintProgressBar draws a simple progress bar.
func PrintProgressBar(label string, current, total int) {
	if total == 0 {
		return
	}
	pct := float64(current) / float64(total)
	filled := int(pct * 30)
	if filled > 30 {
		filled = 30
	}
	bar := strings.Repeat("▓", filled) + strings.Repeat("░", 30-filled)
	fmt.Printf("\r  [%s] %s %d%%", bar, label, int(pct*100))
	if current >= total {
		fmt.Println()
	}
}

// ---------------------------------------------------------------------------
// Finding display
// ---------------------------------------------------------------------------

// PrintFinding renders a single finding as a narrative block to the console.
func PrintFinding(f Finding) {
	sevColor := colorGreen
	switch f.Severity {
	case SevCritical:
		sevColor = colorRed
	case SevHigh:
		sevColor = colorOrange
	case SevMedium:
		sevColor = colorYellow
	}

	// Top border
	fmt.Printf("\n%s══════════════════════════════════════════════════════════════%s\n", sevColor, colorReset)
	fmt.Printf("  %s%s %s — %s%s\n", colorBold, f.Severity.Emoji(), f.Severity, f.Title, colorReset)
	fmt.Printf("%s══════════════════════════════════════════════════════════════%s\n", sevColor, colorReset)

	// Narrative
	fmt.Println()
	for _, line := range wrapText("  "+f.Narrative, 62) {
		fmt.Println(line)
	}

	// Details
	fmt.Println()
	for _, d := range f.Details {
		if d.Label != "" {
			fmt.Printf("  %s➜ %-14s%s %s\n", colorCyan, d.Label+":", colorReset, d.Value)
		} else {
			fmt.Printf("  %s  %-14s%s %s\n", colorCyan, "", colorReset, d.Value)
		}
	}

	// Why it matters
	if f.WhyMatters != "" {
		fmt.Println()
		fmt.Printf("  %s%sWHY THIS MATTERS:%s ", colorBold, colorWhite, colorReset)
		lines := wrapText(f.WhyMatters, 58)
		for i, line := range lines {
			if i == 0 {
				fmt.Println(line)
			} else {
				fmt.Println("  " + line)
			}
		}
	}

	// Suggestion
	if f.Suggestion != "" {
		fmt.Println()
		fmt.Printf("  %s💡 SUGGESTION:%s ", colorYellow, colorReset)
		lines := wrapText(f.Suggestion, 58)
		for i, line := range lines {
			if i == 0 {
				fmt.Println(line)
			} else {
				fmt.Println("  " + line)
			}
		}
	}

	// Bottom border
	fmt.Printf("\n%s──────────────────────────────────────────────────────────────%s\n", colorGray, colorReset)
}

// ---------------------------------------------------------------------------
// Summary box
// ---------------------------------------------------------------------------

// PrintSummary renders the executive summary box.
func PrintSummary(stats ScanStats) {
	fmt.Println()
	fmt.Printf("%s╔══════════════════════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║                     AC2MF — SCAN SUMMARY                    ║%s\n", colorCyan, colorReset)
	fmt.Printf("%s╠══════════════════════════════════════════════════════════════╣%s\n", colorCyan, colorReset)

	fmt.Printf("%s║%s                                                              %s║%s\n", colorCyan, colorReset, colorCyan, colorReset)

	if stats.CriticalFindings > 0 {
		printSummaryLine(fmt.Sprintf("🔴 Critical findings:    %d", stats.CriticalFindings), colorRed)
	} else {
		printSummaryLine("🔴 Critical findings:    0", colorGreen)
	}
	if stats.HighFindings > 0 {
		printSummaryLine(fmt.Sprintf("🟠 High findings:        %d", stats.HighFindings), colorOrange)
	} else {
		printSummaryLine("🟠 High findings:        0", colorGreen)
	}
	if stats.MediumFindings > 0 {
		printSummaryLine(fmt.Sprintf("🟡 Medium findings:      %d", stats.MediumFindings), colorYellow)
	} else {
		printSummaryLine("🟡 Medium findings:      0", colorGreen)
	}
	printSummaryLine("🟢 Low / Clean:          Everything else looks normal", colorGreen)

	fmt.Printf("%s║%s                                                              %s║%s\n", colorCyan, colorReset, colorCyan, colorReset)

	printSummaryLine(fmt.Sprintf("Processes scanned:       %d", stats.ProcessesScanned), "")
	printSummaryLine(fmt.Sprintf("Scheduled tasks checked: %d", stats.TasksChecked), "")
	printSummaryLine(fmt.Sprintf("Persistence entries:     %d", stats.PersistenceEntries), "")
	printSummaryLine(fmt.Sprintf("Services analyzed:       %d", stats.ServicesAnalyzed), "")
	printSummaryLine(fmt.Sprintf("Temp files inspected:    %d", stats.TempFilesInspected), "")
	printSummaryLine(fmt.Sprintf("Network connections:     %d", stats.ConnectionsChecked), "")

	fmt.Printf("%s║%s                                                              %s║%s\n", colorCyan, colorReset, colorCyan, colorReset)
	printSummaryLine(fmt.Sprintf("Scan completed in %.1f seconds", stats.ScanDuration.Seconds()), "")
	fmt.Printf("%s║%s                                                              %s║%s\n", colorCyan, colorReset, colorCyan, colorReset)

	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n", colorCyan, colorReset)
}

func printSummaryLine(text, color string) {
	content := fmt.Sprintf("   %s", text)
	pad := 62 - len(content)
	if pad < 1 {
		pad = 1
	}
	if color != "" {
		fmt.Printf("%s║%s %s%s%s%s %s║%s\n", colorCyan, colorReset, color, content, colorReset, strings.Repeat(" ", pad), colorCyan, colorReset)
	} else {
		fmt.Printf("%s║%s %s%s %s║%s\n", colorCyan, colorReset, content, strings.Repeat(" ", pad), colorCyan, colorReset)
	}
}

// ---------------------------------------------------------------------------
// Unsigned Software Inventory — informational, not alarming
// ---------------------------------------------------------------------------

// PrintUnsignedInventory renders a compact table of unsigned software that is
// running from legitimate locations. Positioned near System Info, before findings.
func PrintUnsignedInventory(entries []UnsignedSoftwareEntry) {
	if len(entries) == 0 {
		return
	}

	fmt.Println()
	fmt.Printf("%s╔══════════════════════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║%s   %s📋 UNSIGNED SOFTWARE ON THIS MACHINE%s                       %s║%s\n",
		colorCyan, colorReset, colorDim, colorReset, colorCyan, colorReset)
	fmt.Printf("%s╠══════════════════════════════════════════════════════════════╣%s\n", colorCyan, colorReset)
	fmt.Printf("%s║%s                                                              %s║%s\n", colorCyan, colorReset, colorCyan, colorReset)
	fmt.Printf("%s║%s   %sThese are running programs without digital signatures.%s     %s║%s\n",
		colorCyan, colorReset, colorGray, colorReset, colorCyan, colorReset)
	fmt.Printf("%s║%s   %sNot necessarily malicious — many legitimate apps are%s       %s║%s\n",
		colorCyan, colorReset, colorGray, colorReset, colorCyan, colorReset)
	fmt.Printf("%s║%s   %sunsigned (Electron apps, indie software, etc).%s             %s║%s\n",
		colorCyan, colorReset, colorGray, colorReset, colorCyan, colorReset)
	fmt.Printf("%s║%s                                                              %s║%s\n", colorCyan, colorReset, colorCyan, colorReset)

	for _, e := range entries {
		name := e.Name
		if len(name) > 28 {
			name = name[:25] + "..."
		}
		loc := e.Location
		if len(loc) > 18 {
			loc = loc[:15] + "..."
		}
		instanceStr := ""
		if e.Instances > 1 {
			instanceStr = fmt.Sprintf(" ×%d", e.Instances)
		}
		line := fmt.Sprintf("   %-28s %s%s", name, loc, instanceStr)
		pad := 62 - len(line)
		if pad < 1 {
			pad = 1
		}
		fmt.Printf("%s║%s %s%s %s║%s\n", colorCyan, colorReset, line, strings.Repeat(" ", pad), colorCyan, colorReset)
	}

	fmt.Printf("%s║%s                                                              %s║%s\n", colorCyan, colorReset, colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n", colorCyan, colorReset)
}

// FormatUnsignedInventoryText returns a plain-text version of the unsigned inventory for file export.
func FormatUnsignedInventoryText(entries []UnsignedSoftwareEntry) string {
	if len(entries) == 0 {
		return ""
	}

	var sb strings.Builder
	sb.WriteString("  UNSIGNED SOFTWARE ON THIS MACHINE\n")
	sb.WriteString("  ──────────────────────────────────────────────────────\n")
	sb.WriteString("  (Not necessarily malicious — many legitimate apps\n")
	sb.WriteString("   are unsigned: Electron apps, indie software, etc.)\n\n")

	for _, e := range entries {
		instanceStr := ""
		if e.Instances > 1 {
			instanceStr = fmt.Sprintf(" (%d instances)", e.Instances)
		}
		sb.WriteString(fmt.Sprintf("   • %s — %s%s\n", e.Name, e.Location, instanceStr))
		sb.WriteString(fmt.Sprintf("     %s\n", e.Path))
	}
	sb.WriteString("\n")

	return sb.String()
}

// ---------------------------------------------------------------------------
// Text file export
// ---------------------------------------------------------------------------

// ansiRegex strips ANSI escape sequences for .txt export.
var ansiRegex = regexp.MustCompile(`\x1b\[[0-9;]*m`)

// StripANSI removes all ANSI color codes from a string.
func StripANSI(s string) string {
	return ansiRegex.ReplaceAllString(s, "")
}

// ExportReport writes the findings to a plain-text file.
func ExportReport(results ScanResults, stats ScanStats, sysInfo SystemInfo) {
	now := time.Now()
	filename := fmt.Sprintf("AC2MF_Report_%s.txt", now.Format("2006-01-02"))

	fmt.Println()
	fmt.Printf("%s╔══════════════════════════════════════════════════════════════╗%s\n", colorCyan, colorReset)
	fmt.Printf("%s║%s   Save report to %s? [Y/n]        %s║%s\n",
		colorCyan, colorReset, filename, colorCyan, colorReset)
	fmt.Printf("%s╚══════════════════════════════════════════════════════════════╝%s\n", colorCyan, colorReset)

	reader := bufio.NewReader(os.Stdin)
	fmt.Print("  > ")
	input, _ := reader.ReadString('\n')
	input = strings.TrimSpace(strings.ToLower(input))

	if input == "n" || input == "no" {
		fmt.Println("  Report not saved.")
		return
	}

	file, err := os.Create(filename)
	if err != nil {
		fmt.Printf("  %sError:%s Could not create file: %v\n", colorRed, colorReset, err)
		return
	}
	defer file.Close()

	w := bufio.NewWriter(file)

	// Header
	w.WriteString("================================================================\n")
	w.WriteString("  AC2MF — Active C2 Malware Finder — Report\n")
	w.WriteString(fmt.Sprintf("  Generated: %s\n", now.Format("2006-01-02 15:04:05")))
	w.WriteString("================================================================\n\n")

	// System info
	w.WriteString(StripANSI(FormatSystemInfo(sysInfo)))
	w.WriteString("\n")

	// Unsigned software inventory (informational section)
	if len(results.UnsignedInventory) > 0 {
		w.WriteString(FormatUnsignedInventoryText(results.UnsignedInventory))
	}

	// Findings
	if len(results.Findings) == 0 {
		w.WriteString("No significant findings. Everything looks clean.\n\n")
	} else {
		for _, f := range results.Findings {
			writeFindingToFile(w, f)
		}
	}

	// Summary
	w.WriteString("\n")
	w.WriteString("================================================================\n")
	w.WriteString("                     AC2MF — SCAN SUMMARY\n")
	w.WriteString("================================================================\n\n")

	if stats.CriticalFindings > 0 {
		w.WriteString(fmt.Sprintf("  CRITICAL findings:     %d\n", stats.CriticalFindings))
	}
	if stats.HighFindings > 0 {
		w.WriteString(fmt.Sprintf("  HIGH findings:         %d\n", stats.HighFindings))
	}
	if stats.MediumFindings > 0 {
		w.WriteString(fmt.Sprintf("  MEDIUM findings:       %d\n", stats.MediumFindings))
	}
	w.WriteString(fmt.Sprintf("\n  Processes scanned:       %d\n", stats.ProcessesScanned))
	w.WriteString(fmt.Sprintf("  Scheduled tasks checked: %d\n", stats.TasksChecked))
	w.WriteString(fmt.Sprintf("  Persistence entries:     %d\n", stats.PersistenceEntries))
	w.WriteString(fmt.Sprintf("  Services analyzed:       %d\n", stats.ServicesAnalyzed))
	w.WriteString(fmt.Sprintf("  Temp files inspected:    %d\n", stats.TempFilesInspected))
	w.WriteString(fmt.Sprintf("  Network connections:     %d\n", stats.ConnectionsChecked))
	w.WriteString(fmt.Sprintf("\n  Scan completed in %.1f seconds\n", stats.ScanDuration.Seconds()))

	w.WriteString("\n================================================================\n")
	w.WriteString("  This tool does NOT replace an antivirus.\n")
	w.WriteString("  AC2MF by Jazz — https://github.com/jazzi\n")
	w.WriteString("================================================================\n")

	w.Flush()

	fmt.Printf("\n  %s✅ Report saved to %s%s\n", colorGreen, filename, colorReset)
}

func writeFindingToFile(w *bufio.Writer, f Finding) {
	w.WriteString("==============================================================\n")
	w.WriteString(fmt.Sprintf("  %s %s — %s\n", severityText(f.Severity), f.Severity, f.Title))
	w.WriteString("==============================================================\n\n")

	for _, line := range wrapText("  "+f.Narrative, 62) {
		w.WriteString(line)
		w.WriteString("\n")
	}
	w.WriteString("\n")

	for _, d := range f.Details {
		if d.Label != "" {
			w.WriteString(fmt.Sprintf("  -> %-14s %s\n", d.Label+":", StripANSI(d.Value)))
		} else {
			w.WriteString(fmt.Sprintf("     %-14s %s\n", "", StripANSI(d.Value)))
		}
	}

	if f.WhyMatters != "" {
		w.WriteString("\n  WHY THIS MATTERS: ")
		lines := wrapText(f.WhyMatters, 58)
		for i, line := range lines {
			if i > 0 {
				w.WriteString("  ")
			}
			w.WriteString(line)
			w.WriteString("\n")
		}
	}

	if f.Suggestion != "" {
		w.WriteString("\n  SUGGESTION: ")
		lines := wrapText(f.Suggestion, 58)
		for i, line := range lines {
			if i > 0 {
				w.WriteString("  ")
			}
			w.WriteString(line)
			w.WriteString("\n")
		}
	}

	w.WriteString("\n--------------------------------------------------------------\n\n")
}

func severityText(s SeverityLevel) string {
	switch s {
	case SevCritical:
		return "[!!!]"
	case SevHigh:
		return "[!!]"
	case SevMedium:
		return "[!]"
	default:
		return "[i]"
	}
}

// ---------------------------------------------------------------------------
// Text wrapping helper
// ---------------------------------------------------------------------------

func wrapText(text string, maxWidth int) []string {
	var lines []string
	paragraphs := strings.Split(text, "\n")

	for _, para := range paragraphs {
		para = strings.TrimSpace(para)
		if para == "" {
			lines = append(lines, "")
			continue
		}

		words := strings.Fields(para)
		if len(words) == 0 {
			continue
		}

		current := words[0]
		for _, w := range words[1:] {
			if len(current)+1+len(w) > maxWidth {
				lines = append(lines, current)
				current = w
			} else {
				current += " " + w
			}
		}
		lines = append(lines, current)
	}

	return lines
}
