package main

import (
	"fmt"
	"strings"
)

// SeverityLevel classifies a finding.
type SeverityLevel int

const (
	SevLow      SeverityLevel = iota // 0–30
	SevMedium                        // 31–60
	SevHigh                          // 61–90
	SevCritical                      // >90
)

func (s SeverityLevel) String() string {
	switch s {
	case SevLow:
		return "LOW"
	case SevMedium:
		return "MEDIUM"
	case SevHigh:
		return "HIGH"
	case SevCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

func (s SeverityLevel) Emoji() string {
	switch s {
	case SevLow:
		return "🟢"
	case SevMedium:
		return "🟡"
	case SevHigh:
		return "🟠"
	case SevCritical:
		return "🔴"
	default:
		return "⚪"
	}
}

func ScoreToSeverity(score int) SeverityLevel {
	switch {
	case score > 90:
		return SevCritical
	case score > 60:
		return SevHigh
	case score > 30:
		return SevMedium
	default:
		return SevLow
	}
}

// ---------------------------------------------------------------------------
// Finding — the universal scored output item
// ---------------------------------------------------------------------------

// Finding is the unified structure that gets turned into a narrative block.
type Finding struct {
	Severity    SeverityLevel
	Score       int
	Title       string       // Short title for the finding box header
	Narrative   string       // The human-readable story paragraph
	Details     []FindingDetail // key→value pairs (➜ Location: ...)
	WhyMatters  string       // "WHY THIS MATTERS:" paragraph
	Suggestion  string       // "SUGGESTION:" paragraph (Critical/High only)
	Source      string       // Which scanner produced this ("process", "task", "persistence", "service", "temp", "network")
	RelatedPID  uint32
	RelatedPath string
}

// FindingDetail is a single key→value pair for the details section.
type FindingDetail struct {
	Label string
	Value string
}

// ---------------------------------------------------------------------------
// Score individual items — called per-module
// ---------------------------------------------------------------------------

// ScoreProcess assigns a base score to a process based on its properties.
func ScoreProcess(p *ProcessInfo) {
	if p.IsWhitelisted {
		p.Score = 0
		return
	}

	// Processes in user-space trusted paths (AppData\Local\Programs) are
	// legitimate installs — they get collected for the unsigned inventory
	// instead of being flagged as findings.
	if p.IsInPrograms {
		p.Score = 0
		return
	}

	score := 0

	// Unsigned executable — only a minor signal on its own
	if !p.Signature.IsSigned() && p.Signature != SignatureError {
		score += 10
	}

	// Running from Temp — this is the real C2 indicator
	if p.IsInTemp {
		score += 45
		// Unsigned + Temp = very suspicious combination
		if !p.Signature.IsSigned() && p.Signature != SignatureError {
			score += 20 // extra on top of the base 10
		}
	}

	// Running from AppData (but NOT Programs, NOT Temp)
	if p.IsInAppData && !p.IsInTemp && !p.IsInPrograms {
		score += 15
	}

	// Running from Desktop
	if p.IsOnDesktop {
		score += 15
	}

	// Typosquatting
	if p.Typosquat != "" {
		score += 35
	}

	// High resource usage (non-browser)
	if p.MemoryMB > 300 && !p.IsBrowser && !p.IsWhitelisted {
		score += 15
	}

	// Not in any trusted path
	if p.FullPath != "" && !IsInTrustedPath(p.FullPath) && !IsInUserSpaceTrustedPath(p.FullPath) && !p.IsWhitelisted {
		score += 10
	}

	p.Score = score
}

// ScoreTask assigns a base score to a scheduled task.
func ScoreTask(t *TaskInfo) {
	if t.IsKnownMS {
		t.Score = 0
		return
	}

	score := 15 // Base: non-Microsoft task

	if t.IsInTemp {
		score += 40
	}
	if t.IsInAppData {
		score += 20
	}
	if t.IsScript {
		score += 25
	}
	if t.ActionSigned == Unsigned {
		score += 30
	}
	if t.DaysSince >= 0 && t.DaysSince < 7 {
		score += 15 // Recently created
	}
	if t.RunLevel == "HighestAvailable" {
		score += 10
	}

	t.Score = score
}

// ScorePersistence assigns a base score to a persistence entry.
func ScorePersistence(pe *PersistenceEntry) {
	score := 10 // Base: has persistence

	if pe.IsInTemp {
		score += 40
	}
	if pe.IsInAppData {
		score += 15
	}
	if pe.IsScript {
		score += 25
	}
	if pe.Signature == Unsigned {
		score += 30
	}

	// IFEO debugger entries are inherently suspicious
	if pe.Type == "IFEO Debugger" {
		score += 40
	}
	// AppInit_DLLs is rarely used legitimately
	if pe.Type == "AppInit_DLLs" {
		score += 35
	}
	// Winlogon modifications
	if strings.HasPrefix(pe.Type, "Winlogon") {
		score += 45
	}
	// WMI subscriptions
	if strings.HasPrefix(pe.Type, "WMI") {
		score += 40
	}

	pe.Score = score
}

// ScoreService assigns a base score to a service.
func ScoreService(si *ServiceInfo) {
	score := 0

	if si.IsInTemp {
		score += 50
	}
	if si.IsInAppData {
		score += 30
	}
	if si.Signature == Unsigned && si.State == "Running" {
		score += 35
	}
	if !si.IsInTrusted && si.State == "Running" {
		score += 20
	}

	si.Score = score
}

// ScoreTempFile assigns a base score to a temp file.
func ScoreTempFile(tf *TempFileInfo) {
	score := 10 // Base: suspicious file in temp

	if tf.IsExecutable {
		score += 25
		if tf.Signature == Unsigned {
			score += 25
		} else if tf.Signature == SignedValid {
			// Signed executable in temp that's just sitting there = much less alarming
			score -= 15
		}
		if tf.IsRecent {
			score += 15
		}
	}

	if tf.IsScript {
		score += 20
		if tf.IsRecent {
			score += 15
		}
	}

	if tf.IsShortcut {
		score += 10
	}

	if tf.IsLarge && tf.IsExecutable {
		score += 10
	}

	if score < 0 {
		score = 0
	}
	tf.Score = score
}

// ---------------------------------------------------------------------------
// UnsignedSoftwareEntry — informational inventory item (not a threat finding)
// ---------------------------------------------------------------------------

// UnsignedSoftwareEntry represents an unsigned executable that is running
// but is in a legitimate location. Shown in the informational inventory,
// not as a threat finding.
type UnsignedSoftwareEntry struct {
	Name       string
	Path       string
	Instances  int      // how many PIDs running this executable
	PIDs       []uint32
	MemoryMB   uint64   // total memory across all instances
	Location   string   // human-readable location description
}

// ScanResults holds all correlation outputs.
type ScanResults struct {
	Findings          []Finding
	UnsignedInventory []UnsignedSoftwareEntry
}

// ---------------------------------------------------------------------------
// Cross-module correlation — the multipliers that catch compound threats
// ---------------------------------------------------------------------------

// CorrelateAndBuildFindings takes all scan results, applies cross-module
// correlation multipliers, and produces the final list of Findings sorted
// by severity, plus the unsigned software inventory.
func CorrelateAndBuildFindings(
	procs []ProcessInfo,
	tasks []TaskInfo,
	persistence []PersistenceEntry,
	services []ServiceInfo,
	tempFiles []TempFileInfo,
	netInfo []ProcessNetworkInfo,
	progress func(string),
) ScanResults {
	progress("Running correlation engine...")

	// ── Score individual items ──
	for i := range procs {
		ScoreProcess(&procs[i])
	}
	for i := range tasks {
		ScoreTask(&tasks[i])
	}
	for i := range persistence {
		ScorePersistence(&persistence[i])
	}
	for i := range services {
		ScoreService(&services[i])
	}
	for i := range tempFiles {
		ScoreTempFile(&tempFiles[i])
	}

	// ── Build cross-reference indexes ──

	// Process paths (lowercase) → index
	procByPath := make(map[string]int)
	procByName := make(map[string]int)
	for i, p := range procs {
		if p.FullPath != "" {
			procByPath[strings.ToLower(p.FullPath)] = i
		}
		procByName[strings.ToLower(p.Name)] = i
	}

	// Persistence targets (lowercase)
	persistTargets := make(map[string]int)
	for i, pe := range persistence {
		if pe.TargetPath != "" {
			persistTargets[strings.ToLower(pe.TargetPath)] = i
		}
		if pe.Value != "" {
			persistTargets[strings.ToLower(pe.Value)] = i
		}
	}

	// Network info by PID
	netByPID := make(map[uint32]int)
	for i, ni := range netInfo {
		netByPID[ni.PID] = i
	}

	// ── Cross-module correlations ──

	// 1. Unsigned process + Registry persistence → ×1.5
	for i, p := range procs {
		if p.Score == 0 {
			continue
		}
		pathLower := strings.ToLower(p.FullPath)
		if _, hasPersist := persistTargets[pathLower]; hasPersist {
			if !p.Signature.IsSigned() {
				procs[i].Score = int(float64(procs[i].Score) * 1.5)
			}
		}
	}

	// 2. Process in Temp + scheduled task referencing it → ×2.0
	for i, p := range procs {
		if p.IsInTemp && p.Score > 0 {
			nameLower := strings.ToLower(p.Name)
			for _, t := range tasks {
				for _, a := range t.Actions {
					if strings.Contains(strings.ToLower(a.Command), nameLower) ||
						strings.Contains(strings.ToLower(a.Args), nameLower) {
						procs[i].Score = int(float64(procs[i].Score) * 2.0)
						break
					}
				}
			}
		}
	}

	// 3. Script in Temp + interpreter process + persistence → ×2.5
	for i, tf := range tempFiles {
		if tf.IsScript && tf.Score > 0 {
			nameLower := strings.ToLower(tf.Name)
			hasPersist := false
			for _, pe := range persistence {
				if strings.Contains(strings.ToLower(pe.Value), nameLower) {
					hasPersist = true
					break
				}
			}
			if hasPersist {
				tempFiles[i].Score = int(float64(tempFiles[i].Score) * 2.5)
			}
		}
	}

	// 4. Executable in Temp + recently created + unsigned → ×1.8
	for i, tf := range tempFiles {
		if tf.IsExecutable && tf.IsRecent && tf.Signature == Unsigned {
			tempFiles[i].Score = int(float64(tempFiles[i].Score) * 1.8)
		}
	}

	// 5. System process with remote connections (INJECTION DETECTION) → high score
	// Already scored in network module, but boost further if process also has
	// other anomalies
	for i, ni := range netInfo {
		if pidIdx, ok := procByName[strings.ToLower(ni.ProcessName)]; ok {
			p := procs[pidIdx]
			// If the process is whitelisted (i.e. legit explorer.exe) but
			// has remote connections — this is the injection red flag
			if p.IsWhitelisted && ni.Score > 0 {
				netInfo[i].Score = int(float64(ni.Score) * 1.5)
			}
		}
	}

	// 6. Unsigned process + high memory → ×1.3
	for i, p := range procs {
		if !p.Signature.IsSigned() && p.MemoryMB > 500 && !p.IsBrowser {
			procs[i].Score = int(float64(procs[i].Score) * 1.3)
		}
	}

	// ── Collect Unsigned Software Inventory ──
	// Group unsigned processes from user-space trusted paths for informational display
	unsignedByPath := make(map[string]*UnsignedSoftwareEntry)
	for _, p := range procs {
		if p.IsWhitelisted || p.FullPath == "" {
			continue
		}
		if !p.Signature.IsSigned() && p.Signature != SignatureError {
			pathLower := strings.ToLower(p.FullPath)
			if entry, exists := unsignedByPath[pathLower]; exists {
				entry.Instances++
				entry.PIDs = append(entry.PIDs, p.PID)
				entry.MemoryMB += p.MemoryMB
			} else {
				unsignedByPath[pathLower] = &UnsignedSoftwareEntry{
					Name:      p.Name,
					Path:      p.FullPath,
					Instances: 1,
					PIDs:      []uint32{p.PID},
					MemoryMB:  p.MemoryMB,
					Location:  locationDescription(p.FullPath),
				}
			}
		}
	}

	var unsignedInventory []UnsignedSoftwareEntry
	for _, entry := range unsignedByPath {
		// Only include in inventory if the process is NOT going to be a finding
		// (i.e., it's in a trusted/user-space location or has low score)
		if IsInUserSpaceTrustedPath(entry.Path) || IsInTrustedPath(entry.Path) {
			unsignedInventory = append(unsignedInventory, *entry)
		}
	}

	// ── Build Findings ──
	var findings []Finding

	// Process findings — GROUP by executable path to avoid duplicates
	type processGroup struct {
		Representative ProcessInfo
		PIDs           []uint32
		TotalMemory    uint64
		Count          int
		MaxScore       int
	}
	procGroups := make(map[string]*processGroup)

	for _, p := range procs {
		if p.Score <= 30 {
			continue
		}
		pathKey := strings.ToLower(p.FullPath)
		if pathKey == "" {
			pathKey = strings.ToLower(p.Name) + "_nopath"
		}

		if grp, exists := procGroups[pathKey]; exists {
			grp.PIDs = append(grp.PIDs, p.PID)
			grp.TotalMemory += p.MemoryMB
			grp.Count++
			if p.Score > grp.MaxScore {
				grp.MaxScore = p.Score
				grp.Representative = p
			}
		} else {
			procGroups[pathKey] = &processGroup{
				Representative: p,
				PIDs:           []uint32{p.PID},
				TotalMemory:    p.MemoryMB,
				Count:          1,
				MaxScore:       p.Score,
			}
		}
	}

	for _, grp := range procGroups {
		grp.Representative.Score = grp.MaxScore
		grp.Representative.MemoryMB = grp.TotalMemory
		findings = append(findings, buildProcessFinding(grp.Representative, grp.Count, grp.PIDs, persistence, tasks, netByPID, netInfo))
	}

	// Task findings
	for _, t := range tasks {
		if t.Score <= 30 {
			continue
		}
		findings = append(findings, buildTaskFinding(t))
	}

	// Persistence findings
	for _, pe := range persistence {
		if pe.Score <= 30 {
			continue
		}
		// Skip if already covered by a process finding
		already := false
		for _, f := range findings {
			if f.RelatedPath != "" && strings.EqualFold(f.RelatedPath, pe.TargetPath) {
				already = true
				break
			}
		}
		if !already {
			findings = append(findings, buildPersistenceFinding(pe))
		}
	}

	// Service findings
	for _, si := range services {
		if si.Score <= 30 {
			continue
		}
		findings = append(findings, buildServiceFinding(si))
	}

	// Temp file findings (deduplicate with process findings)
	for _, tf := range tempFiles {
		if tf.Score <= 30 {
			continue
		}
		already := false
		for _, f := range findings {
			if strings.EqualFold(f.RelatedPath, tf.Path) {
				already = true
				break
			}
		}
		if !already {
			findings = append(findings, buildTempFileFinding(tf))
		}
	}

	// Network/injection findings
	for _, ni := range netInfo {
		if ni.Score <= 30 {
			continue
		}
		findings = append(findings, buildNetworkFinding(ni))
	}

	// Sort by score descending
	sortFindings(findings)

	progress(fmt.Sprintf("  Correlation complete: %d findings above threshold", len(findings)))
	if len(unsignedInventory) > 0 {
		progress(fmt.Sprintf("  Unsigned software inventory: %d entries", len(unsignedInventory)))
	}
	return ScanResults{
		Findings:          findings,
		UnsignedInventory: unsignedInventory,
	}
}


func sortFindings(f []Finding) {
	// Simple insertion sort (list is small)
	for i := 1; i < len(f); i++ {
		key := f[i]
		j := i - 1
		for j >= 0 && f[j].Score < key.Score {
			f[j+1] = f[j]
			j--
		}
		f[j+1] = key
	}
}

// ---------------------------------------------------------------------------
// Finding builders — turn scored data into narrative findings
// ---------------------------------------------------------------------------

func buildProcessFinding(p ProcessInfo, instanceCount int, pids []uint32, persist []PersistenceEntry, tasks []TaskInfo, netByPID map[uint32]int, netInfo []ProcessNetworkInfo) Finding {
	sev := ScoreToSeverity(p.Score)

	// Build narrative
	var narr strings.Builder
	if instanceCount > 1 {
		fmt.Fprintf(&narr, `"%s" has %d instances running`, p.Name, instanceCount)
	} else {
		fmt.Fprintf(&narr, `"%s" is running`, p.Name)
	}
	if p.IsInTemp {
		narr.WriteString(" from your Temp folder")
	} else if p.IsOnDesktop {
		narr.WriteString(" from your Desktop")
	} else if p.IsInAppData {
		narr.WriteString(" from your AppData folder")
	} else if p.FullPath != "" {
		fmt.Fprintf(&narr, " from %s", locationDescription(p.FullPath))
	}

	if !p.Signature.IsSigned() {
		narr.WriteString(" and has no digital signature")
	}
	narr.WriteString(".")

	// Check for persistence link
	for _, pe := range persist {
		if pe.TargetPath != "" && strings.EqualFold(pe.TargetPath, p.FullPath) {
			fmt.Fprintf(&narr, " It is set to auto-start via %s.", pe.Type)
			break
		}
		if strings.Contains(strings.ToLower(pe.Value), strings.ToLower(p.Name)) {
			fmt.Fprintf(&narr, " It is referenced by a %s entry (%s).", pe.Type, pe.Name)
			break
		}
	}

	// Check for task link
	for _, t := range tasks {
		for _, a := range t.Actions {
			if strings.Contains(strings.ToLower(a.Command), strings.ToLower(p.Name)) {
				fmt.Fprintf(&narr, ` It was started by a scheduled task called "%s".`, t.Name)
				if t.DaysSince >= 0 && t.DaysSince < 30 {
					fmt.Fprintf(&narr, " That task was created %d days ago.", t.DaysSince)
				}
				break
			}
		}
	}

	// Check for network connections (check all PIDs in group)
	for _, pid := range pids {
		if idx, ok := netByPID[pid]; ok && idx < len(netInfo) {
			ni := netInfo[idx]
			if ni.HasRemoteConns {
				fmt.Fprintf(&narr, " It has %d active remote network connections to %d unique IPs.",
					ni.TotalRemoteConns, len(ni.UniqueRemoteIPs))
				break
			}
		}
	}

	if p.MemoryMB > 50 {
		if instanceCount > 1 {
			fmt.Fprintf(&narr, "\n\n  Total memory across all instances: %d MB.", p.MemoryMB)
		} else {
			fmt.Fprintf(&narr, "\n\n  It is currently consuming %d MB of memory.", p.MemoryMB)
		}
	}

	// Details
	var details []FindingDetail
	if p.FullPath != "" {
		details = append(details, FindingDetail{"Location", p.FullPath})
	}
	details = append(details, FindingDetail{"Signature", p.Signature.String()})
	if instanceCount > 1 {
		details = append(details, FindingDetail{"Instances", fmt.Sprintf("%d", instanceCount)})
	}
	if p.MemoryMB > 0 {
		label := "Memory"
		if instanceCount > 1 {
			label = "Total Memory"
		}
		details = append(details, FindingDetail{label, fmt.Sprintf("%d MB", p.MemoryMB)})
	}
	if p.Username != "" {
		details = append(details, FindingDetail{"Running as", p.Username})
	}
	if p.Typosquat != "" {
		details = append(details, FindingDetail{"⚠ Mimics", p.Typosquat})
	}

	// Why it matters
	why := buildProcessWhyMatters(p)

	// Suggestion
	suggestion := ""
	if sev >= SevHigh {
		suggestion = buildProcessSuggestion(p)
	}

	title := "Suspicious process"
	if p.Typosquat != "" {
		title = fmt.Sprintf("Process mimicking %s", p.Typosquat)
	} else if p.IsInTemp {
		title = "Suspicious process running from Temp folder"
	} else if !p.Signature.IsSigned() {
		title = "Unsigned process in unusual location"
	}

	return Finding{
		Severity:    sev,
		Score:       p.Score,
		Title:       title,
		Narrative:   narr.String(),
		Details:     details,
		WhyMatters:  why,
		Suggestion:  suggestion,
		Source:      "process",
		RelatedPID:  p.PID,
		RelatedPath: p.FullPath,
	}
}

func buildProcessWhyMatters(p ProcessInfo) string {
	if p.Typosquat != "" {
		return fmt.Sprintf("This process name is suspiciously similar to the legitimate Windows process \"%s\". "+
			"Malware often uses names that look like system processes to avoid detection. "+
			"The real %s only runs from its expected Windows directory.", p.Typosquat, p.Typosquat)
	}
	if p.IsInTemp {
		return "Legitimate software doesn't normally run from your Temp folder. " +
			"Unsigned executables in temporary directories are a common pattern for malware " +
			"that was recently downloaded or dropped by another program."
	}
	if p.IsInAppData {
		return "While some legitimate software installs to AppData, unsigned executables " +
			"in this location deserve scrutiny. Malware frequently uses AppData because " +
			"it doesn't require admin privileges to write there."
	}
	if !p.Signature.IsSigned() {
		return "Most legitimate software is digitally signed by its developer. " +
			"Unsigned executables are not necessarily malicious, but deserve a closer look."
	}
	return "This process has multiple indicators that warrant investigation."
}

func buildProcessSuggestion(p ProcessInfo) string {
	if p.IsInTemp {
		return "Investigate this file immediately. If you don't recognize it, " +
			"consider terminating the process and deleting the file. " +
			"Check for any scheduled tasks or startup entries that reference it."
	}
	if p.Typosquat != "" {
		return fmt.Sprintf("This is NOT the real %s. Investigate the file at its location. "+
			"If you didn't install this software, terminate the process and delete the file.", p.Typosquat)
	}
	return "Investigate this file. If you don't recognize it, consider terminating " +
		"the process and removing any persistence mechanisms that reference it."
}

func buildTaskFinding(t TaskInfo) Finding {
	sev := ScoreToSeverity(t.Score)

	var narr strings.Builder
	if t.IsScript {
		fmt.Fprintf(&narr, `A scheduled task "%s" runs a script`, t.Name)
	} else {
		fmt.Fprintf(&narr, `A scheduled task "%s" executes a program`, t.Name)
	}

	if t.ActionPath != "" {
		if t.IsInTemp {
			narr.WriteString(" located in a Temp folder")
		}
		fmt.Fprintf(&narr, `: %s`, t.ActionPath)
	}
	narr.WriteString(".")

	if len(t.Triggers) > 0 {
		fmt.Fprintf(&narr, " It is triggered %s.", strings.Join(t.Triggers, ", "))
	}
	if t.DaysSince >= 0 && t.DaysSince < 30 {
		fmt.Fprintf(&narr, " It was created %d days ago.", t.DaysSince)
	}

	var details []FindingDetail
	details = append(details, FindingDetail{"Task", t.Path})
	if t.ActionPath != "" {
		details = append(details, FindingDetail{"Action", t.ActionPath})
	}
	if len(t.Triggers) > 0 {
		details = append(details, FindingDetail{"Triggers", strings.Join(t.Triggers, ", ")})
	}
	if t.Author != "" {
		details = append(details, FindingDetail{"Author", t.Author})
	}
	if !t.CreatedDate.IsZero() {
		details = append(details, FindingDetail{"Created", t.CreatedDate.Format("2006-01-02")})
	}
	if t.ActionSigned != SignatureError {
		details = append(details, FindingDetail{"Signature", t.ActionSigned.String()})
	}

	why := "Scheduled tasks that run scripts or unsigned executables — especially from " +
		"temporary folders — are a common persistence mechanism for malware. " +
		"They allow malicious code to survive reboots and run without user interaction."

	suggestion := ""
	if sev >= SevHigh {
		suggestion = fmt.Sprintf(`Inspect the file that this task runs. If you don't recognize it, `+
			`delete the task with: schtasks /delete /tn "%s" /f`, t.Path)
	}

	return Finding{
		Severity:    sev,
		Score:       t.Score,
		Title:       fmt.Sprintf(`Suspicious scheduled task "%s"`, t.Name),
		Narrative:   narr.String(),
		Details:     details,
		WhyMatters:  why,
		Suggestion:  suggestion,
		Source:      "task",
		RelatedPath: t.ActionPath,
	}
}

func buildPersistenceFinding(pe PersistenceEntry) Finding {
	sev := ScoreToSeverity(pe.Score)

	var narr strings.Builder
	switch {
	case strings.HasPrefix(pe.Type, "WMI"):
		fmt.Fprintf(&narr, "A WMI event subscription \"%s\" was found that can execute code "+
			"automatically in response to system events.", pe.Name)
	case pe.Type == "IFEO Debugger":
		fmt.Fprintf(&narr, "An Image File Execution Options debugger is set for \"%s\", "+
			"which means every time that program runs, it actually runs \"%s\" instead.", pe.Name, pe.Value)
	case pe.Type == "AppInit_DLLs":
		fmt.Fprintf(&narr, "AppInit_DLLs is configured to load \"%s\" into every process "+
			"that uses User32.dll — essentially injecting code into most programs.", pe.Value)
	case strings.HasPrefix(pe.Type, "Winlogon"):
		fmt.Fprintf(&narr, "The Winlogon %s value has been modified to \"%s\". "+
			"This controls what runs when you log into Windows.", pe.Name, pe.Value)
	default:
		fmt.Fprintf(&narr, "A %s entry \"%s\" was found", pe.Type, pe.Name)
		if pe.IsScript {
			narr.WriteString(" that references a script")
		}
		if pe.IsInTemp {
			narr.WriteString(" located in a Temp folder")
		}
		fmt.Fprintf(&narr, ": %s.", pe.Value)
	}

	var details []FindingDetail
	details = append(details, FindingDetail{"Type", pe.Type})
	details = append(details, FindingDetail{"Location", pe.Location})
	details = append(details, FindingDetail{"Value", pe.Value})
	if pe.Signature != SignatureError && pe.TargetPath != "" {
		details = append(details, FindingDetail{"Signature", pe.Signature.String()})
	}

	why := buildPersistenceWhyMatters(pe)
	suggestion := ""
	if sev >= SevHigh {
		suggestion = "Investigate the file referenced by this entry. If it's not recognized, " +
			"remove the persistence mechanism and delete the file."
	}

	return Finding{
		Severity:    sev,
		Score:       pe.Score,
		Title:       fmt.Sprintf("%s persistence detected", pe.Type),
		Narrative:   narr.String(),
		Details:     details,
		WhyMatters:  why,
		Suggestion:  suggestion,
		Source:      "persistence",
		RelatedPath: pe.TargetPath,
	}
}

func buildPersistenceWhyMatters(pe PersistenceEntry) string {
	switch {
	case strings.HasPrefix(pe.Type, "WMI"):
		return "WMI event subscriptions are a stealthy persistence technique. " +
			"They're rarely used by legitimate software but frequently by advanced malware."
	case pe.Type == "IFEO Debugger":
		return "IFEO debugger hijacking redirects a legitimate program to run malicious code instead. " +
			"This is an advanced persistence technique used to survive reboots."
	case pe.Type == "AppInit_DLLs":
		return "AppInit_DLLs injects a DLL into virtually every process on the system. " +
			"This is extremely unusual in modern Windows and is a classic code injection technique."
	case strings.HasPrefix(pe.Type, "Winlogon"):
		return "Modifying Winlogon Shell or Userinit allows malware to run every time a user logs in, " +
			"before the normal desktop even loads."
	default:
		if pe.IsInTemp {
			return "Startup entries pointing to files in Temp folders are suspicious. " +
				"Legitimate software installs to Program Files, not Temp."
		}
		if pe.IsScript {
			return "Scripts set to auto-run at login are a common malware persistence technique. " +
				"They're easy to modify and can download additional payloads."
		}
		return "This persistence entry runs automatically and may be keeping unwanted software active."
	}
}

func buildServiceFinding(si ServiceInfo) Finding {
	sev := ScoreToSeverity(si.Score)

	var narr strings.Builder
	fmt.Fprintf(&narr, `A Windows service "%s"`, si.DisplayName)
	if si.DisplayName != si.Name {
		fmt.Fprintf(&narr, ` (internal name: %s)`, si.Name)
	}
	if si.State == "Running" {
		narr.WriteString(" is currently running")
	} else {
		narr.WriteString(" is installed")
	}

	if si.IsInTemp {
		narr.WriteString(" from a Temp folder")
	} else if si.IsInAppData {
		narr.WriteString(" from AppData")
	}

	if si.Signature == Unsigned {
		narr.WriteString(" and its binary is unsigned")
	}
	narr.WriteString(".")

	var details []FindingDetail
	details = append(details, FindingDetail{"Service", si.Name})
	details = append(details, FindingDetail{"Display Name", si.DisplayName})
	details = append(details, FindingDetail{"Binary", si.BinaryPath})
	details = append(details, FindingDetail{"State", si.State})
	details = append(details, FindingDetail{"Start Type", si.StartType})
	if si.Account != "" {
		details = append(details, FindingDetail{"Account", si.Account})
	}
	if si.Signature != SignatureError {
		details = append(details, FindingDetail{"Signature", si.Signature.String()})
	}

	why := "Services run with elevated privileges and start automatically. " +
		"A service running unsigned code from an unusual location is a strong indicator " +
		"of malware that has achieved persistent, privileged access to the system."

	suggestion := ""
	if sev >= SevHigh {
		suggestion = fmt.Sprintf("Investigate the binary at the path shown above. To stop and disable: "+
			`sc stop "%s" && sc config "%s" start= disabled`, si.Name, si.Name)
	}

	return Finding{
		Severity:    sev,
		Score:       si.Score,
		Title:       fmt.Sprintf(`Suspicious service "%s"`, si.DisplayName),
		Narrative:   narr.String(),
		Details:     details,
		WhyMatters:  why,
		Suggestion:  suggestion,
		Source:      "service",
		RelatedPath: si.BinaryPath,
	}
}

func buildTempFileFinding(tf TempFileInfo) Finding {
	sev := ScoreToSeverity(tf.Score)

	var narr strings.Builder
	if tf.IsExecutable {
		fmt.Fprintf(&narr, `An executable "%s" was found in the Temp folder`, tf.Name)
	} else if tf.IsScript {
		fmt.Fprintf(&narr, `A script "%s" was found in the Temp folder`, tf.Name)
	} else if tf.IsArchive {
		fmt.Fprintf(&narr, `An archive "%s" was found in the Temp folder`, tf.Name)
	} else {
		fmt.Fprintf(&narr, `A suspicious file "%s" was found in the Temp folder`, tf.Name)
	}

	if tf.Owner != "" {
		fmt.Fprintf(&narr, " belonging to %s", tf.Owner)
	}
	narr.WriteString(".")

	if tf.IsRecent {
		fmt.Fprintf(&narr, " It was created %d days ago.", tf.DaysOld)
	}
	if tf.IsLarge {
		fmt.Fprintf(&narr, " It is %.1f MB in size.", tf.SizeMB)
	}
	if tf.IsExecutable && tf.Signature == Unsigned {
		narr.WriteString(" The file is not digitally signed.")
	}

	var details []FindingDetail
	details = append(details, FindingDetail{"File", tf.Path})
	details = append(details, FindingDetail{"Size", fmt.Sprintf("%.1f MB", tf.SizeMB)})
	details = append(details, FindingDetail{"Modified", tf.ModTime.Format("2006-01-02 15:04")})
	if tf.IsExecutable {
		details = append(details, FindingDetail{"Signature", tf.Signature.String()})
	}

	why := "Files in Temp folders are meant to be temporary. Executables, scripts, " +
		"and archives in these locations — especially recent ones — may indicate " +
		"malware that was recently downloaded or dropped by an exploit."

	suggestion := ""
	if sev >= SevHigh {
		suggestion = "Inspect this file carefully. If you don't recognize it, delete it. " +
			"Check if any process is using it or if any persistence mechanism references it."
	}

	return Finding{
		Severity:    sev,
		Score:       tf.Score,
		Title:       fmt.Sprintf("Suspicious file in Temp: %s", tf.Name),
		Narrative:   narr.String(),
		Details:     details,
		WhyMatters:  why,
		Suggestion:  suggestion,
		Source:      "temp",
		RelatedPath: tf.Path,
	}
}

func buildNetworkFinding(ni ProcessNetworkInfo) Finding {
	sev := ScoreToSeverity(ni.Score)

	var narr strings.Builder
	fmt.Fprintf(&narr, `"%s" is a legitimate Windows system process, but it has %d active `,
		ni.ProcessName, ni.TotalRemoteConns)
	if ni.TotalRemoteConns == 1 {
		narr.WriteString("connection")
	} else {
		narr.WriteString("connections")
	}
	fmt.Fprintf(&narr, " to %d remote IP address", len(ni.UniqueRemoteIPs))
	if len(ni.UniqueRemoteIPs) > 1 {
		narr.WriteString("es")
	}
	narr.WriteString(". This process should not normally communicate with the internet.\n\n")
	narr.WriteString("  This is a strong indicator of process injection — malware may have\n")
	narr.WriteString("  injected code into this trusted process to hide its network activity.")

	var details []FindingDetail
	details = append(details, FindingDetail{"Process", ni.ProcessName})
	details = append(details, FindingDetail{"Remote Connections", fmt.Sprintf("%d", ni.TotalRemoteConns)})

	// List first few IPs
	ipCount := 0
	for ip := range ni.UniqueRemoteIPs {
		if ipCount >= 5 {
			details = append(details, FindingDetail{"", fmt.Sprintf("... and %d more", len(ni.UniqueRemoteIPs)-5)})
			break
		}
		label := "Remote IP"
		if ipCount > 0 {
			label = ""
		}
		// Find the port
		port := ""
		for _, c := range ni.RemoteConns {
			if c.RemoteAddr == ip {
				port = fmt.Sprintf(":%d (%s)", c.RemotePort, c.State)
				break
			}
		}
		details = append(details, FindingDetail{label, ip + port})
		ipCount++
	}

	why := fmt.Sprintf(`"%s" is a core Windows process that does NOT normally make outbound `+
		`internet connections. When you see a trusted system process connecting to remote `+
		`IP addresses, it typically means malware has injected malicious code into the process. `+
		`This technique is called "process injection" and is used to evade security software `+
		`by hiding behind a trusted process name.`, ni.ProcessName)

	suggestion := "This requires immediate investigation. Use a tool like Process Explorer " +
		"or Process Hacker to inspect the loaded DLLs and threads of this process. " +
		"Consider running a full antivirus scan. If the connections persist, the system " +
		"may be compromised."

	return Finding{
		Severity:    sev,
		Score:       ni.Score,
		Title:       fmt.Sprintf("Possible process injection in %s — unexpected remote connections", ni.ProcessName),
		Narrative:   narr.String(),
		Details:     details,
		WhyMatters:  why,
		Suggestion:  suggestion,
		Source:      "network",
		RelatedPID:  ni.PID,
	}
}

func locationDescription(path string) string {
	lower := strings.ToLower(path)
	if strings.Contains(lower, `\temp\`) || strings.Contains(lower, `\tmp\`) {
		return "a Temp folder"
	}
	if strings.Contains(lower, `\desktop\`) {
		return "the Desktop"
	}
	if strings.Contains(lower, `\downloads\`) {
		return "the Downloads folder"
	}
	if strings.Contains(lower, `\appdata\`) {
		return "the AppData folder"
	}
	if strings.HasPrefix(lower, `c:\program files`) {
		return "Program Files"
	}
	if strings.HasPrefix(lower, `c:\windows\`) {
		return "the Windows directory"
	}
	return "an unusual location"
}
