package main

import (
	"encoding/xml"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// TaskInfo holds analysis results for a single scheduled task.
type TaskInfo struct {
	Name         string
	Path         string
	State        string
	Author       string
	Description  string
	CreatedDate  time.Time
	DaysSince    int
	Actions      []TaskAction
	Triggers     []string
	RunLevel     string

	// Analysis
	IsKnownMS       bool
	ActionSigned    SignatureStatus
	ActionPath      string
	IsScript        bool
	IsInTemp        bool
	IsInAppData     bool
	Score           int
}

// TaskAction represents a single action within a task.
type TaskAction struct {
	Type    string // "Exec", "ComHandler"
	Command string
	Args    string
}

// ---------------------------------------------------------------------------
// XML structures for schtasks /query /xml
// ---------------------------------------------------------------------------

type schtasksOutput struct {
	Tasks []xmlTask `xml:"Task"`
}

type xmlTask struct {
	XMLName        xml.Name        `xml:"Task"`
	RegistrationInfo xmlRegInfo    `xml:"RegistrationInfo"`
	Triggers       xmlTriggers     `xml:"Triggers"`
	Principals     xmlPrincipals   `xml:"Principals"`
	Actions        xmlActions      `xml:"Actions"`
	Settings       xmlSettings     `xml:"Settings"`
}

type xmlRegInfo struct {
	Description string `xml:"Description"`
	Author      string `xml:"Author"`
	Date        string `xml:"Date"`
	URI         string `xml:"URI"`
}

type xmlTriggers struct {
	CalendarTrigger []xmlTrigger `xml:"CalendarTrigger"`
	TimeTrigger     []xmlTrigger `xml:"TimeTrigger"`
	LogonTrigger    []xmlTrigger `xml:"LogonTrigger"`
	BootTrigger     []xmlTrigger `xml:"BootTrigger"`
	IdleTrigger     []xmlTrigger `xml:"IdleTrigger"`
	EventTrigger    []xmlTrigger `xml:"EventTrigger"`
}

type xmlTrigger struct {
	Enabled string `xml:"Enabled"`
}

type xmlPrincipals struct {
	Principal xmlPrincipal `xml:"Principal"`
}

type xmlPrincipal struct {
	RunLevel string `xml:"RunLevel"`
	UserId   string `xml:"UserId"`
	GroupId  string `xml:"GroupId"`
}

type xmlActions struct {
	Exec []xmlExecAction `xml:"Exec"`
}

type xmlExecAction struct {
	Command   string `xml:"Command"`
	Arguments string `xml:"Arguments"`
}

type xmlSettings struct {
	Enabled string `xml:"Enabled"`
}

// ScanScheduledTasks enumerates and analyses all scheduled tasks.
func ScanScheduledTasks(progress func(string)) []TaskInfo {
	progress("Querying scheduled tasks...")

	// Get list of tasks via schtasks /query /fo csv
	listOut, err := exec.Command("schtasks", "/query", "/fo", "csv", "/nh").Output()
	if err != nil {
		progress(fmt.Sprintf("  Could not query tasks: %v", err))
		return nil
	}

	lines := strings.Split(string(listOut), "\n")
	var taskPaths []string
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// CSV: "TaskName","Next Run Time","Status"
		parts := strings.SplitN(line, `","`, 3)
		if len(parts) < 1 {
			continue
		}
		taskName := strings.Trim(parts[0], `"`)
		if taskName == "TaskName" || taskName == "" {
			continue
		}
		taskPaths = append(taskPaths, taskName)
	}

	progress(fmt.Sprintf("  Found %d tasks, analyzing...", len(taskPaths)))

	var results []TaskInfo

	for _, tp := range taskPaths {
		ti := TaskInfo{
			Path: tp,
			Name: lastSegment(tp),
		}

		// Check if known Microsoft task
		ti.IsKnownMS = IsKnownMicrosoftTask(tp)

		// Get XML details for non-MS tasks (or all if we want full data)
		if !ti.IsKnownMS {
			analyzeTask(&ti, progress)
		}

		results = append(results, ti)
	}

	// Count non-MS for reporting
	suspicious := 0
	for _, t := range results {
		if !t.IsKnownMS {
			suspicious++
		}
	}
	progress(fmt.Sprintf("  Analyzed %d tasks (%d non-Microsoft)", len(results), suspicious))

	return results
}

func analyzeTask(ti *TaskInfo, progress func(string)) {
	xmlOut, err := exec.Command("schtasks", "/query", "/tn", ti.Path, "/xml", "ONE").Output()
	if err != nil {
		return
	}

	var task xmlTask
	if err := xml.Unmarshal(xmlOut, &task); err != nil {
		return
	}

	ti.Author = task.RegistrationInfo.Author
	ti.Description = task.RegistrationInfo.Description
	ti.RunLevel = task.Principals.Principal.RunLevel

	// Parse creation date
	if task.RegistrationInfo.Date != "" {
		for _, layout := range []string{
			"2006-01-02T15:04:05",
			"2006-01-02T15:04:05.9999999",
			"2006-01-02T15:04:05Z",
			time.RFC3339,
		} {
			t, err := time.Parse(layout, task.RegistrationInfo.Date)
			if err == nil {
				ti.CreatedDate = t
				ti.DaysSince = int(time.Since(t).Hours() / 24)
				break
			}
		}
	}

	// Triggers
	if len(task.Triggers.LogonTrigger) > 0 {
		ti.Triggers = append(ti.Triggers, "At logon")
	}
	if len(task.Triggers.BootTrigger) > 0 {
		ti.Triggers = append(ti.Triggers, "At boot")
	}
	if len(task.Triggers.CalendarTrigger) > 0 {
		ti.Triggers = append(ti.Triggers, "Scheduled")
	}
	if len(task.Triggers.TimeTrigger) > 0 {
		ti.Triggers = append(ti.Triggers, "Timed")
	}
	if len(task.Triggers.EventTrigger) > 0 {
		ti.Triggers = append(ti.Triggers, "On event")
	}
	if len(task.Triggers.IdleTrigger) > 0 {
		ti.Triggers = append(ti.Triggers, "On idle")
	}

	// Actions
	for _, a := range task.Actions.Exec {
		action := TaskAction{
			Type:    "Exec",
			Command: a.Command,
			Args:    a.Arguments,
		}
		ti.Actions = append(ti.Actions, action)

		cmd := strings.ToLower(a.Command)
		ti.ActionPath = a.Command

		// Script detection
		scriptExts := []string{".ps1", ".vbs", ".bat", ".cmd", ".js", ".wsf", ".hta"}
		for _, ext := range scriptExts {
			if strings.HasSuffix(cmd, ext) || strings.Contains(strings.ToLower(a.Arguments), ext) {
				ti.IsScript = true
				break
			}
		}
		// Also check if action is powershell/cmd running a script
		if strings.Contains(cmd, "powershell") || strings.Contains(cmd, "cmd") || strings.Contains(cmd, "wscript") || strings.Contains(cmd, "cscript") || strings.Contains(cmd, "mshta") {
			if a.Arguments != "" {
				ti.IsScript = true
			}
		}

		// Location analysis
		if strings.Contains(cmd, `\temp\`) || strings.Contains(cmd, `\tmp\`) ||
			strings.Contains(strings.ToLower(a.Arguments), `\temp\`) {
			ti.IsInTemp = true
		}
		if strings.Contains(cmd, `\appdata\`) || strings.Contains(strings.ToLower(a.Arguments), `\appdata\`) {
			ti.IsInAppData = true
		}

		// Signature check
		if strings.HasSuffix(cmd, ".exe") {
			ti.ActionSigned = VerifySignature(a.Command)
		}
	}

	// State via settings
	if task.Settings.Enabled == "false" {
		ti.State = "Disabled"
	} else {
		ti.State = "Enabled"
	}
}

func lastSegment(path string) string {
	parts := strings.Split(path, `\`)
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] != "" {
			return parts[i]
		}
	}
	return path
}
