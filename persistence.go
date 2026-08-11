package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows/registry"
)

// PersistenceEntry represents a single persistence mechanism found.
type PersistenceEntry struct {
	Type        string // "Registry Run", "Registry RunOnce", "Startup Folder", "WMI", "IFEO", "AppInit", "Winlogon"
	Location    string // Registry key path or folder
	Name        string // Value name or file name
	Value       string // Command / path
	Hive        string // "HKCU" or "HKLM"

	// Analysis
	TargetPath  string          // Resolved executable path
	Signature   SignatureStatus
	IsScript    bool
	IsInTemp    bool
	IsInAppData bool
	Score       int
}

// ScanPersistence checks all common persistence mechanisms.
func ScanPersistence(progress func(string)) []PersistenceEntry {
	var results []PersistenceEntry

	progress("Scanning Registry Run keys...")
	results = append(results, scanRegistryRunKeys(progress)...)

	progress("Scanning Startup folders...")
	results = append(results, scanStartupFolders(progress)...)

	progress("Scanning IFEO debugger keys...")
	results = append(results, scanIFEO(progress)...)

	progress("Scanning AppInit_DLLs...")
	results = append(results, scanAppInitDLLs(progress)...)

	progress("Scanning Winlogon Shell/Userinit...")
	results = append(results, scanWinlogon(progress)...)

	progress("Scanning WMI event subscriptions...")
	results = append(results, scanWMISubscriptions(progress)...)

	progress(fmt.Sprintf("  Found %d persistence entries", len(results)))
	return results
}

// ---------------------------------------------------------------------------
// Registry Run / RunOnce
// ---------------------------------------------------------------------------

func scanRegistryRunKeys(progress func(string)) []PersistenceEntry {
	type regTarget struct {
		hive     registry.Key
		hiveName string
		path     string
		typeName string
	}

	targets := []regTarget{
		{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\Run`, "Registry Run"},
		{registry.CURRENT_USER, "HKCU", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "Registry RunOnce"},
		{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\Run`, "Registry Run"},
		{registry.LOCAL_MACHINE, "HKLM", `Software\Microsoft\Windows\CurrentVersion\RunOnce`, "Registry RunOnce"},
		{registry.LOCAL_MACHINE, "HKLM", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "Registry Run (WOW64)"},
		{registry.LOCAL_MACHINE, "HKLM", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "Registry RunOnce (WOW64)"},
	}

	var results []PersistenceEntry

	for _, t := range targets {
		k, err := registry.OpenKey(t.hive, t.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, err := k.ReadValueNames(-1)
		if err != nil {
			k.Close()
			continue
		}
		for _, name := range names {
			val, _, err := k.GetStringValue(name)
			if err != nil {
				continue
			}
			entry := PersistenceEntry{
				Type:     t.typeName,
				Location: t.hiveName + `\` + t.path,
				Name:     name,
				Value:    val,
				Hive:     t.hiveName,
			}
			analyzePersistenceValue(&entry)
			results = append(results, entry)
		}
		k.Close()
	}

	return results
}

// ---------------------------------------------------------------------------
// Startup Folder
// ---------------------------------------------------------------------------

func scanStartupFolders(progress func(string)) []PersistenceEntry {
	var results []PersistenceEntry

	folders := []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
	}

	// Also check other users' startup folders
	userDirs, _ := os.ReadDir(`C:\Users`)
	for _, u := range userDirs {
		if u.IsDir() && !strings.HasPrefix(u.Name(), ".") {
			folder := filepath.Join(`C:\Users`, u.Name(), `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`)
			if _, err := os.Stat(folder); err == nil {
				// Avoid duplicates
				isDup := false
				for _, f := range folders {
					if strings.EqualFold(f, folder) {
						isDup = true
						break
					}
				}
				if !isDup {
					folders = append(folders, folder)
				}
			}
		}
	}

	for _, folder := range folders {
		entries, err := os.ReadDir(folder)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			fullPath := filepath.Join(folder, e.Name())
			entry := PersistenceEntry{
				Type:     "Startup Folder",
				Location: folder,
				Name:     e.Name(),
				Value:    fullPath,
			}

			// Resolve .lnk files
			if strings.EqualFold(filepath.Ext(e.Name()), ".lnk") {
				resolved := resolveLnk(fullPath)
				if resolved != "" {
					entry.TargetPath = resolved
					entry.Value = resolved
				}
			}

			analyzePersistenceValue(&entry)
			results = append(results, entry)
		}
	}

	return results
}

// resolveLnk attempts to resolve a .lnk shortcut target via PowerShell.
func resolveLnk(lnkPath string) string {
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		fmt.Sprintf(`(New-Object -ComObject WScript.Shell).CreateShortcut('%s').TargetPath`, lnkPath)).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// ---------------------------------------------------------------------------
// Image File Execution Options (IFEO) — Debugger persistence
// ---------------------------------------------------------------------------

func scanIFEO(progress func(string)) []PersistenceEntry {
	var results []PersistenceEntry

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`,
		registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return results
	}
	defer k.Close()

	names, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return results
	}

	for _, name := range names {
		subKey, err := registry.OpenKey(registry.LOCAL_MACHINE,
			`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\`+name,
			registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		debugger, _, err := subKey.GetStringValue("Debugger")
		subKey.Close()
		if err != nil || debugger == "" {
			continue
		}

		entry := PersistenceEntry{
			Type:     "IFEO Debugger",
			Location: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\` + name,
			Name:     name,
			Value:    debugger,
			Hive:     "HKLM",
		}
		analyzePersistenceValue(&entry)
		results = append(results, entry)
	}

	return results
}

// ---------------------------------------------------------------------------
// AppInit_DLLs
// ---------------------------------------------------------------------------

func scanAppInitDLLs(progress func(string)) []PersistenceEntry {
	var results []PersistenceEntry

	paths := []string{
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
	}

	for _, p := range paths {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, p, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		val, _, err := k.GetStringValue("AppInit_DLLs")
		k.Close()
		if err != nil || strings.TrimSpace(val) == "" {
			continue
		}

		entry := PersistenceEntry{
			Type:     "AppInit_DLLs",
			Location: `HKLM\` + p,
			Name:     "AppInit_DLLs",
			Value:    val,
			Hive:     "HKLM",
		}
		analyzePersistenceValue(&entry)
		results = append(results, entry)
	}

	return results
}

// ---------------------------------------------------------------------------
// Winlogon Shell / Userinit
// ---------------------------------------------------------------------------

func scanWinlogon(progress func(string)) []PersistenceEntry {
	var results []PersistenceEntry

	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, registry.QUERY_VALUE)
	if err != nil {
		return results
	}
	defer k.Close()

	checkValue := func(valueName, expected string) {
		val, _, err := k.GetStringValue(valueName)
		if err != nil || val == "" {
			return
		}
		// Only flag if modified from default
		if !strings.EqualFold(strings.TrimSpace(val), expected) {
			entry := PersistenceEntry{
				Type:     "Winlogon " + valueName,
				Location: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`,
				Name:     valueName,
				Value:    val,
				Hive:     "HKLM",
			}
			analyzePersistenceValue(&entry)
			results = append(results, entry)
		}
	}

	checkValue("Shell", "explorer.exe")
	checkValue("Userinit", `C:\Windows\system32\userinit.exe,`)

	return results
}

// ---------------------------------------------------------------------------
// WMI Event Subscriptions
// ---------------------------------------------------------------------------

func scanWMISubscriptions(progress func(string)) []PersistenceEntry {
	var results []PersistenceEntry

	// Query WMI for event consumers via PowerShell
	classes := []string{
		"CommandLineEventConsumer",
		"ActiveScriptEventConsumer",
	}

	for _, class := range classes {
		out, err := exec.Command("powershell", "-NoProfile", "-Command",
			fmt.Sprintf(`Get-WmiObject -Namespace root\subscription -Class %s -ErrorAction SilentlyContinue | ForEach-Object { $_.Name + '|||' + $_.CommandLineTemplate + $_.ScriptText }`, class)).Output()
		if err != nil {
			continue
		}

		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			parts := strings.SplitN(line, "|||", 2)
			name := parts[0]
			value := ""
			if len(parts) > 1 {
				value = parts[1]
			}

			entry := PersistenceEntry{
				Type:     "WMI " + class,
				Location: `root\subscription\` + class,
				Name:     name,
				Value:    value,
			}
			analyzePersistenceValue(&entry)
			results = append(results, entry)
		}
	}

	// Also check for FilterToConsumerBinding
	out, err := exec.Command("powershell", "-NoProfile", "-Command",
		`Get-WmiObject -Namespace root\subscription -Class __FilterToConsumerBinding -ErrorAction SilentlyContinue | ForEach-Object { $_.Filter + ' -> ' + $_.Consumer }`).Output()
	if err == nil {
		for _, line := range strings.Split(string(out), "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			entry := PersistenceEntry{
				Type:     "WMI FilterToConsumerBinding",
				Location: `root\subscription\__FilterToConsumerBinding`,
				Name:     "Binding",
				Value:    line,
			}
			// WMI bindings are inherently suspicious in most environments
			entry.Score = 50
			results = append(results, entry)
		}
	}

	return results
}

// ---------------------------------------------------------------------------
// Common analysis helper
// ---------------------------------------------------------------------------

func analyzePersistenceValue(entry *PersistenceEntry) {
	val := strings.ToLower(entry.Value)

	// Extract the executable path from command lines
	exePath := extractExePath(entry.Value)
	if entry.TargetPath == "" && exePath != "" {
		entry.TargetPath = exePath
	}

	// Script detection
	scriptExts := []string{".ps1", ".vbs", ".bat", ".cmd", ".js", ".wsf", ".hta"}
	for _, ext := range scriptExts {
		if strings.Contains(val, ext) {
			entry.IsScript = true
			break
		}
	}

	// Location analysis
	if strings.Contains(val, `\temp\`) || strings.Contains(val, `\tmp\`) {
		entry.IsInTemp = true
	}
	if strings.Contains(val, `\appdata\`) {
		entry.IsInAppData = true
	}

	// Signature check on resolved target
	if entry.TargetPath != "" {
		entry.Signature = VerifySignature(entry.TargetPath)
	}
}

// extractExePath tries to pull the executable path from a command line string.
func extractExePath(cmdLine string) string {
	cmdLine = strings.TrimSpace(cmdLine)
	if cmdLine == "" {
		return ""
	}

	// Handle quoted paths
	if cmdLine[0] == '"' {
		end := strings.Index(cmdLine[1:], `"`)
		if end > 0 {
			return cmdLine[1 : end+1]
		}
	}

	// Try splitting on space
	parts := strings.Fields(cmdLine)
	if len(parts) > 0 {
		candidate := parts[0]
		// Expand environment variables
		candidate = os.ExpandEnv(candidate)
		if strings.ContainsAny(candidate, `\/:`) {
			return candidate
		}
	}

	return cmdLine
}
