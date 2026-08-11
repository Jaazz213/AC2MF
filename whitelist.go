package main

import (
	"path/filepath"
	"strings"
)

// ---------------------------------------------------------------------------
// Whitelisted Windows system processes — only trusted when running from their
// expected directory.  Map key = lowercase exe name, value = lowercase
// expected directory suffix (we compare with HasSuffix so both
// "C:\Windows\System32" and "\\?\C:\Windows\System32" match).
// ---------------------------------------------------------------------------

var trustedSystemProcesses = map[string]string{
	// Core Windows
	"csrss.exe":                    `\windows\system32`,
	"smss.exe":                     `\windows\system32`,
	"wininit.exe":                  `\windows\system32`,
	"winlogon.exe":                 `\windows\system32`,
	"services.exe":                 `\windows\system32`,
	"lsass.exe":                    `\windows\system32`,
	"svchost.exe":                  `\windows\system32`,
	"dwm.exe":                      `\windows\system32`,
	"conhost.exe":                  `\windows\system32`,
	"taskhostw.exe":                `\windows\system32`,
	"taskhost.exe":                 `\windows\system32`,
	"explorer.exe":                 `\windows`,
	"ctfmon.exe":                   `\windows\system32`,
	"dllhost.exe":                  `\windows\system32`,
	"sihost.exe":                   `\windows\system32`,
	"fontdrvhost.exe":              `\windows\system32`,
	"dashost.exe":                  `\windows\system32`,
	"searchindexer.exe":            `\windows\system32`,
	"searchprotocolhost.exe":       `\windows\system32`,
	"searchfilterhost.exe":         `\windows\system32`,
	"runtimebroker.exe":            `\windows\system32`,
	"applicationframehost.exe":     `\windows\system32`,
	"shellexperiencehost.exe":      `\windows\systemapps`,
	"startmenuexperiencehost.exe":  `\windows\systemapps`,
	"textinputhost.exe":            `\windows\systemapps`,
	"lockapp.exe":                  `\windows\systemapps`,
	"systemsettings.exe":           `\windows\immersivecontrolpanel`,
	"winstore.app.exe":             `\windowsapps`,
	"spoolsv.exe":                  `\windows\system32`,
	"wudfhost.exe":                 `\windows\system32`,
	"audiodg.exe":                  `\windows\system32`,
	"msdtc.exe":                    `\windows\system32`,
	"lsm.exe":                      `\windows\system32`,
	"wlanext.exe":                  `\windows\system32`,
	"consent.exe":                  `\windows\system32`,
	"securityhealthsystray.exe":    `\windows\system32`,
	"securityhealthservice.exe":    `\windows\system32`,
	"smartscreen.exe":              `\windows\system32`,
	"sgrmbroker.exe":               `\windows\system32`,
	"msmpeng.exe":                  `\programdata\microsoft\windows defender`,
	"nissrv.exe":                   `\programdata\microsoft\windows defender`,
	"mpcmdrun.exe":                 `\programdata\microsoft\windows defender`,
	"wmiprvse.exe":                 `\windows\system32\wbem`,
	"unsecapp.exe":                 `\windows\system32\wbem`,
	"wbemcaching.exe":              `\windows\system32\wbem`,
	"wsmprovhost.exe":              `\windows\system32`,
	"msiexec.exe":                  `\windows\system32`,
	"tiworker.exe":                 `\windows\winsxs`,
	"trustedinstaller.exe":         `\windows\servicing`,
	"usoclient.exe":                `\windows\system32`,
	"musnotification.exe":          `\windows\system32`,
	"musnotifyicon.exe":            `\windows\system32`,
	"logonui.exe":                  `\windows\system32`,
	"userinit.exe":                 `\windows\system32`,
	"cmd.exe":                      `\windows\system32`,
	"powershell.exe":               `\windows\system32\windowspowershell`,
	"pwsh.exe":                     `\program files\powershell`,
	"wermgr.exe":                   `\windows\system32`,
	"wermsgsv.exe":                 `\windows\system32`,
	"werfault.exe":                 `\windows\system32`,
	"backgroundtaskhost.exe":       `\windows\system32`,
	"runtimebroker.exe1":           `\windows\system32`, // duplicate guard
	"searchapp.exe":                `\windows\systemapps`,
	"searchhost.exe":               `\windows\systemapps`,
	"widgetservice.exe":            `\program files\windowsapps`,
	"widgets.exe":                  `\program files\windowsapps`,
	"gamebar.exe":                  `\program files\windowsapps`,
	"gamebarftserver.exe":          `\program files\windowsapps`,
	"video.ui.exe":                 `\program files\windowsapps`,
	"yourphone.exe":                `\program files\windowsapps`,
	"phoneexperiencehost.exe":      `\program files\windowsapps`,
	"windowsterminal.exe":          `\program files\windowsapps`,
	"openwith.exe":                 `\windows\system32`,
	"snippingtool.exe":             `\program files\windowsapps`,
	"systemsettingsbroker.exe":     `\windows\system32`,
	"rdpclip.exe":                  `\windows\system32`,
	"credentialenrollmentmanager.exe": `\windows\system32`,
}

// ---------------------------------------------------------------------------
// Browser processes — exempted from high-resource-usage flagging.
// ---------------------------------------------------------------------------

var browserProcesses = map[string]bool{
	"chrome.exe":          true,
	"msedge.exe":          true,
	"firefox.exe":         true,
	"brave.exe":           true,
	"opera.exe":           true,
	"vivaldi.exe":         true,
	"iexplore.exe":        true,
	"safari.exe":          true,
	"chromium.exe":        true,
	"waterfox.exe":        true,
	"seamonkey.exe":       true,
	"tor.exe":             true,
	"librewolf.exe":       true,
	"floorp.exe":          true,
	"arc.exe":             true,
	// Helper / renderer processes
	"chrome_proxy.exe":    true,
	"msedgewebview2.exe":  true,
	"firefox.exe1":        true, // placeholder guard
}

// ---------------------------------------------------------------------------
// Known Microsoft scheduled tasks — prefix-matched, case-insensitive.
// If a task name starts with any of these prefixes it's considered known.
// ---------------------------------------------------------------------------

var knownMicrosoftTaskPrefixes = []string{
	`\Microsoft\Windows\Application Experience`,
	`\Microsoft\Windows\ApplicationData`,
	`\Microsoft\Windows\AppID`,
	`\Microsoft\Windows\Appx`,
	`\Microsoft\Windows\Autochk`,
	`\Microsoft\Windows\BitLocker`,
	`\Microsoft\Windows\Bluetooth`,
	`\Microsoft\Windows\BrokerInfrastructure`,
	`\Microsoft\Windows\CertificateServicesClient`,
	`\Microsoft\Windows\Chkdsk`,
	`\Microsoft\Windows\Clip`,
	`\Microsoft\Windows\CloudExperienceHost`,
	`\Microsoft\Windows\Customer Experience Improvement Program`,
	`\Microsoft\Windows\Data Integrity Scan`,
	`\Microsoft\Windows\Defrag`,
	`\Microsoft\Windows\Device Information`,
	`\Microsoft\Windows\Device Setup`,
	`\Microsoft\Windows\DeviceDirectoryClient`,
	`\Microsoft\Windows\Diagnosis`,
	`\Microsoft\Windows\DirectX`,
	`\Microsoft\Windows\DiskCleanup`,
	`\Microsoft\Windows\DiskDiagnostic`,
	`\Microsoft\Windows\DiskFootprint`,
	`\Microsoft\Windows\DUSM`,
	`\Microsoft\Windows\EDP`,
	`\Microsoft\Windows\ExploitGuard`,
	`\Microsoft\Windows\Feedback`,
	`\Microsoft\Windows\File Classification Infrastructure`,
	`\Microsoft\Windows\FileHistory`,
	`\Microsoft\Windows\Flighting`,
	`\Microsoft\Windows\LanguageComponentsInstaller`,
	`\Microsoft\Windows\License Manager`,
	`\Microsoft\Windows\Location`,
	`\Microsoft\Windows\Maintenance`,
	`\Microsoft\Windows\Management`,
	`\Microsoft\Windows\Maps`,
	`\Microsoft\Windows\MemoryDiagnostic`,
	`\Microsoft\Windows\Mobile Broadband Accounts`,
	`\Microsoft\Windows\MUI`,
	`\Microsoft\Windows\Multimedia`,
	`\Microsoft\Windows\NetTrace`,
	`\Microsoft\Windows\NlaSvc`,
	`\Microsoft\Windows\Offline Files`,
	`\Microsoft\Windows\PI`,
	`\Microsoft\Windows\Plug and Play`,
	`\Microsoft\Windows\Power Efficiency Diagnostics`,
	`\Microsoft\Windows\PushToInstall`,
	`\Microsoft\Windows\Ras`,
	`\Microsoft\Windows\RecoveryEnvironment`,
	`\Microsoft\Windows\Registry`,
	`\Microsoft\Windows\RemoteAssistance`,
	`\Microsoft\Windows\RetailDemo`,
	`\Microsoft\Windows\Servicing`,
	`\Microsoft\Windows\Setup`,
	`\Microsoft\Windows\SharedPC`,
	`\Microsoft\Windows\Shell`,
	`\Microsoft\Windows\SoftwareProtectionPlatform`,
	`\Microsoft\Windows\SpacePort`,
	`\Microsoft\Windows\Speech`,
	`\Microsoft\Windows\StateRepository`,
	`\Microsoft\Windows\Storage Tiers Management`,
	`\Microsoft\Windows\Subscription`,
	`\Microsoft\Windows\Sysmain`,
	`\Microsoft\Windows\SystemRestore`,
	`\Microsoft\Windows\Task Manager`,
	`\Microsoft\Windows\TaskScheduler`,
	`\Microsoft\Windows\Tcpip`,
	`\Microsoft\Windows\TextServicesFramework`,
	`\Microsoft\Windows\Time Synchronization`,
	`\Microsoft\Windows\Time Zone`,
	`\Microsoft\Windows\TPM`,
	`\Microsoft\Windows\UNP`,
	`\Microsoft\Windows\UpdateAssistant`,
	`\Microsoft\Windows\UpdateOrchestrator`,
	`\Microsoft\Windows\UPnP`,
	`\Microsoft\Windows\USB`,
	`\Microsoft\Windows\User Profile Service`,
	`\Microsoft\Windows\WCM`,
	`\Microsoft\Windows\WDI`,
	`\Microsoft\Windows\Windows Defender`,
	`\Microsoft\Windows\Windows Error Reporting`,
	`\Microsoft\Windows\Windows Filtering Platform`,
	`\Microsoft\Windows\Windows Media Sharing`,
	`\Microsoft\Windows\WindowsColorSystem`,
	`\Microsoft\Windows\WindowsUpdate`,
	`\Microsoft\Windows\Wininet`,
	`\Microsoft\Windows\WlanSvc`,
	`\Microsoft\Windows\WOF`,
	`\Microsoft\Windows\Work Folders`,
	`\Microsoft\Windows\Workplace Join`,
	`\Microsoft\Windows\WS`,
	`\Microsoft\Windows\WwanSvc`,
	`\Microsoft\XblGameSave`,
	`\Microsoft\Office`,
	`\Microsoft\Windows\Input`,
	`\Microsoft\Windows\InstallService`,
	`\Microsoft\Windows\International`,
	`\Microsoft\Windows\IME`,
	`\Microsoft\Windows\HelloFace`,
	`\Microsoft\Windows\Management\Provisioning`,
}

// ---------------------------------------------------------------------------
// Trusted installation paths — if an executable resides under one of these
// path prefixes it is considered "expected".
// ---------------------------------------------------------------------------

var trustedPathPrefixes = []string{
	`c:\program files\`,
	`c:\program files (x86)\`,
	`c:\windows\`,
	`c:\programdata\microsoft\`,
}

// userSpaceTrustedPaths — legitimate user-space installation directories.
// Software installed here (Discord, VSCode, Electron apps) should NOT be
// flagged as suspicious findings, but may appear in the unsigned inventory.
var userSpaceTrustedPaths = []string{
	`\appdata\local\programs\`,
	`\appdata\local\microsoft\`,
}

// IsInUserSpaceTrustedPath returns true if the file is installed in a
// known user-space application directory (e.g. AppData\Local\Programs).
func IsInUserSpaceTrustedPath(filePath string) bool {
	lower := strings.ToLower(filePath)
	for _, p := range userSpaceTrustedPaths {
		if strings.Contains(lower, p) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// File extensions considered suspicious when found in temp directories.
// ---------------------------------------------------------------------------

var suspiciousTempExtensions = map[string]bool{
	".exe": true, ".dll": true, ".scr": true, ".bat": true,
	".cmd": true, ".ps1": true, ".vbs": true, ".vbe": true,
	".wsf": true, ".wsh": true,
	".hta": true, ".lnk": true, ".pif": true, ".msi": true,
	".msp": true, ".com": true, ".cpl": true, ".inf": true,
	".reg": true, ".rgs": true, ".sct": true, ".7z":  true,
	".zip": true, ".rar": true, ".cab": true,
}

// ---------------------------------------------------------------------------
// System process names commonly typosquatted by malware.
// The key is the legitimate name; if we see something that is "close" but
// not exactly this, we flag it.
// ---------------------------------------------------------------------------

var typosquatTargets = []string{
	"svchost.exe",
	"csrss.exe",
	"lsass.exe",
	"services.exe",
	"winlogon.exe",
	"explorer.exe",
	"smss.exe",
	"conhost.exe",
	"dwm.exe",
	"dllhost.exe",
	"taskhostw.exe",
	"runtimebroker.exe",
	"spoolsv.exe",
	"wininit.exe",
}

// ---------------------------------------------------------------------------
// Helper functions
// ---------------------------------------------------------------------------

// IsWhitelistedProcess checks if the process name running from the given path
// is a known-good Windows system process in its expected location.
func IsWhitelistedProcess(exeName, fullPath string) bool {
	lower := strings.ToLower(exeName)
	expectedSuffix, ok := trustedSystemProcesses[lower]
	if !ok {
		return false
	}
	dir := strings.ToLower(filepath.Dir(fullPath))
	return strings.HasSuffix(dir, expectedSuffix)
}

// IsBrowserProcess returns true if the process is a known web browser or
// browser helper (exempted from high-resource flags).
func IsBrowserProcess(exeName string) bool {
	return browserProcesses[strings.ToLower(exeName)]
}

// IsKnownMicrosoftTask returns true if the scheduled task path matches a
// known Microsoft task prefix.
func IsKnownMicrosoftTask(taskPath string) bool {
	lower := strings.ToLower(taskPath)
	for _, prefix := range knownMicrosoftTaskPrefixes {
		if strings.HasPrefix(lower, strings.ToLower(prefix)) {
			return true
		}
	}
	return false
}

// IsInTrustedPath returns true if the file path starts with one of the
// standard trusted installation directories.
func IsInTrustedPath(filePath string) bool {
	lower := strings.ToLower(filePath)
	for _, p := range trustedPathPrefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}
	return false
}

// IsSuspiciousTempExtension returns true if the file extension is one that
// shouldn't normally be sitting in a temp folder.
func IsSuspiciousTempExtension(ext string) bool {
	return suspiciousTempExtensions[strings.ToLower(ext)]
}

// LevenshteinDistance computes the edit distance between two strings (used
// for typosquatting detection).
func LevenshteinDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	matrix := make([][]int, la+1)
	for i := range matrix {
		matrix[i] = make([]int, lb+1)
		matrix[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		matrix[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min3(matrix[i-1][j]+1, matrix[i][j-1]+1, matrix[i-1][j-1]+cost)
		}
	}
	return matrix[la][lb]
}

func min3(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}

// CheckTyposquatting returns the legitimate process name if the given name
// appears to be a typosquatted variant (edit distance 1–2, but not an exact
// match and not in the whitelist).
func CheckTyposquatting(exeName string) string {
	lower := strings.ToLower(exeName)
	for _, legit := range typosquatTargets {
		if lower == legit {
			return "" // exact match — not a typosquat
		}
		dist := LevenshteinDistance(lower, legit)
		if dist > 0 && dist <= 2 {
			return legit
		}
	}
	return ""
}
