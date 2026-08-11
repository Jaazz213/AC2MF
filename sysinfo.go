package main

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// SystemInfo holds collected situational-awareness data.
type SystemInfo struct {
	Hostname     string
	Domain       string
	CurrentUser  string
	UserAccounts []string
	WindowsVer   string
	Build        string
	Architecture string
	Uptime       time.Duration
	IsAdmin      bool
	VMIndicators []string
	IsVM         bool
}

// CollectSystemInfo gathers machine metadata for the situational-awareness
// box displayed at the start of the report.
func CollectSystemInfo() SystemInfo {
	var info SystemInfo

	info.Hostname, _ = os.Hostname()
	info.CurrentUser = getCurrentUser()
	info.Domain = getDomain()
	info.UserAccounts = enumerateUsers()
	info.WindowsVer, info.Build = getWindowsVersion()
	info.Architecture = runtime.GOARCH
	if info.Architecture == "amd64" {
		info.Architecture = "x64 (64-bit)"
	}
	info.Uptime = getUptime()
	info.IsAdmin = checkAdmin()
	info.VMIndicators, info.IsVM = detectVM()

	return info
}

func getCurrentUser() string {
	u, err := user.Current()
	if err != nil {
		return os.Getenv("USERNAME")
	}
	return u.Username
}

func getDomain() string {
	d := os.Getenv("USERDOMAIN")
	if d == "" {
		d = os.Getenv("COMPUTERNAME")
	}
	return d
}

func enumerateUsers() []string {
	var users []string
	entries, err := os.ReadDir(`C:\Users`)
	if err != nil {
		return users
	}
	skip := map[string]bool{
		"public":       true,
		"default":      true,
		"default user": true,
		"all users":    true,
	}
	for _, e := range entries {
		if e.IsDir() {
			name := e.Name()
			if !skip[strings.ToLower(name)] && !strings.HasPrefix(name, ".") {
				users = append(users, name)
			}
		}
	}
	return users
}

func getWindowsVersion() (string, string) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Unknown", "Unknown"
	}
	defer k.Close()

	productName, _, _ := k.GetStringValue("ProductName")
	displayVersion, _, _ := k.GetStringValue("DisplayVersion")
	buildNum, _, _ := k.GetStringValue("CurrentBuildNumber")
	ubr, _, ubrErr := k.GetIntegerValue("UBR")

	ver := productName
	if displayVersion != "" {
		ver += " (" + displayVersion + ")"
	}
	build := buildNum
	if ubrErr == nil {
		build = fmt.Sprintf("%s.%d", buildNum, ubr)
	}
	return ver, build
}

func getUptime() time.Duration {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("GetTickCount64")
	ret, _, _ := proc.Call()
	ms := *(*uint64)(unsafe.Pointer(&ret))
	return time.Duration(ms) * time.Millisecond
}

func checkAdmin() bool {
	_, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	return true
}

func detectVM() ([]string, bool) {
	var indicators []string

	// Check BIOS/system info in registry
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Services\Disk\Enum`, registry.QUERY_VALUE)
	if err == nil {
		val, _, err := k.GetStringValue("0")
		if err == nil {
			lower := strings.ToLower(val)
			for _, vm := range []string{"vmware", "vbox", "virtual", "qemu", "xen", "hyper-v"} {
				if strings.Contains(lower, vm) {
					indicators = append(indicators, fmt.Sprintf("Disk device contains '%s'", vm))
				}
			}
		}
		k.Close()
	}

	// Check system manufacturer
	k2, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SYSTEM\CurrentControlSet\Control\SystemInformation`, registry.QUERY_VALUE)
	if err == nil {
		mfg, _, err := k2.GetStringValue("SystemManufacturer")
		if err == nil {
			lower := strings.ToLower(mfg)
			for _, vm := range []string{"vmware", "virtualbox", "innotek", "qemu", "xen", "microsoft corporation"} {
				if strings.Contains(lower, vm) {
					indicators = append(indicators, fmt.Sprintf("System manufacturer: %s", mfg))
				}
			}
		}
		product, _, err := k2.GetStringValue("SystemProductName")
		if err == nil {
			lower := strings.ToLower(product)
			if strings.Contains(lower, "virtual") {
				indicators = append(indicators, fmt.Sprintf("Product name: %s", product))
			}
		}
		k2.Close()
	}

	// Check for VM-related files
	vmFiles := []string{
		`C:\Windows\System32\drivers\VBoxGuest.sys`,
		`C:\Windows\System32\drivers\vmhgfs.sys`,
		`C:\Windows\System32\drivers\vm3dmp.sys`,
		`C:\Program Files\VMware\VMware Tools\vmtoolsd.exe`,
		`C:\Program Files\Oracle\VirtualBox Guest Additions\VBoxService.exe`,
	}
	for _, f := range vmFiles {
		if _, err := os.Stat(f); err == nil {
			indicators = append(indicators, fmt.Sprintf("VM file found: %s", filepath.Base(f)))
		}
	}

	return indicators, len(indicators) > 0
}

// FormatSystemInfo returns a formatted box for console display.
func FormatSystemInfo(info SystemInfo) string {
	var sb strings.Builder

	sb.WriteString("\n")
	sb.WriteString("  ╔══════════════════════════════════════════════════════════════╗\n")
	sb.WriteString("  ║               SYSTEM INFORMATION                            ║\n")
	sb.WriteString("  ╠══════════════════════════════════════════════════════════════╣\n")

	addField := func(label, value string) {
		line := fmt.Sprintf("  ║  %-16s %s", label+":", value)
		pad := 64 - len(line)
		if pad < 1 {
			pad = 1
		}
		sb.WriteString(line)
		sb.WriteString(strings.Repeat(" ", pad))
		sb.WriteString("║\n")
	}

	addField("Machine", info.Hostname)
	addField("Domain", info.Domain)
	addField("Current User", info.CurrentUser)
	addField("User Accounts", strings.Join(info.UserAccounts, ", "))
	addField("Windows", info.WindowsVer)
	addField("Build", info.Build)
	addField("Architecture", info.Architecture)

	hours := int(info.Uptime.Hours())
	mins := int(info.Uptime.Minutes()) % 60
	addField("Uptime", fmt.Sprintf("%d hours, %d minutes", hours, mins))

	if info.IsAdmin {
		addField("Admin", "✅ Yes — full scan capability")
	} else {
		addField("Admin", "⚠️  No — limited visibility")
	}

	if info.IsVM {
		addField("VM Detected", "Yes")
		for _, ind := range info.VMIndicators {
			addField("  VM Indicator", ind)
		}
	} else {
		addField("VM Detected", "No signs of virtualization")
	}

	sb.WriteString("  ╚══════════════════════════════════════════════════════════════╝\n")

	return sb.String()
}
