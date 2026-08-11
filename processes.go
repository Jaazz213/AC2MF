package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ProcessInfo holds everything we know about a single running process.
type ProcessInfo struct {
	PID           uint32
	Name          string
	FullPath      string
	ParentPID     uint32
	ParentName    string
	MemoryMB      uint64
	Signature     SignatureStatus
	Username      string

	// Analysis fields set during scoring
	IsInTemp      bool
	IsInAppData   bool
	IsInPrograms  bool // AppData\Local\Programs — legitimate user-space installs
	IsOnDesktop   bool
	Typosquat     string // name of the legitimate process it mimics, if any
	IsWhitelisted bool
	IsBrowser     bool
	Score         int
}

// ScanProcesses enumerates all running processes and collects metadata.
func ScanProcesses(progress func(string)) []ProcessInfo {
	progress("Taking process snapshot...")

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		progress(fmt.Sprintf("  Could not snapshot processes: %v", err))
		return nil
	}
	defer windows.CloseHandle(snap)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))

	// First pass: collect PID→Name map for parent lookup
	pidMap := make(map[uint32]string)
	var entries []windows.ProcessEntry32

	err = windows.Process32First(snap, &entry)
	for err == nil {
		name := windows.UTF16ToString(entry.ExeFile[:])
		pidMap[entry.ProcessID] = name
		entries = append(entries, entry)
		err = windows.Process32Next(snap, &entry)
	}

	progress(fmt.Sprintf("  Found %d processes, analyzing...", len(entries)))

	var results []ProcessInfo

	for _, e := range entries {
		name := windows.UTF16ToString(e.ExeFile[:])

		pi := ProcessInfo{
			PID:        e.ProcessID,
			Name:       name,
			ParentPID:  e.ParentProcessID,
			ParentName: pidMap[e.ParentProcessID],
		}

		// Skip system idle / system
		if pi.PID == 0 || pi.PID == 4 {
			continue
		}

		// Open process for path + memory info
		handle, err := windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ,
			false, pi.PID)
		if err == nil {
			pi.FullPath = getProcessImagePath(handle)
			pi.MemoryMB = getProcessMemory(handle)
			pi.Username = getProcessUser(handle)
			windows.CloseHandle(handle)
		}

		// Analyse location
		lowerPath := strings.ToLower(pi.FullPath)
		if strings.Contains(lowerPath, `\temp\`) || strings.Contains(lowerPath, `\tmp\`) {
			pi.IsInTemp = true
		}
		if strings.Contains(lowerPath, `\appdata\`) {
			pi.IsInAppData = true
		}
		if IsInUserSpaceTrustedPath(pi.FullPath) {
			pi.IsInPrograms = true
		}
		if strings.Contains(lowerPath, `\desktop\`) {
			pi.IsOnDesktop = true
		}

		// Whitelist & browser check
		pi.IsWhitelisted = IsWhitelistedProcess(pi.Name, pi.FullPath)
		pi.IsBrowser = IsBrowserProcess(pi.Name)

		// Signature
		if pi.FullPath != "" && !pi.IsWhitelisted {
			pi.Signature = VerifySignature(pi.FullPath)
		} else if pi.IsWhitelisted {
			pi.Signature = SignedValid // trust the whitelist
		} else {
			pi.Signature = SignatureError
		}

		// Typosquatting
		pi.Typosquat = CheckTyposquatting(pi.Name)

		results = append(results, pi)
	}

	progress(fmt.Sprintf("  Analyzed %d processes", len(results)))
	return results
}

func getProcessImagePath(h windows.Handle) string {
	buf := make([]uint16, windows.MAX_PATH*2)
	size := uint32(len(buf))
	err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size)
	if err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}

func getProcessMemory(h windows.Handle) uint64 {
	type processMemoryCounters struct {
		CB                         uint32
		PageFaultCount             uint32
		PeakWorkingSetSize         uintptr
		WorkingSetSize             uintptr
		QuotaPeakPagedPoolUsage    uintptr
		QuotaPagedPoolUsage        uintptr
		QuotaPeakNonPagedPoolUsage uintptr
		QuotaNonPagedPoolUsage     uintptr
		PagefileUsage              uintptr
		PeakPagefileUsage          uintptr
	}

	psapi := windows.NewLazySystemDLL("psapi.dll")
	proc := psapi.NewProc("GetProcessMemoryInfo")

	var counters processMemoryCounters
	counters.CB = uint32(unsafe.Sizeof(counters))

	ret, _, _ := proc.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&counters)),
		uintptr(counters.CB),
	)
	if ret == 0 {
		return 0
	}
	return uint64(counters.WorkingSetSize) / (1024 * 1024)
}

func getProcessUser(h windows.Handle) string {
	var token windows.Token
	err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token)
	if err != nil {
		return ""
	}
	defer token.Close()

	u, err := token.GetTokenUser()
	if err != nil {
		return ""
	}

	account, domain, _, err := u.User.Sid.LookupAccount("")
	if err != nil {
		return ""
	}
	if domain != "" {
		return domain + `\` + account
	}
	return account
}
