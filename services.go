package main

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/svc/mgr"
)

// ServiceInfo holds analysis results for a single Windows service.
type ServiceInfo struct {
	Name        string
	DisplayName string
	State       string
	StartType   string
	BinaryPath  string
	Account     string
	Description string

	// Analysis
	Signature   SignatureStatus
	IsInTemp    bool
	IsInAppData bool
	IsInTrusted bool
	Score       int
}

// ScanServices enumerates all Windows services via the Service Control Manager.
func ScanServices(progress func(string)) []ServiceInfo {
	progress("Connecting to Service Control Manager...")

	m, err := mgr.Connect()
	if err != nil {
		progress(fmt.Sprintf("  Could not connect to SCM: %v", err))
		// Fallback: try manual enumeration
		return scanServicesManual(progress)
	}
	defer m.Disconnect()

	names, err := m.ListServices()
	if err != nil {
		progress(fmt.Sprintf("  Could not list services: %v", err))
		return nil
	}

	progress(fmt.Sprintf("  Found %d services, analyzing...", len(names)))

	var results []ServiceInfo

	for _, name := range names {
		s, err := m.OpenService(name)
		if err != nil {
			continue
		}

		config, err := s.Config()
		if err != nil {
			s.Close()
			continue
		}

		status, err := s.Query()
		s.Close()

		si := ServiceInfo{
			Name:        name,
			DisplayName: config.DisplayName,
			BinaryPath:  config.BinaryPathName,
			Account:     config.ServiceStartName,
			Description: config.Description,
		}

		// Start type
		switch config.StartType {
		case windows.SERVICE_AUTO_START:
			si.StartType = "Automatic"
		case windows.SERVICE_BOOT_START:
			si.StartType = "Boot"
		case windows.SERVICE_DEMAND_START:
			si.StartType = "Manual"
		case windows.SERVICE_DISABLED:
			si.StartType = "Disabled"
		case windows.SERVICE_SYSTEM_START:
			si.StartType = "System"
		default:
			si.StartType = "Unknown"
		}

		// State
		if err == nil {
			switch status.State {
			case windows.SERVICE_RUNNING:
				si.State = "Running"
			case windows.SERVICE_STOPPED:
				si.State = "Stopped"
			case windows.SERVICE_PAUSED:
				si.State = "Paused"
			case windows.SERVICE_START_PENDING:
				si.State = "Starting"
			case windows.SERVICE_STOP_PENDING:
				si.State = "Stopping"
			default:
				si.State = "Unknown"
			}
		}

		// Analyze binary path
		analyzeServicePath(&si)

		results = append(results, si)
	}

	// Count flagged
	flagged := 0
	for _, s := range results {
		if s.Score > 0 {
			flagged++
		}
	}
	progress(fmt.Sprintf("  Analyzed %d services (%d flagged)", len(results), flagged))

	return results
}

func analyzeServicePath(si *ServiceInfo) {
	binPath := si.BinaryPath
	if binPath == "" {
		return
	}

	// Clean the path: remove quotes, arguments
	cleanPath := extractExePath(binPath)
	lowerPath := strings.ToLower(cleanPath)

	si.IsInTrusted = IsInTrustedPath(cleanPath)

	if strings.Contains(lowerPath, `\temp\`) || strings.Contains(lowerPath, `\tmp\`) {
		si.IsInTemp = true
	}
	if strings.Contains(lowerPath, `\appdata\`) {
		si.IsInAppData = true
	}

	// Only verify signature for non-trusted or running services
	if !si.IsInTrusted || si.State == "Running" {
		if strings.HasSuffix(lowerPath, ".exe") || strings.HasSuffix(lowerPath, ".dll") || strings.HasSuffix(lowerPath, ".sys") {
			si.Signature = VerifySignature(cleanPath)
		}
	}
}

// scanServicesManual is a fallback when SCM access fails (non-admin).
// Uses EnumServicesStatusEx directly.
func scanServicesManual(progress func(string)) []ServiceInfo {
	progress("  Attempting manual service enumeration...")

	advapi32 := windows.NewLazySystemDLL("advapi32.dll")
	openSCManager := advapi32.NewProc("OpenSCManagerW")
	enumServicesStatusEx := advapi32.NewProc("EnumServicesStatusExW")
	closeServiceHandle := advapi32.NewProc("CloseServiceHandle")

	scmHandle, _, err := openSCManager.Call(0, 0, 0x0004) // SC_MANAGER_ENUMERATE_SERVICE
	if scmHandle == 0 {
		progress(fmt.Sprintf("  Manual SCM open failed: %v", err))
		return nil
	}
	defer closeServiceHandle.Call(scmHandle)

	// Get required buffer size
	var bytesNeeded, servicesReturned, resumeHandle uint32
	enumServicesStatusEx.Call(
		scmHandle,
		0, // SC_ENUM_PROCESS_INFO
		0x30, // SERVICE_WIN32
		0x03, // SERVICE_STATE_ALL
		0, 0,
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)

	if bytesNeeded == 0 {
		progress("  No services found via manual enumeration")
		return nil
	}

	buf := make([]byte, bytesNeeded)
	ret, _, _ := enumServicesStatusEx.Call(
		scmHandle,
		0,
		0x30,
		0x03,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(bytesNeeded),
		uintptr(unsafe.Pointer(&bytesNeeded)),
		uintptr(unsafe.Pointer(&servicesReturned)),
		uintptr(unsafe.Pointer(&resumeHandle)),
		0,
	)

	if ret == 0 {
		progress("  EnumServicesStatusEx failed")
		return nil
	}

	progress(fmt.Sprintf("  Enumerated %d services (limited detail without admin)", servicesReturned))

	// For the manual path we just return a count for the summary
	return nil
}
