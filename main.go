package main

import (
	"fmt"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

const banner = `
%s
                    ░░░░░░░░░░░░░░░░░░░░                    
               ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░               
            ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░            
          ░░░░░░░░░░░▓▓▓▓░░░░░░░░░▓▓▓▓░░░░░░░░░░░          
        ░░░░░░░░░░░▓▓▓▓▓▓▓▓░░░░░▓▓▓▓▓▓▓▓░░░░░░░░░░        
       ░░░░░░░░░░░▓▓▓▓▓▓▓▓▓▓░░░▓▓▓▓▓▓▓▓▓▓░░░░░░░░░░░      
      ░░░░░░░░░░░░▓▓▓▓████▓▓░░░▓▓▓▓████▓▓░░░░░░░░░░░░     
      ░░░░░░░░░░░░▓▓████████░░░▓▓████████░░░░░░░░░░░░░     
     ░░░░░░░░░░░░░░▓████████░░░▓████████▓░░░░░░░░░░░░░░    
     ░░░░░░░░░░░░░░░▓██████▓░░░░▓██████▓░░░░░░░░░░░░░░░    
      ░░░░░░░░░░░░░░░▓▓▓▓▓░░░░░░░▓▓▓▓▓░░░░░░░░░░░░░░░     
      ░░░░░░░░░░░░░░░░░░░░░▓▓▓▓▓░░░░░░░░░░░░░░░░░░░░░     
       ░░░░░░░░░░░░░░░░░░▓▓▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░      
        ░░░░░░░░░░░░░░░░░░▓▓▓▓▓▓▓░░░░░░░░░░░░░░░░░░       
          ░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░░         
          ░░░░░░░▓░░░░░░░░░░░░░░░░░░░░░░░▓░░░░░░░          
           ░░░░░░▓▓▓░░░░░░░░░░░░░░░░░▓▓▓▓░░░░░░           
            ░░░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░            
              ░░░░░░▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓░░░░░░░              
                ░░░░░░░░░▓▓▓▓▓▓▓░░░░░░░░░░                 
                    ░░░░░░░░░░░░░░░░░░░                     
%s
   %s█████╗  ██████╗██████╗ ███╗   ███╗███████╗
  ██╔══██╗██╔════╝╚════██╗████╗ ████║██╔════╝
  ███████║██║      █████╔╝██╔████╔██║█████╗  
  ██╔══██║██║     ██╔═══╝ ██║╚██╔╝██║██╔══╝  
  ██║  ██║╚██████╗███████╗██║ ╚═╝ ██║██║     
  ╚═╝  ╚═╝ ╚═════╝╚══════╝╚═╝     ╚═╝╚═╝%s     

  %sActive C2 Malware Finder%s           %sBy Jazz%s
`

func main() {
	// Enable ANSI on Windows
	enableANSI()

	// Print banner
	fmt.Printf(banner,
		colorRed, colorReset,
		colorCyan, colorReset,
		colorBold+colorWhite, colorReset, colorGray, colorReset,
	)

	// Disclaimer
	fmt.Printf(`
  %s╔══════════════════════════════════════════════════════════════╗
  ║  ⚠  DISCLAIMER                                             ║
  ║                                                              ║
  ║  This tool does NOT replace an antivirus. It provides        ║
  ║  situational awareness by scanning persistence mechanisms,   ║
  ║  processes, network connections, and common malware hiding   ║
  ║  spots to surface what hides between the lines.              ║
  ║                                                              ║
  ║  Fully offline — no internet required.                       ║
  ║  Safe for sandboxes and quarantined machines.                ║
  ╚══════════════════════════════════════════════════════════════╝%s
`, colorYellow, colorReset)

	// Collect system info
	fmt.Printf("\n  %s%s[ PHASE 1 ] System Information%s\n", colorBold, colorCyan, colorReset)
	sysInfo := CollectSystemInfo()
	fmt.Print(FormatSystemInfo(sysInfo))

	// Admin check warning
	if !sysInfo.IsAdmin {
		fmt.Printf(`
  %s╔══════════════════════════════════════════════════════════════╗
  ║  ⚠  NOT RUNNING AS ADMINISTRATOR                           ║
  ║                                                              ║
  ║  Without admin privileges, AC2MF cannot:                     ║
  ║    • Access all process details (some will show limited      ║
  ║      info or be invisible)                                   ║
  ║    • Read HKLM registry persistence keys                     ║
  ║    • Enumerate all Windows services fully                    ║
  ║    • Scan other users' Temp directories                      ║
  ║    • Verify signatures of protected system files             ║
  ║                                                              ║
  ║  For a complete scan, right-click AC2MF.exe → Run as Admin   ║
  ╚══════════════════════════════════════════════════════════════╝%s
`, colorOrange, colorReset)
	}

	startTime := time.Now()

	// ── Phase 2: Process Scan ──
	fmt.Printf("\n  %s%s[ PHASE 2 ] Process Analysis%s\n", colorBold, colorCyan, colorReset)
	processes := ScanProcesses(func(msg string) {
		PrintProgress("PROC", msg)
	})

	// ── Phase 3: Network Connections ──
	fmt.Printf("\n  %s%s[ PHASE 3 ] Network Connection Analysis%s\n", colorBold, colorCyan, colorReset)
	connections := ScanNetworkConnections(func(msg string) {
		PrintProgress("NET", msg)
	})
	netInfo := AnalyzeProcessConnections(processes, connections, func(msg string) {
		PrintProgress("NET", msg)
	})

	// ── Phase 4: Scheduled Tasks ──
	fmt.Printf("\n  %s%s[ PHASE 4 ] Scheduled Tasks%s\n", colorBold, colorCyan, colorReset)
	tasks := ScanScheduledTasks(func(msg string) {
		PrintProgress("TASK", msg)
	})

	// ── Phase 5: Persistence Mechanisms ──
	fmt.Printf("\n  %s%s[ PHASE 5 ] Persistence Mechanisms%s\n", colorBold, colorCyan, colorReset)
	persistence := ScanPersistence(func(msg string) {
		PrintProgress("PERS", msg)
	})

	// ── Phase 6: Services ──
	fmt.Printf("\n  %s%s[ PHASE 6 ] Windows Services%s\n", colorBold, colorCyan, colorReset)
	services := ScanServices(func(msg string) {
		PrintProgress("SVC", msg)
	})

	// ── Phase 7: Temp Files ──
	fmt.Printf("\n  %s%s[ PHASE 7 ] Temp Directory Scan%s\n", colorBold, colorCyan, colorReset)
	tempFiles := ScanTempDirectories(func(msg string) {
		PrintProgress("TEMP", msg)
	})

	// ── Phase 8: Correlation & Scoring ──
	fmt.Printf("\n  %s%s[ PHASE 8 ] Correlation Engine%s\n", colorBold, colorCyan, colorReset)
	results := CorrelateAndBuildFindings(
		processes, tasks, persistence, services, tempFiles, netInfo,
		func(msg string) {
			PrintProgress("CORR", msg)
		},
	)

	scanDuration := time.Since(startTime)

	// ── Unsigned Software Inventory (informational, near sysinfo) ──
	PrintUnsignedInventory(results.UnsignedInventory)

	// ── Results ──
	fmt.Printf("\n\n  %s%s═══════════════════════════════════════════════════════════%s\n",
		colorBold, colorCyan, colorReset)
	fmt.Printf("  %s%s                       FINDINGS                           %s\n",
		colorBold, colorWhite, colorReset)
	fmt.Printf("  %s%s═══════════════════════════════════════════════════════════%s\n",
		colorBold, colorCyan, colorReset)

	if len(results.Findings) == 0 {
		fmt.Printf("\n  %s✅ No significant findings. Your system looks clean!%s\n", colorGreen, colorReset)
		fmt.Printf("  %s(Low-risk items were found but are not worth reporting.)%s\n", colorGray, colorReset)
	} else {
		for _, f := range results.Findings {
			PrintFinding(f)
		}
	}

	// Build stats
	stats := ScanStats{
		ProcessesScanned:   len(processes),
		TasksChecked:       len(tasks),
		PersistenceEntries: len(persistence),
		ServicesAnalyzed:   len(services),
		TempFilesInspected: len(tempFiles),
		ConnectionsChecked: len(connections),
		ScanDuration:       scanDuration,
	}

	for _, f := range results.Findings {
		switch f.Severity {
		case SevCritical:
			stats.CriticalFindings++
		case SevHigh:
			stats.HighFindings++
		case SevMedium:
			stats.MediumFindings++
		}
	}

	// Summary
	PrintSummary(stats)

	// Export prompt
	ExportReport(results, stats, sysInfo)

	fmt.Printf("\n  %sThank you for using AC2MF. Stay safe.%s\n\n", colorGray, colorReset)
}

// enableANSI enables virtual terminal processing on Windows for ANSI codes.
func enableANSI() {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	proc := kernel32.NewProc("SetConsoleMode")
	getMode := kernel32.NewProc("GetConsoleMode")

	stdout := os.Stdout.Fd()
	var mode uint32
	getMode.Call(stdout, uintptr(unsafe.Pointer(&mode)))
	proc.Call(stdout, uintptr(mode|0x0004)) // ENABLE_VIRTUAL_TERMINAL_PROCESSING
}

