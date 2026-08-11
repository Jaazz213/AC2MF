package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// NetConnection represents a single TCP connection with its owning process.
type NetConnection struct {
	LocalAddr  string
	LocalPort  uint16
	RemoteAddr string
	RemotePort uint16
	State      string
	OwnerPID   uint32
}

// ProcessNetworkInfo aggregates network data per process for injection detection.
type ProcessNetworkInfo struct {
	PID              uint32
	ProcessName      string
	RemoteConns      []NetConnection
	TotalRemoteConns int
	UniqueRemoteIPs  map[string]bool
	HasRemoteConns   bool
	Score            int
}

// systemProcessNoRemote lists processes that should NEVER have outbound remote
// TCP connections under normal circumstances.  If they do, it's a strong
// indicator of process injection or hollowing.
var systemProcessNoRemote = map[string]bool{
	"explorer.exe":      true,
	"csrss.exe":         true,
	"smss.exe":          true,
	"wininit.exe":       true,
	"winlogon.exe":      true,
	"lsass.exe":         true,  // except domain controller — but on a workstation this is sus
	"dwm.exe":           true,
	"fontdrvhost.exe":   true,
	"sihost.exe":        true,
	"ctfmon.exe":        true,
	"conhost.exe":       true,
	"dllhost.exe":       true,
	"taskhostw.exe":     true,
	"spoolsv.exe":       true,
	"audiodg.exe":       true,
	"logonui.exe":       true,
	"userinit.exe":      true,
	"backgroundtaskhost.exe": true,
	"runtimebroker.exe": true,
	"cmd.exe":           true,
	"notepad.exe":       true,
	"calc.exe":          true,
	"mspaint.exe":       true,
	"write.exe":         true,
}

// localhost / private IP ranges — we don't flag connections to these.
func isPrivateOrLocal(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return true // can't parse → don't flag
	}
	if parsed.IsLoopback() || parsed.IsLinkLocalUnicast() || parsed.IsLinkLocalMulticast() {
		return true
	}
	// RFC 1918 ranges
	privateRanges := []struct {
		network string
		mask    string
	}{
		{"10.0.0.0", "255.0.0.0"},
		{"172.16.0.0", "255.240.0.0"},
		{"192.168.0.0", "255.255.0.0"},
		{"169.254.0.0", "255.255.0.0"},
	}
	for _, r := range privateRanges {
		_, cidr, _ := net.ParseCIDR(r.network + "/8")
		if cidr == nil {
			n := net.ParseIP(r.network)
			m := net.IPMask(net.ParseIP(r.mask).To4())
			cidr = &net.IPNet{IP: n, Mask: m}
		}
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// TCP states for display
var tcpStateNames = map[uint32]string{
	1:  "CLOSED",
	2:  "LISTEN",
	3:  "SYN_SENT",
	4:  "SYN_RCVD",
	5:  "ESTABLISHED",
	6:  "FIN_WAIT1",
	7:  "FIN_WAIT2",
	8:  "CLOSE_WAIT",
	9:  "CLOSING",
	10: "LAST_ACK",
	11: "TIME_WAIT",
	12: "DELETE_TCB",
}

// MIB_TCPROW_OWNER_PID structure
type tcpRowOwnerPID struct {
	DwState      uint32
	DwLocalAddr  uint32
	DwLocalPort  uint32
	DwRemoteAddr uint32
	DwRemotePort uint32
	DwOwningPid  uint32
}

// ScanNetworkConnections enumerates all TCP connections and maps them to
// owning processes.
func ScanNetworkConnections(progress func(string)) []NetConnection {
	progress("Enumerating TCP connections...")

	iphlpapi := windows.NewLazySystemDLL("iphlpapi.dll")
	getExtendedTcpTable := iphlpapi.NewProc("GetExtendedTcpTable")

	// First call to get buffer size
	var size uint32
	getExtendedTcpTable.Call(
		0,
		uintptr(unsafe.Pointer(&size)),
		1, // bOrder = TRUE
		2, // AF_INET
		5, // TCP_TABLE_OWNER_PID_ALL
		0,
	)

	if size == 0 {
		progress("  Could not determine TCP table size")
		return nil
	}

	buf := make([]byte, size)
	ret, _, _ := getExtendedTcpTable.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(unsafe.Pointer(&size)),
		1,
		2,
		5,
		0,
	)

	if ret != 0 {
		progress(fmt.Sprintf("  GetExtendedTcpTable failed: 0x%x", ret))
		return nil
	}

	// Parse the table
	numEntries := binary.LittleEndian.Uint32(buf[0:4])
	rowSize := unsafe.Sizeof(tcpRowOwnerPID{})
	var conns []NetConnection

	for i := uint32(0); i < numEntries; i++ {
		offset := 4 + uintptr(i)*rowSize
		if offset+rowSize > uintptr(len(buf)) {
			break
		}

		row := (*tcpRowOwnerPID)(unsafe.Pointer(&buf[offset]))

		localIP := uint32ToIP(row.DwLocalAddr)
		remoteIP := uint32ToIP(row.DwRemoteAddr)
		localPort := ntohs(uint16(row.DwLocalPort))
		remotePort := ntohs(uint16(row.DwRemotePort))

		state := tcpStateNames[row.DwState]
		if state == "" {
			state = fmt.Sprintf("UNKNOWN(%d)", row.DwState)
		}

		conns = append(conns, NetConnection{
			LocalAddr:  localIP,
			LocalPort:  localPort,
			RemoteAddr: remoteIP,
			RemotePort: remotePort,
			State:      state,
			OwnerPID:   row.DwOwningPid,
		})
	}

	progress(fmt.Sprintf("  Found %d TCP connections", len(conns)))
	return conns
}

// AnalyzeProcessConnections cross-references network connections with process
// data to detect injection indicators.
func AnalyzeProcessConnections(procs []ProcessInfo, conns []NetConnection, progress func(string)) []ProcessNetworkInfo {
	progress("Cross-referencing connections with processes...")

	// Build PID → process name map
	pidName := make(map[uint32]string)
	for _, p := range procs {
		pidName[p.PID] = p.Name
	}

	// Group remote connections by PID
	pidConns := make(map[uint32][]NetConnection)
	for _, c := range conns {
		// Only care about remote (non-local, non-private for injection detection)
		if c.RemoteAddr == "0.0.0.0" || c.State == "LISTEN" {
			continue
		}
		// Include all established/active connections to remote addresses
		if !isPrivateOrLocal(c.RemoteAddr) {
			pidConns[c.OwnerPID] = append(pidConns[c.OwnerPID], c)
		}
	}

	var results []ProcessNetworkInfo

	for pid, remoteConns := range pidConns {
		name := strings.ToLower(pidName[pid])
		if name == "" {
			name = fmt.Sprintf("PID_%d", pid)
		}

		info := ProcessNetworkInfo{
			PID:              pid,
			ProcessName:      pidName[pid],
			RemoteConns:      remoteConns,
			TotalRemoteConns: len(remoteConns),
			UniqueRemoteIPs:  make(map[string]bool),
			HasRemoteConns:   true,
		}

		for _, c := range remoteConns {
			info.UniqueRemoteIPs[c.RemoteAddr] = true
		}

		// Score: system process with remote connections = very suspicious
		if systemProcessNoRemote[name] {
			info.Score = 70 // High base score for injection indicator
			if len(info.UniqueRemoteIPs) > 3 {
				info.Score = 90 // Multiple remote IPs = even worse
			}
		}

		if info.Score > 0 {
			results = append(results, info)
		}
	}

	if len(results) > 0 {
		progress(fmt.Sprintf("  ⚠ Found %d processes with suspicious remote connections", len(results)))
	} else {
		progress("  No suspicious process network activity detected")
	}

	return results
}

func uint32ToIP(addr uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		addr&0xFF,
		(addr>>8)&0xFF,
		(addr>>16)&0xFF,
		(addr>>24)&0xFF,
	)
}

func ntohs(port uint16) uint16 {
	return (port>>8)&0xFF | (port&0xFF)<<8
}
