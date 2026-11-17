package collect

import (
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// Connection is one row of the socket table: what "netstat -ano" prints,
// plus the owning program resolved to a name, a full path and a signer.
type Connection struct {
	Proto      string `json:"proto"` // TCP, TCP6, UDP, UDP6
	LocalIP    string `json:"local_ip"`
	LocalPort  uint16 `json:"local_port"`
	RemoteIP   string `json:"remote_ip,omitempty"`
	RemotePort uint16 `json:"remote_port,omitempty"`
	State      string `json:"state,omitempty"`
	PID        uint32 `json:"pid"`

	ProcessName string           `json:"process_name"`
	ProcessPath string           `json:"process_path,omitempty"`
	Services    []string         `json:"services,omitempty"`
	Sig         winsys.Signature `json:"signature"`

	// Scope tells where the peer is: "listen" (no peer), "loopback",
	// "private" (LAN) or "public" (internet).
	Scope      string `json:"scope"`
	RemoteHost string `json:"remote_host,omitempty"` // from the local DNS cache, never looked up live
}

// Local returns the local endpoint in netstat notation.
func (c Connection) Local() string { return endpoint(c.LocalIP, c.LocalPort) }

// Remote returns the remote endpoint in netstat notation.
func (c Connection) Remote() string {
	if c.RemoteIP == "" {
		return "*:*"
	}
	return endpoint(c.RemoteIP, c.RemotePort)
}

func endpoint(ip string, port uint16) string {
	return net.JoinHostPort(ip, fmt.Sprint(port))
}

var (
	modIphlpapi             = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetExtendedTCPTable = modIphlpapi.NewProc("GetExtendedTcpTable")
	procGetExtendedUDPTable = modIphlpapi.NewProc("GetExtendedUdpTable")
)

const (
	afInet               = 2
	afInet6              = 23
	tcpTableOwnerPIDAll  = 5
	udpTableOwnerPID     = 1
	errInsufficientBuf   = 122
	tcpStateListen       = 2
	scopeListen          = "listen"
	scopeLoopback        = "loopback"
	scopePrivate         = "private"
	scopePublic          = "public"
)

var tcpStates = map[uint32]string{
	1: "CLOSED", 2: "LISTENING", 3: "SYN_SENT", 4: "SYN_RCVD", 5: "ESTABLISHED", 6: "FIN_WAIT1",
	7: "FIN_WAIT2", 8: "CLOSE_WAIT", 9: "CLOSING", 10: "LAST_ACK", 11: "TIME_WAIT", 12: "DELETE_TCB",
}

// Row layouts from iprtrmib.h / tcpmib.h / udpmib.h.
type tcp4Row struct {
	State, LocalAddr, LocalPort, RemoteAddr, RemotePort, PID uint32
}

type tcp6Row struct {
	LocalAddr     [16]byte
	LocalScopeID  uint32
	LocalPort     uint32
	RemoteAddr    [16]byte
	RemoteScopeID uint32
	RemotePort    uint32
	State         uint32
	PID           uint32
}

type udp4Row struct {
	LocalAddr, LocalPort, PID uint32
}

type udp6Row struct {
	LocalAddr    [16]byte
	LocalScopeID uint32
	LocalPort    uint32
	PID          uint32
}

// socketTable fetches one of the extended TCP/UDP tables, growing the buffer
// until the kernel is satisfied (the table can grow between calls).
func socketTable(proc *windows.LazyProc, family, class uintptr) []byte {
	size := uint32(64 * 1024)
	for attempt := 0; attempt < 6; attempt++ {
		buf := make([]byte, size)
		r, _, _ := proc.Call(uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&size)), 0, family, class, 0)
		if r == 0 {
			return buf
		}
		if r != errInsufficientBuf {
			return nil
		}
		size += 16 * 1024
	}
	return nil
}

// port converts the network-order port stored in the low word of a DWORD.
func port(v uint32) uint16 { return uint16(v&0xFF)<<8 | uint16(v>>8&0xFF) }

func ip4(v uint32) string {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return net.IP(b[:]).String()
}

func collectNetwork(s *Snapshot) string {
	var conns []Connection

	if buf := socketTable(procGetExtendedTCPTable, afInet, tcpTableOwnerPIDAll); len(buf) >= 4 {
		n := binary.LittleEndian.Uint32(buf)
		if max := uint32((len(buf) - 4) / int(unsafe.Sizeof(tcp4Row{}))); n > max {
			n = max
		}
		for _, r := range unsafe.Slice((*tcp4Row)(unsafe.Pointer(&buf[4])), n) {
			c := Connection{Proto: "TCP", LocalIP: ip4(r.LocalAddr), LocalPort: port(r.LocalPort), State: tcpStates[r.State], PID: r.PID}
			if r.State != tcpStateListen {
				c.RemoteIP, c.RemotePort = ip4(r.RemoteAddr), port(r.RemotePort)
			}
			conns = append(conns, c)
		}
	} else {
		s.note("IPv4 TCP table unavailable")
	}

	if buf := socketTable(procGetExtendedTCPTable, afInet6, tcpTableOwnerPIDAll); len(buf) >= 4 {
		n := binary.LittleEndian.Uint32(buf)
		if max := uint32((len(buf) - 4) / int(unsafe.Sizeof(tcp6Row{}))); n > max {
			n = max
		}
		for _, r := range unsafe.Slice((*tcp6Row)(unsafe.Pointer(&buf[4])), n) {
			c := Connection{Proto: "TCP6", LocalIP: net.IP(r.LocalAddr[:]).String(), LocalPort: port(r.LocalPort), State: tcpStates[r.State], PID: r.PID}
			if r.State != tcpStateListen {
				c.RemoteIP, c.RemotePort = net.IP(r.RemoteAddr[:]).String(), port(r.RemotePort)
			}
			conns = append(conns, c)
		}
	}

	if buf := socketTable(procGetExtendedUDPTable, afInet, udpTableOwnerPID); len(buf) >= 4 {
		n := binary.LittleEndian.Uint32(buf)
		if max := uint32((len(buf) - 4) / int(unsafe.Sizeof(udp4Row{}))); n > max {
			n = max
		}
		for _, r := range unsafe.Slice((*udp4Row)(unsafe.Pointer(&buf[4])), n) {
			conns = append(conns, Connection{Proto: "UDP", LocalIP: ip4(r.LocalAddr), LocalPort: port(r.LocalPort), PID: r.PID})
		}
	}

	if buf := socketTable(procGetExtendedUDPTable, afInet6, udpTableOwnerPID); len(buf) >= 4 {
		n := binary.LittleEndian.Uint32(buf)
		if max := uint32((len(buf) - 4) / int(unsafe.Sizeof(udp6Row{}))); n > max {
			n = max
		}
		for _, r := range unsafe.Slice((*udp6Row)(unsafe.Pointer(&buf[4])), n) {
			conns = append(conns, Connection{Proto: "UDP6", LocalIP: net.IP(r.LocalAddr[:]).String(), LocalPort: port(r.LocalPort), PID: r.PID})
		}
	}

	// Resolve owners and peers.
	byPID := make(map[uint32]*Process, len(s.Processes))
	for i := range s.Processes {
		byPID[s.Processes[i].PID] = &s.Processes[i]
	}
	hostByIP := make(map[string]string)
	for _, rec := range s.DNS {
		for _, ip := range rec.IPs {
			if _, dup := hostByIP[ip]; !dup {
				hostByIP[ip] = rec.Name
			}
		}
	}

	remote := 0
	for i := range conns {
		c := &conns[i]
		switch p, ok := byPID[c.PID]; {
		case ok:
			c.ProcessName, c.ProcessPath, c.Services, c.Sig = p.Name, p.Path, p.Services, p.Sig
		case c.PID == 0:
			c.ProcessName = "System Idle Process"
		default:
			c.ProcessName = "(exited)"
		}
		c.Scope = PeerScope(c.RemoteIP)
		if c.Scope == scopePublic {
			c.RemoteHost = hostByIP[c.RemoteIP]
			remote++
		}
	}

	sort.SliceStable(conns, func(i, j int) bool {
		if conns[i].PID != conns[j].PID {
			return conns[i].PID < conns[j].PID
		}
		return conns[i].Proto < conns[j].Proto
	})
	s.Connections = conns
	return fmt.Sprintf("%d sockets, %d to public addresses", len(conns), remote)
}

// PeerScope classifies a remote address. An empty or unspecified address
// means the socket has no peer (it is listening or is an unconnected UDP
// socket).
func PeerScope(ip string) string {
	if ip == "" {
		return scopeListen
	}
	parsed := net.ParseIP(ip)
	switch {
	case parsed == nil, parsed.IsUnspecified():
		return scopeListen
	case parsed.IsLoopback():
		return scopeLoopback
	case parsed.IsPrivate(), parsed.IsLinkLocalUnicast(), parsed.IsLinkLocalMulticast(), parsed.IsMulticast():
		return scopePrivate
	}
	// Carrier-grade NAT (100.64.0.0/10) is not routable on the internet either.
	if v4 := parsed.To4(); v4 != nil && v4[0] == 100 && v4[1]&0xC0 == 64 {
		return scopePrivate
	}
	return scopePublic
}
