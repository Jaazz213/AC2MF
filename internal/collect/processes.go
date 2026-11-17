package collect

import (
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// Process is one running process and everything we could learn about it.
type Process struct {
	PID         uint32    `json:"pid"`
	PPID        uint32    `json:"ppid"`
	Name        string    `json:"name"`
	Path        string    `json:"path,omitempty"`
	CommandLine string    `json:"command_line,omitempty"`
	User        string    `json:"user,omitempty"`
	Session     uint32    `json:"session"`
	Started     time.Time `json:"started"`
	MemoryMB    uint64    `json:"memory_mb"`

	// ParentName/ParentPath are only filled when the parent is verifiably
	// the process that started this one (PIDs get reused, so a parent that
	// started *after* its child is an impostor and is ignored).
	ParentName string `json:"parent_name,omitempty"`
	ParentPath string `json:"parent_path,omitempty"`

	Services []string `json:"services,omitempty"` // services hosted by this process

	Sig         winsys.Signature `json:"signature"`
	Loc         winsys.Location  `json:"location"`
	Inspectable bool             `json:"inspectable"`             // false when access was denied
	ImageGone   bool             `json:"image_missing,omitempty"` // file deleted while still running
	Self        bool             `json:"self,omitempty"`          // AC2MF itself
}

var (
	modPsapi                 = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = modPsapi.NewProc("GetProcessMemoryInfo")
)

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

// SYSTEM_PROCESS_ID_INFORMATION, used to learn the image path of processes
// that cannot be opened (protected processes, other users when not elevated).
type systemProcessIDInformation struct {
	ProcessID uintptr
	ImageName windows.NTUnicodeString
}

func collectProcesses(s *Snapshot) string {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		s.note("process snapshot failed (%v)", err)
		return "unavailable"
	}
	defer windows.CloseHandle(snap)

	self := uint32(os.Getpid())
	hosted := servicesByPID(s.Services)

	var entry windows.ProcessEntry32
	entry.Size = uint32(unsafe.Sizeof(entry))
	for err = windows.Process32First(snap, &entry); err == nil; err = windows.Process32Next(snap, &entry) {
		if entry.ProcessID == 0 {
			continue // System Idle Process
		}
		p := Process{
			PID:      entry.ProcessID,
			PPID:     entry.ParentProcessID,
			Name:     windows.UTF16ToString(entry.ExeFile[:]),
			Self:     entry.ProcessID == self,
			Services: hosted[entry.ProcessID],
		}
		inspect(&p)
		s.Processes = append(s.Processes, p)
	}

	// Signatures in parallel, then per-process derived facts.
	paths := make([]string, 0, len(s.Processes))
	for _, p := range s.Processes {
		paths = append(paths, p.Path)
	}
	winsys.VerifyMany(paths, true)

	byPID := make(map[uint32]*Process, len(s.Processes))
	for i := range s.Processes {
		byPID[s.Processes[i].PID] = &s.Processes[i]
	}
	blind := 0
	owners := make(map[string]bool)
	for i := range s.Processes {
		p := &s.Processes[i]
		if p.Path != "" {
			p.Sig = winsys.Verify(p.Path)
			p.Loc = winsys.Classify(p.Path)
			p.ImageGone = winsys.Gone(p.Path)
		} else if !isKernelPseudoProcess(p.Name) {
			blind++
		}
		if parent, ok := byPID[p.PPID]; ok && p.PPID != p.PID {
			if p.Started.IsZero() || parent.Started.IsZero() || !parent.Started.After(p.Started) {
				p.ParentName, p.ParentPath = parent.Name, parent.Path
			}
		}
		if p.User != "" {
			owners[lower(p.User)] = true
		}
	}

	// Mark which accounts currently own processes.
	host := lower(s.System.Hostname)
	for i := range s.Users {
		u := &s.Users[i]
		name := lower(u.Name)
		if owners[name] || owners[host+`\`+name] {
			u.LoggedOn = true
		}
	}

	if blind > 0 {
		s.note("%d processes could not be inspected (path unavailable) - run elevated for full coverage", blind)
		return fmt.Sprintf("%d processes, %d not inspectable", len(s.Processes), blind)
	}
	return fmt.Sprintf("%d processes", len(s.Processes))
}

func isKernelPseudoProcess(name string) bool {
	switch lower(name) {
	case "system", "registry", "memory compression", "secure system", "vmmem", "vmmemwsl", "[system process]":
		return true
	}
	return false
}

func inspect(p *Process) {
	windows.ProcessIdToSessionId(p.PID, &p.Session)

	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, p.PID)
	if err != nil {
		p.Path = imagePathWithoutHandle(p.PID)
		return
	}
	defer windows.CloseHandle(h)
	p.Inspectable = true

	buf := make([]uint16, 1024)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err == nil {
		p.Path = windows.UTF16ToString(buf[:size])
	} else {
		p.Path = imagePathWithoutHandle(p.PID)
	}

	p.CommandLine = commandLine(h)

	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err == nil {
		p.Started = time.Unix(0, created.Nanoseconds())
	}

	var mem processMemoryCounters
	mem.CB = uint32(unsafe.Sizeof(mem))
	if r, _, _ := procGetProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&mem)), uintptr(mem.CB)); r != 0 {
		p.MemoryMB = uint64(mem.WorkingSetSize) / (1024 * 1024)
	}

	var token windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &token); err == nil {
		if tu, err := token.GetTokenUser(); err == nil {
			if account, domain, _, err := tu.User.Sid.LookupAccount(""); err == nil {
				p.User = account
				if domain != "" {
					p.User = domain + `\` + account
				}
			}
		}
		token.Close()
	}
}

// commandLine reads the process command line through
// ProcessCommandLineInformation (Windows 8.1+), which needs nothing more than
// a limited-information handle.
func commandLine(h windows.Handle) string {
	size := uint32(4096)
	for attempt := 0; attempt < 3; attempt++ {
		buf := make([]byte, size)
		var ret uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation,
			unsafe.Pointer(&buf[0]), size, &ret)
		if err == nil {
			us := (*windows.NTUnicodeString)(unsafe.Pointer(&buf[0]))
			return strings.TrimSpace(us.String())
		}
		if ret <= size {
			return ""
		}
		size = ret
	}
	return ""
}

// imagePathWithoutHandle asks the kernel for a process image path by PID
// alone. It works for every process regardless of privileges, which is what
// lets a non-elevated scan still attribute connections to programs.
func imagePathWithoutHandle(pid uint32) string {
	buf := make([]uint16, 1024)
	info := systemProcessIDInformation{ProcessID: uintptr(pid)}
	info.ImageName.Buffer = &buf[0]
	info.ImageName.MaximumLength = uint16(len(buf) * 2)

	err := windows.NtQuerySystemInformation(windows.SystemProcessIdInformation,
		unsafe.Pointer(&info), uint32(unsafe.Sizeof(info)), nil)
	if err != nil || info.ImageName.Length == 0 {
		return ""
	}
	return winsys.DevicePathToDOS(windows.UTF16ToString(buf[:info.ImageName.Length/2]))
}
