package collect

import (
	"fmt"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// Service is a Windows service or kernel driver.
type Service struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name"`
	Driver      bool   `json:"driver"`
	State       string `json:"state"`
	StartType   string `json:"start_type"`
	PID         uint32 `json:"pid,omitempty"`
	Account     string `json:"account,omitempty"`

	ImagePath  string `json:"image_path"`            // raw registry value
	Binary     string `json:"binary"`                // resolved program
	Args       string `json:"args,omitempty"`
	ServiceDLL string `json:"service_dll,omitempty"` // for svchost-hosted services

	// Target is the code that actually implements the service: the
	// ServiceDll when there is one, the binary otherwise.
	Target string           `json:"target"`
	Sig    winsys.Signature `json:"signature"`
	Loc    winsys.Location  `json:"location"`
	Gone   bool             `json:"target_missing,omitempty"`
}

// Running reports whether the service is currently started.
func (s Service) Running() bool { return s.State == "running" }

// AutoStart reports whether the service starts without user action.
func (s Service) AutoStart() bool {
	return s.StartType == "auto" || s.StartType == "boot" || s.StartType == "system"
}

var serviceStates = map[uint32]string{
	windows.SERVICE_STOPPED:          "stopped",
	windows.SERVICE_START_PENDING:    "starting",
	windows.SERVICE_STOP_PENDING:     "stopping",
	windows.SERVICE_RUNNING:          "running",
	windows.SERVICE_CONTINUE_PENDING: "resuming",
	windows.SERVICE_PAUSE_PENDING:    "pausing",
	windows.SERVICE_PAUSED:           "paused",
}

var startTypes = map[uint64]string{0: "boot", 1: "system", 2: "auto", 3: "manual", 4: "disabled"}

func collectServices(s *Snapshot) string {
	// Enumerating needs only connect + enumerate rights, which every user
	// has; the configuration comes from the registry, which is also world
	// readable. This is why services are visible without elevation.
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT|windows.SC_MANAGER_ENUMERATE_SERVICE)
	if err != nil {
		s.note("service manager could not be opened (%v)", err)
		return "unavailable"
	}
	defer windows.CloseServiceHandle(scm)

	const kinds = windows.SERVICE_WIN32 | windows.SERVICE_DRIVER
	var needed, returned, resume uint32
	buf := make([]byte, 256*1024)
	var paths []string

	for {
		err := windows.EnumServicesStatusEx(scm, windows.SC_ENUM_PROCESS_INFO, kinds, windows.SERVICE_STATE_ALL,
			&buf[0], uint32(len(buf)), &needed, &returned, &resume, nil)
		if err != nil && err != windows.ERROR_MORE_DATA {
			s.note("service enumeration failed (%v)", err)
			break
		}
		for _, e := range unsafe.Slice((*windows.ENUM_SERVICE_STATUS_PROCESS)(unsafe.Pointer(&buf[0])), returned) {
			st := e.ServiceStatusProcess
			svc := Service{
				Name:        windows.UTF16PtrToString(e.ServiceName),
				DisplayName: windows.UTF16PtrToString(e.DisplayName),
				Driver:      st.ServiceType&windows.SERVICE_DRIVER != 0,
				State:       serviceStates[st.CurrentState],
				PID:         st.ProcessId,
			}
			readServiceConfig(&svc)
			if svc.Target != "" {
				paths = append(paths, svc.Target)
			}
			s.Services = append(s.Services, svc)
		}
		if err == nil {
			break
		}
	}

	winsys.VerifyMany(paths, true)
	running, drivers := 0, 0
	for i := range s.Services {
		svc := &s.Services[i]
		if svc.Target != "" {
			svc.Sig = winsys.Verify(svc.Target)
			svc.Loc = winsys.Classify(svc.Target)
			svc.Gone = winsys.Gone(svc.Target)
		}
		if svc.Running() {
			running++
		}
		if svc.Driver {
			drivers++
		}
	}
	return fmt.Sprintf("%d services, %d drivers, %d running", len(s.Services)-drivers, drivers, running)
}

func readServiceConfig(svc *Service) {
	base := `SYSTEM\CurrentControlSet\Services\` + svc.Name
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, base, registry.QUERY_VALUE)
	if err != nil {
		return
	}
	defer k.Close()

	svc.ImagePath, _, _ = k.GetStringValue("ImagePath")
	svc.Account, _, _ = k.GetStringValue("ObjectName")
	if v, _, err := k.GetIntegerValue("Start"); err == nil {
		svc.StartType = startTypes[v]
	}

	if svc.ImagePath == "" {
		if svc.Driver {
			// Drivers without an ImagePath load from the default location.
			svc.Binary = winsys.SystemRoot() + `\System32\drivers\` + svc.Name + ".sys"
		}
	} else {
		svc.Binary, svc.Args = winsys.SplitCommandLine(svc.ImagePath)
	}
	svc.Target = svc.Binary

	// Shared-process services keep their real code in a DLL.
	dll := regString(registry.LOCAL_MACHINE, base+`\Parameters`, "ServiceDll")
	if dll == "" {
		dll = regString(registry.LOCAL_MACHINE, base, "ServiceDll")
	}
	if dll != "" {
		svc.ServiceDLL = winsys.NormalizePath(dll)
		svc.Target = svc.ServiceDLL
	}
}

// servicesByPID maps a process ID to the names of the services it hosts.
func servicesByPID(svcs []Service) map[uint32][]string {
	out := make(map[uint32][]string)
	for _, s := range svcs {
		if s.PID != 0 && !s.Driver {
			out[s.PID] = append(out[s.PID], s.Name)
		}
	}
	return out
}

func lower(s string) string { return strings.ToLower(s) }
