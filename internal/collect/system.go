package collect

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// SystemInfo is the "what machine is this" part of the overview.
type SystemInfo struct {
	Hostname     string    `json:"hostname"`
	Domain       string    `json:"domain"`
	DomainJoined bool      `json:"domain_joined"`
	OS           string    `json:"os"`
	Version      string    `json:"version"`
	Build        string    `json:"build"`
	Arch         string    `json:"arch"`
	InstallDate  time.Time `json:"install_date"`
	BootTime     time.Time `json:"boot_time"`
	TimeZone     string    `json:"time_zone"`
	Manufacturer string    `json:"manufacturer"`
	Model        string    `json:"model"`
	VM           bool      `json:"vm"`
	VMHints      []string  `json:"vm_hints,omitempty"`
	CurrentUser  string    `json:"current_user"`

	Interfaces []NetInterface `json:"interfaces"`
}

// NetInterface is an active network adapter and its addresses.
type NetInterface struct {
	Name string   `json:"name"`
	MAC  string   `json:"mac,omitempty"`
	IPs  []string `json:"ips"`
}

func collectSystem(s *Snapshot) string {
	info := &s.System
	info.Hostname, _ = os.Hostname()
	if u, err := user.Current(); err == nil {
		info.CurrentUser = u.Username
	} else {
		info.CurrentUser = os.Getenv("USERNAME")
	}
	info.Domain, info.DomainJoined = joinInformation()
	info.OS, info.Version, info.Build, info.InstallDate = windowsVersion()

	info.Arch = os.Getenv("PROCESSOR_ARCHITEW6432")
	if info.Arch == "" {
		info.Arch = os.Getenv("PROCESSOR_ARCHITECTURE")
	}
	switch strings.ToUpper(info.Arch) {
	case "AMD64":
		info.Arch = "x64"
	case "X86":
		info.Arch = "x86"
	case "ARM64":
		info.Arch = "ARM64"
	}

	info.BootTime = time.Now().Add(-windows.DurationSinceBoot()).Truncate(time.Second)
	zone, offset := time.Now().Zone()
	info.TimeZone = fmt.Sprintf("UTC%+d", offset/3600)
	if zone != "" && zone[0] != '+' && zone[0] != '-' {
		info.TimeZone = fmt.Sprintf("%s (UTC%+d)", zone, offset/3600)
	}

	info.Manufacturer = regString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemManufacturer")
	info.Model = regString(registry.LOCAL_MACHINE, `HARDWARE\DESCRIPTION\System\BIOS`, "SystemProductName")
	info.VMHints = detectVM(info.Manufacturer, info.Model)
	info.VM = len(info.VMHints) > 0
	info.Interfaces = activeInterfaces()

	return fmt.Sprintf("%s, %s build %s", info.Hostname, info.OS, info.Build)
}

func joinInformation() (name string, joined bool) {
	var namePtr *uint16
	var status uint32
	if err := windows.NetGetJoinInformation(nil, &namePtr, &status); err == nil && namePtr != nil {
		name = windows.UTF16PtrToString(namePtr)
		windows.NetApiBufferFree((*byte)(unsafe.Pointer(namePtr)))
		return name, status == windows.NetSetupDomainName
	}
	return os.Getenv("USERDOMAIN"), false
}

func windowsVersion() (product, display, build string, installed time.Time) {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return "Windows", "", "", time.Time{}
	}
	defer k.Close()

	product, _, _ = k.GetStringValue("ProductName")
	display, _, _ = k.GetStringValue("DisplayVersion")
	build, _, _ = k.GetStringValue("CurrentBuildNumber")

	// Windows 11 still reports "Windows 10" in ProductName; the build number
	// is the reliable discriminator.
	if n, err := strconv.Atoi(build); err == nil && n >= 22000 {
		product = strings.Replace(product, "Windows 10", "Windows 11", 1)
	}
	if ubr, _, err := k.GetIntegerValue("UBR"); err == nil {
		build = fmt.Sprintf("%s.%d", build, ubr)
	}
	if secs, _, err := k.GetIntegerValue("InstallDate"); err == nil && secs > 0 {
		installed = time.Unix(int64(secs), 0)
	}
	return product, display, build, installed
}

func detectVM(manufacturer, model string) []string {
	var hints []string
	hw := strings.ToLower(manufacturer + " " + model)
	for _, marker := range []string{"vmware", "virtualbox", "innotek", "qemu", "xen", "kvm", "parallels", "bochs", "virtual machine"} {
		if strings.Contains(hw, marker) {
			hints = append(hints, fmt.Sprintf("hardware reports %q", strings.TrimSpace(manufacturer+" "+model)))
			break
		}
	}
	drivers := filepath.Join(winsys.SystemRoot(), `System32\drivers`)
	for file, product := range map[string]string{
		"VBoxGuest.sys": "VirtualBox guest additions",
		"vmhgfs.sys":    "VMware tools",
		"vm3dmp.sys":    "VMware tools",
		"vioscsi.sys":   "VirtIO (KVM/QEMU) drivers",
		"prl_fs.sys":    "Parallels tools",
	} {
		if winsys.FileExists(filepath.Join(drivers, file)) {
			hints = append(hints, product+" installed")
		}
	}
	return hints
}

func activeInterfaces() []NetInterface {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil
	}
	var out []NetInterface
	for _, ifc := range ifaces {
		if ifc.Flags&net.FlagUp == 0 || ifc.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, _ := ifc.Addrs()
		var ips []string
		for _, a := range addrs {
			ipnet, ok := a.(*net.IPNet)
			if !ok || ipnet.IP.IsLinkLocalUnicast() {
				continue
			}
			ips = append(ips, ipnet.IP.String())
		}
		if len(ips) == 0 {
			continue
		}
		out = append(out, NetInterface{Name: ifc.Name, MAC: ifc.HardwareAddr.String(), IPs: ips})
	}
	return out
}

// ---------------------------------------------------------------------------
// Small registry helpers shared by the collectors
// ---------------------------------------------------------------------------

func regString(root registry.Key, path, name string) string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue(name)
	if err != nil {
		return ""
	}
	return v
}

// regDWORD returns the value and whether it exists.
func regDWORD(root registry.Key, path, name string) (uint64, bool) {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return 0, false
	}
	defer k.Close()
	v, _, err := k.GetIntegerValue(name)
	if err != nil {
		return 0, false
	}
	return v, true
}

func regMultiString(root registry.Key, path, name string) []string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	v, _, err := k.GetStringsValue(name)
	if err != nil {
		return nil
	}
	return v
}

func regValueNames(root registry.Key, path string) []string {
	k, err := registry.OpenKey(root, path, registry.QUERY_VALUE)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadValueNames(-1)
	return names
}

func regSubKeys(root registry.Key, path string) []string {
	k, err := registry.OpenKey(root, path, registry.ENUMERATE_SUB_KEYS)
	if err != nil {
		return nil
	}
	defer k.Close()
	names, _ := k.ReadSubKeyNames(-1)
	return names
}
