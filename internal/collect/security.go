package collect

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows/registry"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// Tri-state values used across the posture report.
const (
	On      = "on"
	Off     = "off"
	Unknown = "unknown"
)

// SecurityPosture describes the state of the machine's built-in defences.
// Malware routinely weakens these, so a deviation is a finding in itself.
type SecurityPosture struct {
	Antivirus []AVProduct `json:"antivirus"`

	DefenderRealtime       string   `json:"defender_realtime"`
	DefenderTamper         string   `json:"defender_tamper_protection"`
	DefenderPolicyDisabled bool     `json:"defender_disabled_by_policy"`
	DefenderExclusions     []string `json:"defender_exclusions,omitempty"`
	ExclusionsReadable     bool     `json:"defender_exclusions_readable"`

	Firewall map[string]string `json:"firewall"` // profile -> on/off/unknown

	UAC           string `json:"uac"`
	RDP           string `json:"rdp"`
	SecureBoot    string `json:"secure_boot"`
	LSAProtection string `json:"lsa_protection"`
	WDigest       string `json:"wdigest_plaintext_creds"`

	ProxyEnabled bool   `json:"proxy_enabled"`
	ProxyServer  string `json:"proxy_server,omitempty"`
	ProxyPAC     string `json:"proxy_autoconfig_url,omitempty"`

	Hosts []HostsEntry `json:"hosts_entries,omitempty"`
}

// AVProduct is an antivirus registered with Windows Security Center.
type AVProduct struct {
	Name     string `json:"name"`
	Enabled  bool   `json:"enabled"`
	UpToDate bool   `json:"up_to_date"`
	Path     string `json:"path,omitempty"`
}

// HostsEntry is a non-comment line of the hosts file.
type HostsEntry struct {
	IP    string   `json:"ip"`
	Names []string `json:"names"`
}

func triFromBool(v, ok bool) string {
	if !ok {
		return Unknown
	}
	if v {
		return On
	}
	return Off
}

func collectSecurity(s *Snapshot) string {
	p := &s.Security
	const defender = `SOFTWARE\Microsoft\Windows Defender`
	const defenderPolicy = `SOFTWARE\Policies\Microsoft\Windows Defender`

	// --- Antivirus products (Security Center; absent on Server SKUs) ---
	err := wmiQuery(`root\SecurityCenter2`, "SELECT * FROM AntiVirusProduct", func(item *ole.IDispatch) {
		state := comInt(item, "productState")
		p.Antivirus = append(p.Antivirus, AVProduct{
			Name:     comString(item, "displayName"),
			Enabled:  state&0x1000 != 0,
			UpToDate: state&0x10 == 0,
			Path:     comString(item, "pathToSignedProductExe"),
		})
	})
	if err != nil {
		s.note("Security Center could not be queried (%v); antivirus list unavailable", err)
	}

	// --- Microsoft Defender ---
	p.DefenderRealtime = Unknown
	if k, err := registry.OpenKey(registry.LOCAL_MACHINE, defender, registry.QUERY_VALUE); err == nil {
		k.Close()
		p.DefenderRealtime = On
		if v, ok := regDWORD(registry.LOCAL_MACHINE, defender+`\Real-Time Protection`, "DisableRealtimeMonitoring"); ok && v == 1 {
			p.DefenderRealtime = Off
		}
	}
	if v, ok := regDWORD(registry.LOCAL_MACHINE, defenderPolicy+`\Real-Time Protection`, "DisableRealtimeMonitoring"); ok && v == 1 {
		p.DefenderRealtime = Off
		p.DefenderPolicyDisabled = true
	}
	if v, ok := regDWORD(registry.LOCAL_MACHINE, defenderPolicy, "DisableAntiSpyware"); ok && v == 1 {
		p.DefenderPolicyDisabled = true
	}
	p.DefenderTamper = Unknown
	if v, ok := regDWORD(registry.LOCAL_MACHINE, defender+`\Features`, "TamperProtection"); ok {
		p.DefenderTamper = triFromBool(v == 5 || v == 1, true)
	}

	// Exclusions are a favourite hiding place: anything listed there is
	// invisible to Defender. Reading them requires elevation.
	for _, base := range []string{defender, defenderPolicy} {
		for _, kind := range []string{"Paths", "Processes", "Extensions"} {
			path := base + `\Exclusions\` + kind
			k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE)
			if err != nil {
				continue
			}
			p.ExclusionsReadable = true
			names, _ := k.ReadValueNames(-1)
			k.Close()
			for _, n := range names {
				p.DefenderExclusions = append(p.DefenderExclusions, strings.TrimSuffix(kind, "s")+": "+n)
			}
		}
	}

	// --- Firewall ---
	p.Firewall = map[string]string{}
	const fw = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\`
	for label, key := range map[string]string{"Domain": "DomainProfile", "Private": "StandardProfile", "Public": "PublicProfile"} {
		v, ok := regDWORD(registry.LOCAL_MACHINE, fw+key, "EnableFirewall")
		p.Firewall[label] = triFromBool(v != 0, ok)
	}

	// --- Hardening switches ---
	v, ok := regDWORD(registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA")
	p.UAC = triFromBool(v != 0, ok)

	v, ok = regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Terminal Server`, "fDenyTSConnections")
	p.RDP = triFromBool(v == 0, ok)

	v, ok = regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecureBoot\State`, "UEFISecureBootEnabled")
	p.SecureBoot = triFromBool(v != 0, ok)

	v, ok = regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL")
	p.LSAProtection = Off
	if ok && v != 0 {
		p.LSAProtection = On
	}

	v, ok = regDWORD(registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest`, "UseLogonCredential")
	p.WDigest = Off
	if ok && v == 1 {
		p.WDigest = On
	}

	// --- Proxy (current user) ---
	const inet = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`
	if v, ok := regDWORD(registry.CURRENT_USER, inet, "ProxyEnable"); ok && v != 0 {
		p.ProxyEnabled = true
	}
	p.ProxyServer = regString(registry.CURRENT_USER, inet, "ProxyServer")
	p.ProxyPAC = regString(registry.CURRENT_USER, inet, "AutoConfigURL")

	p.Hosts = readHosts()

	av := "no antivirus registered"
	if len(p.Antivirus) > 0 {
		names := make([]string, 0, len(p.Antivirus))
		for _, a := range p.Antivirus {
			names = append(names, a.Name)
		}
		av = strings.Join(names, ", ")
	}
	return fmt.Sprintf("%s; Defender real-time %s", av, p.DefenderRealtime)
}

func readHosts() []HostsEntry {
	f, err := os.Open(filepath.Join(winsys.SystemRoot(), `System32\drivers\etc\hosts`))
	if err != nil {
		return nil
	}
	defer f.Close()

	var out []HostsEntry
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := sc.Text()
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		out = append(out, HostsEntry{IP: fields[0], Names: fields[1:]})
	}
	return out
}
