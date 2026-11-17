package collect

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-ole/go-ole"
	"golang.org/x/sys/windows/registry"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// Autorun is one way code gets started without the user asking for it.
type Autorun struct {
	Kind     string `json:"kind"`     // "Run key", "Startup folder", "IFEO debugger", ...
	Location string `json:"location"` // registry key, folder or WMI class
	Name     string `json:"name"`
	Command  string `json:"command"`
	User     string `json:"user,omitempty"` // whose logon triggers it ("" = machine-wide)

	// Special marks mechanisms that are rarely used by legitimate software
	// (IFEO debuggers, Winlogon overrides, WMI consumers, LSA packages...).
	// Their mere presence deserves an explanation.
	Special  bool `json:"special"`
	Disabled bool `json:"disabled,omitempty"` // switched off in Task Manager's Startup tab

	Target string           `json:"target,omitempty"`
	Args   string           `json:"args,omitempty"`
	Sig    winsys.Signature `json:"signature"`
	Loc    winsys.Location  `json:"location_class"`
	Gone   bool             `json:"target_missing,omitempty"`
	Note   string           `json:"note,omitempty"`
}

type autorunCollector struct {
	out []Autorun
}

func (c *autorunCollector) add(a Autorun) {
	a.Command = strings.TrimSpace(a.Command)
	if a.Command == "" {
		return
	}
	if a.Target == "" {
		a.Target, a.Args = winsys.SplitCommandLine(a.Command)
	}
	c.out = append(c.out, a)
}

func collectAutoruns(s *Snapshot) string {
	c := &autorunCollector{}

	c.runKeys(registry.LOCAL_MACHINE, "HKLM", "")
	for _, hive := range userHives() {
		c.runKeys(registry.USERS, `HKU\`+hive.sid, hive.user)
		c.perUser(hive)
	}
	c.startupFolders(s)
	c.winlogon()
	c.ifeo()
	c.appInit()
	c.sessionManager()
	c.lsaPackages()
	c.wmiConsumers(s)
	c.accessibility()

	var paths []string
	for _, a := range c.out {
		paths = append(paths, a.Target)
	}
	winsys.VerifyMany(paths, true)
	special := 0
	for i := range c.out {
		a := &c.out[i]
		if a.Target != "" {
			a.Sig = winsys.Verify(a.Target)
			a.Loc = winsys.Classify(a.Target)
			a.Gone = winsys.Gone(a.Target)
		}
		if a.Special {
			special++
		}
	}
	s.Autoruns = c.out
	return fmt.Sprintf("%d entries, %d using unusual mechanisms", len(c.out), special)
}

type userHive struct {
	sid, user string
}

// userHives lists the user registry hives currently loaded under HKEY_USERS.
func userHives() []userHive {
	var out []userHive
	for _, sid := range regSubKeys(registry.USERS, "") {
		if strings.HasSuffix(sid, "_Classes") {
			continue
		}
		if !strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasPrefix(sid, "S-1-12-1-") {
			continue
		}
		out = append(out, userHive{sid: sid, user: accountName(sid)})
	}
	return out
}

// runKeys reads the classic Run-style keys below prefix ("" for HKLM, the
// user SID for a hive under HKEY_USERS).
func (c *autorunCollector) runKeys(root registry.Key, label, user string) {
	prefix := ""
	if root == registry.USERS {
		prefix = strings.TrimPrefix(label, `HKU\`) + `\`
	}
	type src struct{ path, kind string }
	sources := []src{
		{`Software\Microsoft\Windows\CurrentVersion\Run`, "Run key"},
		{`Software\Microsoft\Windows\CurrentVersion\RunOnce`, "RunOnce key"},
		{`Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`, "Policy Run key"},
		{`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`, "Run key (32-bit)"},
		{`Software\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce`, "RunOnce key (32-bit)"},
	}
	for _, src := range sources {
		k, err := registry.OpenKey(root, prefix+src.path, registry.QUERY_VALUE)
		if err != nil {
			continue
		}
		names, _ := k.ReadValueNames(-1)
		for _, name := range names {
			val, _, err := k.GetStringValue(name)
			if err != nil {
				continue
			}
			c.add(Autorun{
				Kind: src.kind, Location: label + `\` + src.path, Name: name, Command: val, User: user,
				Disabled: startupDisabled(root, prefix, src.path, name),
			})
		}
		k.Close()
	}
}

// startupDisabled checks the StartupApproved bookkeeping that Task Manager's
// Startup tab writes: an odd first byte means the entry is switched off.
func startupDisabled(root registry.Key, prefix, runPath, name string) bool {
	sub := "Run"
	if strings.Contains(runPath, "WOW6432Node") {
		sub = "Run32"
	}
	k, err := registry.OpenKey(root,
		prefix+`Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\`+sub, registry.QUERY_VALUE)
	if err != nil {
		return false
	}
	defer k.Close()
	data, _, err := k.GetBinaryValue(name)
	return err == nil && len(data) > 0 && data[0]&1 == 1
}

// perUser covers the quieter per-user logon hooks.
func (c *autorunCollector) perUser(h userHive) {
	base := h.sid + `\`
	label := `HKU\` + h.sid + `\`

	const win = `Software\Microsoft\Windows NT\CurrentVersion\Windows`
	for _, name := range []string{"Load", "Run"} {
		if v := regString(registry.USERS, base+win, name); strings.TrimSpace(v) != "" {
			c.add(Autorun{Kind: "Windows Load/Run value", Location: label + win, Name: name, Command: v, User: h.user, Special: true})
		}
	}
	if v := regString(registry.USERS, base+`Environment`, "UserInitMprLogonScript"); v != "" {
		c.add(Autorun{Kind: "Logon script", Location: label + `Environment`, Name: "UserInitMprLogonScript", Command: v, User: h.user, Special: true})
	}
	const wl = `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
	if v := regString(registry.USERS, base+wl, "Shell"); v != "" && !strings.EqualFold(strings.TrimSpace(v), "explorer.exe") {
		c.add(Autorun{Kind: "Winlogon shell (per-user)", Location: label + wl, Name: "Shell", Command: v, User: h.user, Special: true})
	}
	if v := regString(registry.USERS, base+`Control Panel\Desktop`, "SCRNSAVE.EXE"); v != "" {
		target := winsys.NormalizePath(v)
		if winsys.Classify(target) != winsys.LocWindows {
			c.add(Autorun{Kind: "Screensaver", Location: label + `Control Panel\Desktop`, Name: "SCRNSAVE.EXE", Command: v, User: h.user, Special: true})
		}
	}
}

func (c *autorunCollector) startupFolders(s *Snapshot) {
	type folder struct{ path, user string }
	folders := []folder{{filepath.Join(os.Getenv("ProgramData"), `Microsoft\Windows\Start Menu\Programs\StartUp`), ""}}
	if entries, err := os.ReadDir(winsys.UsersDir()); err == nil {
		for _, e := range entries {
			if e.IsDir() {
				folders = append(folders, folder{
					filepath.Join(winsys.UsersDir(), e.Name(), `AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`), e.Name()})
			}
		}
	}
	for _, f := range folders {
		entries, err := os.ReadDir(f.path)
		if err != nil {
			continue
		}
		for _, e := range entries {
			if e.IsDir() || strings.EqualFold(e.Name(), "desktop.ini") {
				continue
			}
			full := filepath.Join(f.path, e.Name())
			a := Autorun{Kind: "Startup folder", Location: f.path, Name: e.Name(), Command: full, User: f.user, Target: full}
			if strings.EqualFold(filepath.Ext(full), ".lnk") {
				if target, args := resolveShortcut(full); target != "" {
					a.Target, a.Args = target, args
					a.Command = strings.TrimSpace(`"` + target + `" ` + args)
				}
			}
			c.add(a)
		}
	}
}

func (c *autorunCollector) winlogon() {
	const key = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`
	loc := `HKLM\` + key

	if shell := regString(registry.LOCAL_MACHINE, key, "Shell"); shell != "" &&
		!strings.EqualFold(strings.TrimSpace(shell), "explorer.exe") {
		c.add(Autorun{Kind: "Winlogon shell", Location: loc, Name: "Shell", Command: shell, Special: true,
			Note: `expected "explorer.exe"`})
	}

	expected := strings.ToLower(winsys.SystemRoot() + `\system32\userinit.exe`)
	userinit := regString(registry.LOCAL_MACHINE, key, "Userinit")
	for _, part := range strings.Split(userinit, ",") {
		part = strings.TrimSpace(part)
		if part == "" || strings.ToLower(winsys.NormalizePath(part)) == expected {
			continue
		}
		c.add(Autorun{Kind: "Winlogon userinit", Location: loc, Name: "Userinit", Command: part, Special: true,
			Note: "extra program chained after userinit.exe"})
	}

	for _, name := range []string{"Taskman", "AppSetup", "VmApplet"} {
		v := strings.TrimSpace(regString(registry.LOCAL_MACHINE, key, name))
		if v == "" || (name == "VmApplet" && strings.EqualFold(v, "SystemPropertiesPerformance.exe /pagefile")) {
			continue
		}
		c.add(Autorun{Kind: "Winlogon " + name, Location: loc, Name: name, Command: v, Special: true})
	}
}

// ifeo covers Image File Execution Options hijacks: a "Debugger" replaces the
// named program every time it starts; a SilentProcessExit monitor runs when
// the named program exits.
func (c *autorunCollector) ifeo() {
	for _, view := range []string{`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, `SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion`} {
		base := view + `\Image File Execution Options`
		for _, image := range regSubKeys(registry.LOCAL_MACHINE, base) {
			if dbg := regString(registry.LOCAL_MACHINE, base+`\`+image, "Debugger"); strings.TrimSpace(dbg) != "" {
				c.add(Autorun{Kind: "IFEO debugger", Location: `HKLM\` + base + `\` + image, Name: image, Command: dbg, Special: true,
					Note: "runs instead of " + image + " whenever it is launched"})
			}
		}
		spe := view + `\SilentProcessExit`
		for _, image := range regSubKeys(registry.LOCAL_MACHINE, spe) {
			if mon := regString(registry.LOCAL_MACHINE, spe+`\`+image, "MonitorProcess"); strings.TrimSpace(mon) != "" {
				c.add(Autorun{Kind: "Silent process exit monitor", Location: `HKLM\` + spe + `\` + image, Name: image, Command: mon, Special: true,
					Note: "runs whenever " + image + " exits"})
			}
		}
	}
}

func (c *autorunCollector) appInit() {
	for _, key := range []string{
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows`,
		`SOFTWARE\WOW6432Node\Microsoft\Windows NT\CurrentVersion\Windows`,
	} {
		list := regString(registry.LOCAL_MACHINE, key, "AppInit_DLLs")
		enabled, _ := regDWORD(registry.LOCAL_MACHINE, key, "LoadAppInit_DLLs")
		note := "loading currently disabled (LoadAppInit_DLLs=0)"
		if enabled != 0 {
			note = "loaded into every process that uses user32.dll"
		}
		for _, dll := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ';' }) {
			dll = strings.TrimSpace(dll)
			if dll == "" {
				continue
			}
			c.add(Autorun{Kind: "AppInit DLL", Location: `HKLM\` + key, Name: "AppInit_DLLs", Command: dll, Special: true,
				Target: winsys.NormalizePath(dll), Note: note})
		}
	}
}

func (c *autorunCollector) sessionManager() {
	const key = `SYSTEM\CurrentControlSet\Control\Session Manager`
	for _, line := range regMultiString(registry.LOCAL_MACHINE, key, "BootExecute") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(strings.ToLower(line), "autocheck autochk") {
			continue
		}
		c.add(Autorun{Kind: "Boot execute", Location: `HKLM\` + key, Name: "BootExecute", Command: line, Special: true,
			Note: "native program run by the Session Manager before Windows finishes booting"})
	}
	const certs = key + `\AppCertDlls`
	for _, name := range regValueNames(registry.LOCAL_MACHINE, certs) {
		if dll := regString(registry.LOCAL_MACHINE, certs, name); dll != "" {
			c.add(Autorun{Kind: "AppCert DLL", Location: `HKLM\` + certs, Name: name, Command: dll, Special: true,
				Target: winsys.NormalizePath(dll), Note: "loaded into every process that creates another process"})
		}
	}
}

// Packages that ship with Windows; anything else loaded into LSASS can read
// every credential that passes through the machine.
var defaultLSAPackages = map[string]bool{
	"": true, `""`: true, "msv1_0": true, "kerberos": true, "schannel": true, "wdigest": true, "tspkg": true,
	"pku2u": true, "cloudap": true, "negoexts": true, "livessp": true, "scecli": true, "rassfm": true,
}

func (c *autorunCollector) lsaPackages() {
	for _, key := range []string{`SYSTEM\CurrentControlSet\Control\Lsa`, `SYSTEM\CurrentControlSet\Control\Lsa\OSConfig`} {
		for _, value := range []string{"Authentication Packages", "Notification Packages", "Security Packages"} {
			for _, pkg := range regMultiString(registry.LOCAL_MACHINE, key, value) {
				pkg = strings.TrimSpace(pkg)
				if defaultLSAPackages[strings.ToLower(pkg)] {
					continue
				}
				target := pkg
				if filepath.Ext(target) == "" {
					target += ".dll"
				}
				c.add(Autorun{Kind: "LSA package", Location: `HKLM\` + key, Name: value, Command: pkg, Special: true,
					Target: winsys.NormalizePath(target), Note: "non-default package loaded into LSASS"})
			}
		}
	}
}

// wmiConsumers lists the permanent WMI event consumers able to run code.
// Passive consumers (event-log writers and the like) are not persistence.
func (c *autorunCollector) wmiConsumers(s *Snapshot) {
	const ns = `root\subscription`
	err := wmiQuery(ns, "SELECT * FROM CommandLineEventConsumer", func(item *ole.IDispatch) {
		cmd := comString(item, "CommandLineTemplate")
		if cmd == "" {
			cmd = comString(item, "ExecutablePath")
		}
		c.add(Autorun{Kind: "WMI command consumer", Location: ns + `:CommandLineEventConsumer`,
			Name: comString(item, "Name"), Command: cmd, Special: true,
			Note: "runs a command whenever its WMI event filter fires"})
	})
	if err != nil {
		s.note("WMI subscriptions could not be queried (%v)", err)
		return
	}
	wmiQuery(ns, "SELECT * FROM ActiveScriptEventConsumer", func(item *ole.IDispatch) {
		script := comString(item, "ScriptFileName")
		a := Autorun{Kind: "WMI script consumer", Location: ns + `:ActiveScriptEventConsumer`,
			Name: comString(item, "Name"), Special: true,
			Note: "runs " + comString(item, "ScriptingEngine") + " whenever its WMI event filter fires"}
		if script != "" {
			a.Command, a.Target = script, winsys.NormalizePath(script)
		} else {
			// Inline script: keep the text itself as the "command".
			text := strings.Join(strings.Fields(comString(item, "ScriptText")), " ")
			a.Command, a.Target = text, "(inline script)"
			a.Args = text
		}
		c.add(a)
	})
}

// accessibility detects the "sticky keys" backdoor: an accessibility tool
// reachable from the lock screen replaced by a command shell.
func (c *autorunCollector) accessibility() {
	sys := winsys.SystemRoot() + `\System32\`
	shells := map[string]string{}
	for _, name := range []string{"cmd.exe", `WindowsPowerShell\v1.0\powershell.exe`, "explorer.exe", "taskmgr.exe"} {
		if h, err := winsys.SHA256File(sys+name, 64<<20); err == nil {
			shells[h] = filepath.Base(name)
		}
	}
	if h, err := winsys.SHA256File(winsys.SystemRoot()+`\explorer.exe`, 64<<20); err == nil {
		shells[h] = "explorer.exe"
	}
	for _, tool := range []string{"sethc.exe", "utilman.exe", "osk.exe", "narrator.exe", "magnify.exe", "displayswitch.exe", "atbroker.exe"} {
		h, err := winsys.SHA256File(sys+tool, 64<<20)
		if err != nil {
			continue
		}
		if shell, hit := shells[h]; hit {
			c.add(Autorun{Kind: "Accessibility backdoor", Location: sys, Name: tool, Command: sys + tool, Special: true,
				Target: sys + tool, Note: tool + " is a byte-for-byte copy of " + shell + " (reachable from the lock screen)"})
		}
	}
}
