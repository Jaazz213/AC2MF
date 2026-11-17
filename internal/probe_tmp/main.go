package main

import (
	"fmt"
	"time"

	"github.com/Jaazz213/AC2MF/internal/collect"
	"github.com/Jaazz213/AC2MF/internal/winsys"
)

type rep struct{}

func (rep) StepStart(string) {}
func (rep) StepDone(name, summary string, took time.Duration) {
	fmt.Printf("%-20s %-60s %v\n", name, summary, took.Round(time.Millisecond))
}

func main() {
	for _, p := range []string{`C:\Windows\System32\notepad.exe`, `C:\Windows\System32\svchost.exe`, `C:\Windows\explorer.exe`, `C:\Windows\System32\drivers\tcpip.sys`, `C:\Program Files\Go\bin\go.exe`, `C:\nope.exe`} {
		s := winsys.Verify(p)
		fmt.Printf("SIG %-45s %-9s catalog=%-5v %q ms=%v\n", p, s.State, s.Catalog, s.Signer, s.IsMicrosoft())
	}
	for _, c := range []string{`C:\Program Files\Docker\Docker\Docker Desktop.exe -Autostart`, `%windir%\system32\SecurityHealthSystray.exe`, `rundll32.exe shell32.dll,Control_RunDLL`, `"C:\a b\c.exe" /x`, `C:\Program Files\Gone\x.exe -arg`, `\SystemRoot\System32\drivers\tcpip.sys`} {
		e, a := winsys.SplitCommandLine(c)
		fmt.Printf("CMD %-62s => [%s] [%s]\n", c, e, a)
	}

	s := collect.Collect(collect.Options{}, rep{})
	fmt.Println("elevated:", s.Elevated)
	for _, n := range s.Notes {
		fmt.Println("NOTE:", n)
	}
	fmt.Printf("SYS %+v\n", s.System)
	fmt.Printf("SEC %+v\n", s.Security)
	for _, u := range s.Users {
		fmt.Printf("USER %-28s kind=%-7s admin=%-5v en=%-5v on=%-5v builtin=%-18s last=%s prof=%s\n", u.Name, u.Kind, u.Admin, u.Enabled, u.LoggedOn, u.BuiltIn, u.LastLogon.Format("2006-01-02"), u.ProfilePath)
	}
	nopath, nocmd, unsigned := 0, 0, 0
	for _, p := range s.Processes {
		if p.Path == "" {
			nopath++
			fmt.Printf("NOPATH pid=%d %s\n", p.PID, p.Name)
		}
		if p.CommandLine == "" {
			nocmd++
		}
		if p.Sig.State != winsys.SigValid && p.Path != "" {
			unsigned++
			fmt.Printf("PROC-NOTVALID pid=%-6d %-9s %s\n", p.PID, p.Sig.State, p.Path)
		}
	}
	fmt.Println("procs", len(s.Processes), "nopath", nopath, "nocmd", nocmd, "notvalid", unsigned)
	pub := 0
	for _, c := range s.Connections {
		if c.Scope == "public" {
			pub++
			if pub <= 12 {
				fmt.Printf("CONN %-5s %-24s %-24s %-12s %-6d %-22s host=%-30s %s | %s\n", c.Proto, c.Local(), c.Remote(), c.State, c.PID, c.ProcessName, c.RemoteHost, c.ProcessPath, c.Sig.Label())
			}
		}
	}
	fmt.Println("dns names:", len(s.DNS))
	for i, d := range s.DNS {
		if i < 5 {
			fmt.Printf("DNS %s %v\n", d.Name, d.IPs)
		}
	}
	bad := 0
	for _, v := range s.Services {
		if v.Running() && v.Sig.State != winsys.SigValid {
			bad++
			if bad <= 15 {
				fmt.Printf("SVC-NOTVALID %-28s drv=%-5v %-9s img=%q target=%q\n", v.Name, v.Driver, v.Sig.State, v.ImagePath, v.Target)
			}
		}
	}
	fmt.Println("running services not valid:", bad)
	exec, com, nt := 0, 0, 0
	for _, t := range s.Tasks {
		for _, a := range t.Actions {
			if a.Kind == "com" {
				com++
				continue
			}
			exec++
			if a.Sig.State != winsys.SigValid {
				nt++
				fmt.Printf("TASK-NOTVALID %-55s %-9s cmd=%q target=%q args=%q\n", t.Path, a.Sig.State, a.Command, a.Target, a.Args)
			}
		}
		if t.NoSecurityDescriptor || t.RegistryOnly {
			fmt.Printf("TASK-STEALTH %s nosd=%v regonly=%v\n", t.Path, t.NoSecurityDescriptor, t.RegistryOnly)
		}
	}
	fmt.Println("task exec actions", exec, "com", com, "notvalid", nt)
	for _, a := range s.Autoruns {
		fmt.Printf("AUTORUN %-22s sp=%-5v dis=%-5v %-28s %-9s %-22s target=%q args=%q\n", a.Kind, a.Special, a.Disabled, a.Name, a.Sig.State, a.Sig.Signer, a.Target, a.Args)
	}
	kinds := map[string]int{}
	for _, f := range s.Files {
		kinds[f.Zone+"/"+f.Kind+"/"+f.Sig.State.String()]++
		if f.DisguisedPE || f.DoubleExt || f.RTLO || (f.Hidden && f.Kind == "executable") {
			fmt.Printf("FILE-ODD %s disguised=%v dbl=%v hidden=%v\n", f.Path, f.DisguisedPE, f.DoubleExt, f.Hidden)
		}
	}
	fmt.Println("files:", len(s.Files), kinds)
}
