package main

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"unsafe"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
)

type dnsCacheEntry struct {
	next       *dnsCacheEntry
	name       *uint16
	rtype      uint16
	dataLength uint16
	flags      uint32
}

func main() {
	runtime.LockOSThread()
	ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED)

	// --- DNS cache ---
	proc := windows.NewLazySystemDLL("dnsapi.dll").NewProc("DnsGetCacheDataTable")
	fmt.Println("find:", proc.Find())
	var head *dnsCacheEntry
	r, _, e := proc.Call(uintptr(unsafe.Pointer(&head)))
	fmt.Println("r=", r, "err=", e, "head nil?", head == nil)
	n := 0
	for p := head; p != nil && n < 5000; p = p.next {
		if n < 6 {
			fmt.Printf("  entry type=%d name=%s\n", p.rtype, windows.UTF16PtrToString(p.name))
		}
		n++
	}
	fmt.Println("entries:", n)

	// --- AV product state ---
	unk, _ := oleutil.CreateObject("WbemScripting.SWbemLocator")
	loc, _ := unk.QueryInterface(ole.IID_IDispatch)
	svcV, err := oleutil.CallMethod(loc, "ConnectServer", ".", `root\SecurityCenter2`)
	fmt.Println("connect err:", err)
	resV, _ := oleutil.CallMethod(svcV.ToIDispatch(), "ExecQuery", "SELECT * FROM AntiVirusProduct")
	oleutil.ForEach(resV.ToIDispatch(), func(v *ole.VARIANT) error {
		it := v.ToIDispatch()
		ps, err := oleutil.GetProperty(it, "productState")
		nm, _ := oleutil.GetProperty(it, "displayName")
		fmt.Printf("AV %v state VT=%d val=%v (%T) err=%v\n", nm.Value(), ps.VT, ps.Value(), ps.Value(), err)
		return nil
	})

	// --- Store package signature ---
	wa := `C:\Program Files\WindowsApps`
	pkgs, err := os.ReadDir(wa)
	fmt.Println("list WindowsApps:", len(pkgs), err)
	for _, pkg := range []string{"Microsoft.WidgetsPlatformRuntime_1.6.19.0_x64__8wekyb3d8bbwe", "Claude_5.11492.5.0_x64__pzs8sxrjxfjjc"} {
		for _, f := range []string{"AppxSignature.p7x", `AppxMetadata\CodeIntegrity.cat`, "AppxManifest.xml"} {
			full := filepath.Join(wa, pkg, f)
			_, serr := os.Stat(full)
			p, _ := windows.UTF16PtrFromString(full)
			fi := windows.WinTrustFileInfo{FilePath: p}
			fi.Size = uint32(unsafe.Sizeof(fi))
			data := windows.WinTrustData{UIChoice: windows.WTD_UI_NONE, RevocationChecks: windows.WTD_REVOKE_NONE, UnionChoice: windows.WTD_CHOICE_FILE,
				FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fi), StateAction: windows.WTD_STATEACTION_VERIFY,
				ProvFlags: windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL}
			data.Size = uint32(unsafe.Sizeof(data))
			verr := windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
			hr := uint32(0)
			if en, ok := verr.(syscall.Errno); ok {
				hr = uint32(en)
			}
			data.StateAction = windows.WTD_STATEACTION_CLOSE
			windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
			fmt.Printf("PKG %-22s %-32s stat=%v hr=0x%08X\n", pkg[:22], f, serr == nil, hr)
		}
	}
}
