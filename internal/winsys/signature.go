// Package winsys holds the low-level Windows plumbing shared by the
// collectors: Authenticode verification, path handling, privileges, console
// helpers and the DNS resolver cache.
package winsys

import (
	"os"
	"strings"
	"sync"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SigState is the outcome of an Authenticode check.
type SigState int

const (
	SigUnknown   SigState = iota // not checked, or the file could not be read
	SigValid                     // embedded or catalog signature with a trusted chain
	SigUntrusted                 // signature present but broken / untrusted / revoked
	SigExpired                   // signing certificate expired without a timestamp
	SigUnsigned                  // no signature anywhere
	SigMissing                   // the file does not exist on disk
)

func (s SigState) String() string {
	switch s {
	case SigValid:
		return "signed"
	case SigUntrusted:
		return "invalid"
	case SigExpired:
		return "expired"
	case SigUnsigned:
		return "unsigned"
	case SigMissing:
		return "missing"
	default:
		return "unknown"
	}
}

// MarshalText makes the state readable in JSON reports.
func (s SigState) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// Signature describes who (if anyone) vouches for a file.
type Signature struct {
	State   SigState `json:"state"`
	Signer  string   `json:"signer,omitempty"`
	Catalog bool     `json:"catalog,omitempty"` // signed through a Windows security catalog
}

// Trusted reports whether the file carries a valid, chained signature.
func (s Signature) Trusted() bool { return s.State == SigValid }

// Unsigned reports whether the file verifiably carries no signature at all.
func (s Signature) Unsigned() bool { return s.State == SigUnsigned }

// Broken reports a signature that exists but does not validate.
func (s Signature) Broken() bool { return s.State == SigUntrusted }

// IsMicrosoft reports whether the file is validly signed by Microsoft itself.
// "Microsoft Windows Hardware Compatibility Publisher" is deliberately not
// included: that is the WHQL certificate used for third-party drivers.
func (s Signature) IsMicrosoft() bool {
	if !s.Trusted() {
		return false
	}
	switch s.Signer {
	case "Microsoft Windows", "Microsoft Corporation", "Microsoft Windows Publisher",
		"Microsoft Windows Kits Publisher", "Microsoft 3rd Party Application Component":
		return true
	}
	return false
}

// Label is the short human form used in tables.
func (s Signature) Label() string {
	switch s.State {
	case SigValid:
		if s.Signer != "" {
			return s.Signer
		}
		return "signed"
	case SigUntrusted:
		if s.Signer != "" {
			return "INVALID signature (" + s.Signer + ")"
		}
		return "INVALID signature"
	case SigExpired:
		if s.Signer != "" {
			return "expired signature (" + s.Signer + ")"
		}
		return "expired signature"
	case SigUnsigned:
		return "UNSIGNED"
	case SigMissing:
		return "file missing"
	default:
		return "not verified"
	}
}

// ---------------------------------------------------------------------------
// WinVerifyTrust / catalog plumbing
// ---------------------------------------------------------------------------

var (
	modWintrust = windows.NewLazySystemDLL("wintrust.dll")

	procWTHelperProvDataFromStateData      = modWintrust.NewProc("WTHelperProvDataFromStateData")
	procWTHelperGetProvSignerFromChain     = modWintrust.NewProc("WTHelperGetProvSignerFromChain")
	procCryptCATAdminAcquireContext2       = modWintrust.NewProc("CryptCATAdminAcquireContext2")
	procCryptCATAdminCalcHashFromFileHndl2 = modWintrust.NewProc("CryptCATAdminCalcHashFromFileHandle2")
	procCryptCATAdminEnumCatalogFromHash   = modWintrust.NewProc("CryptCATAdminEnumCatalogFromHash")
	procCryptCATCatalogInfoFromContext     = modWintrust.NewProc("CryptCATCatalogInfoFromContext")
	procCryptCATAdminReleaseCatalogContext = modWintrust.NewProc("CryptCATAdminReleaseCatalogContext")
	procCryptCATAdminReleaseContext        = modWintrust.NewProc("CryptCATAdminReleaseContext")
)

const (
	hrOK                 = 0x00000000
	hrNoSignature        = 0x800B0100
	hrSubjectFormUnknown = 0x800B0003
	hrProviderUnknown    = 0x800B0001
	hrCertExpired        = 0x800B0101
	hrFileError          = 0x80092003
	hrAccessDenied       = 0x80070005
	hrSharingViolation   = 0x80070020

	certNameSimpleDisplayType = 4
)

// Partial layouts of CRYPT_PROVIDER_SGNR / CRYPT_PROVIDER_CERT: only the
// leading fields are needed to reach the leaf certificate.
type cryptProviderCert struct {
	cbStruct uint32
	pCert    *windows.CertContext
}

type cryptProviderSgnr struct {
	cbStruct     uint32
	verifyAsOf   windows.Filetime
	csCertChain  uint32
	pasCertChain *cryptProviderCert
}

type catalogInfo struct {
	cbStruct    uint32
	catalogFile [windows.MAX_PATH]uint16
}

// ptr converts an address returned by a system call into a pointer without
// tripping vet's unsafe.Pointer arithmetic check.
func ptr(u uintptr) unsafe.Pointer { return *(*unsafe.Pointer)(unsafe.Pointer(&u)) }

// verifyTrustFile runs WinVerifyTrust on one file. It never touches the
// network: revocation checks are off and URL retrieval is cache-only.
func verifyTrustFile(path string) (hr uint32, signer string) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return hrFileError, ""
	}
	fi := windows.WinTrustFileInfo{FilePath: p}
	fi.Size = uint32(unsafe.Sizeof(fi))

	data := windows.WinTrustData{
		UIChoice:                        windows.WTD_UI_NONE,
		RevocationChecks:                windows.WTD_REVOKE_NONE,
		UnionChoice:                     windows.WTD_CHOICE_FILE,
		FileOrCatalogOrBlobOrSgnrOrCert: unsafe.Pointer(&fi),
		StateAction:                     windows.WTD_STATEACTION_VERIFY,
		ProvFlags:                       windows.WTD_REVOCATION_CHECK_NONE | windows.WTD_CACHE_ONLY_URL_RETRIEVAL,
	}
	data.Size = uint32(unsafe.Sizeof(data))

	err = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	if err != nil {
		if errno, ok := err.(syscall.Errno); ok {
			hr = uint32(errno)
		} else {
			hr = hrFileError
		}
	}
	if data.StateData != 0 {
		signer = signerFromState(data.StateData)
	}

	data.StateAction = windows.WTD_STATEACTION_CLOSE
	_ = windows.WinVerifyTrustEx(windows.InvalidHWND, &windows.WINTRUST_ACTION_GENERIC_VERIFY_V2, &data)
	return hr, signer
}

func signerFromState(state windows.Handle) string {
	prov, _, _ := procWTHelperProvDataFromStateData.Call(uintptr(state))
	if prov == 0 {
		return ""
	}
	sg, _, _ := procWTHelperGetProvSignerFromChain.Call(prov, 0, 0, 0)
	if sg == 0 {
		return ""
	}
	s := (*cryptProviderSgnr)(ptr(sg))
	if s.csCertChain == 0 || s.pasCertChain == nil || s.pasCertChain.pCert == nil {
		return ""
	}
	var buf [256]uint16
	n := windows.CertGetNameString(s.pasCertChain.pCert, certNameSimpleDisplayType, 0, nil, &buf[0], uint32(len(buf)))
	if n <= 1 {
		return ""
	}
	return windows.UTF16ToString(buf[:])
}

// catalogFor looks the file's hash up in the system catalog database and
// returns the path of the catalog that lists it ("" when none does). Most
// binaries that ship with Windows are signed this way and carry no embedded
// signature at all.
func catalogFor(path string) string {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_ATTRIBUTE_NORMAL, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	if procCryptCATAdminAcquireContext2.Find() != nil {
		return ""
	}
	sha256, _ := windows.UTF16PtrFromString("SHA256")
	for _, alg := range []*uint16{sha256, nil} { // nil selects the legacy SHA1 catalogs
		var admin uintptr
		r, _, _ := procCryptCATAdminAcquireContext2.Call(
			uintptr(unsafe.Pointer(&admin)), 0, uintptr(unsafe.Pointer(alg)), 0, 0)
		if r == 0 || admin == 0 {
			continue
		}
		found := ""
		var hash [64]byte
		size := uint32(len(hash))
		_, _ = windows.Seek(h, 0, 0)
		r, _, _ = procCryptCATAdminCalcHashFromFileHndl2.Call(
			admin, uintptr(h), uintptr(unsafe.Pointer(&size)), uintptr(unsafe.Pointer(&hash[0])), 0)
		if r != 0 {
			info, _, _ := procCryptCATAdminEnumCatalogFromHash.Call(
				admin, uintptr(unsafe.Pointer(&hash[0])), uintptr(size), 0, 0)
			if info != 0 {
				var ci catalogInfo
				ci.cbStruct = uint32(unsafe.Sizeof(ci))
				r, _, _ = procCryptCATCatalogInfoFromContext.Call(info, uintptr(unsafe.Pointer(&ci)), 0)
				if r != 0 {
					found = windows.UTF16ToString(ci.catalogFile[:])
				}
				procCryptCATAdminReleaseCatalogContext.Call(admin, info, 0)
			}
		}
		procCryptCATAdminReleaseContext.Call(admin, 0)
		if found != "" {
			return found
		}
	}
	return ""
}

// ---------------------------------------------------------------------------
// Public, cached API
// ---------------------------------------------------------------------------

type sigCacheEntry struct {
	sig          Signature
	catalogTried bool
}

var (
	sigCache sync.Map // lower-case path -> sigCacheEntry
	catCache sync.Map // lower-case catalog path -> Signature
)

// Verify checks a file's embedded signature and, failing that, the Windows
// catalog database. Results are cached for the life of the process.
func Verify(path string) Signature { return verify(path, true) }

// VerifyEmbedded checks only the embedded signature. It is much cheaper than
// Verify and is the right call for bulk scans of drop folders, where catalog
// signed files are not expected.
func VerifyEmbedded(path string) Signature { return verify(path, false) }

func verify(path string, catalog bool) Signature {
	if path == "" {
		return Signature{}
	}
	key := strings.ToLower(path)
	if v, ok := sigCache.Load(key); ok {
		e := v.(sigCacheEntry)
		if e.catalogTried || !catalog || e.sig.State != SigUnsigned {
			return e.sig
		}
	}
	sig := verifyUncached(path, catalog)
	sigCache.Store(key, sigCacheEntry{sig: sig, catalogTried: catalog})
	return sig
}

func verifyUncached(path string, catalog bool) Signature {
	st, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return Signature{State: SigMissing}
		}
		return Signature{State: SigUnknown}
	}
	if st.IsDir() {
		return Signature{State: SigUnknown}
	}

	hr, signer := verifyTrustFile(path)
	switch hr {
	case hrOK:
		return Signature{State: SigValid, Signer: signer}
	case hrNoSignature, hrSubjectFormUnknown, hrProviderUnknown:
		// A format Windows cannot sign at all (a shortcut, a text file) is
		// "not applicable", which must not be reported as "unsigned".
		none := Signature{State: SigUnsigned}
		if hr != hrNoSignature {
			none.State = SigUnknown
		}
		if !catalog {
			return none
		}
		if cat := catalogFor(path); cat != "" {
			return verifyCatalog(cat)
		}
		if pkg := packageSignature(path); pkg != "" {
			return verifyCatalog(pkg)
		}
		return none
	case hrCertExpired:
		return Signature{State: SigExpired, Signer: signer}
	case hrFileError, hrAccessDenied, hrSharingViolation:
		return Signature{State: SigUnknown}
	default:
		return Signature{State: SigUntrusted, Signer: signer}
	}
}

// packageSignature returns the signature file of the Store (MSIX/AppX)
// package a file belongs to. Packaged apps are signed as a whole: the
// binaries inside carry no signature of their own and are not in the system
// catalogs, but the package directory is only writable by the installer.
func packageSignature(path string) string {
	const marker = `\windowsapps\`
	lower := strings.ToLower(path)
	i := strings.Index(lower, marker)
	if i < 0 || !strings.HasPrefix(lower, strings.ToLower(os.Getenv("ProgramFiles"))) {
		return ""
	}
	rest := path[i+len(marker):]
	j := strings.IndexByte(rest, '\\')
	if j <= 0 {
		return ""
	}
	p7x := path[:i+len(marker)+j] + `\AppxSignature.p7x`
	if _, err := os.Stat(p7x); err != nil {
		return ""
	}
	return p7x
}

func verifyCatalog(cat string) Signature {
	key := strings.ToLower(cat)
	if v, ok := catCache.Load(key); ok {
		return v.(Signature)
	}
	hr, signer := verifyTrustFile(cat)
	sig := Signature{State: SigUntrusted, Signer: signer, Catalog: true}
	if hr == hrOK {
		sig.State = SigValid
	}
	catCache.Store(key, sig)
	return sig
}

// VerifyMany warms the cache for a batch of files using a small worker pool.
// Callers then read the results back with Verify / VerifyEmbedded.
func VerifyMany(paths []string, catalog bool) {
	seen := make(map[string]bool, len(paths))
	jobs := make(chan string)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for p := range jobs {
				verify(p, catalog)
			}
		}()
	}
	for _, p := range paths {
		k := strings.ToLower(p)
		if p == "" || seen[k] {
			continue
		}
		seen[k] = true
		jobs <- p
	}
	close(jobs)
	wg.Wait()
}
