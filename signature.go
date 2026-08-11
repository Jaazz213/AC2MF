package main

import (
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// SignatureStatus represents the result of Authenticode verification.
type SignatureStatus int

const (
	SignedValid       SignatureStatus = iota // Good signature
	SignedUntrusted                          // Signed but cert not trusted
	SignedExpired                            // Signature expired
	Unsigned                                // No signature at all
	SignatureError                           // Could not verify (access denied, etc.)
)

func (s SignatureStatus) String() string {
	switch s {
	case SignedValid:
		return "✅ Signed (valid)"
	case SignedUntrusted:
		return "⚠️  Signed (untrusted)"
	case SignedExpired:
		return "⚠️  Signed (expired)"
	case Unsigned:
		return "❌ Not signed"
	case SignatureError:
		return "⚠️  Unable to verify"
	default:
		return "Unknown"
	}
}

// PlainString returns a text-only representation (no emoji, for .txt export).
func (s SignatureStatus) PlainString() string {
	switch s {
	case SignedValid:
		return "Signed (valid)"
	case SignedUntrusted:
		return "Signed (untrusted)"
	case SignedExpired:
		return "Signed (expired)"
	case Unsigned:
		return "Not signed"
	case SignatureError:
		return "Unable to verify"
	default:
		return "Unknown"
	}
}

// IsSigned returns true if the file has any kind of valid signature.
func (s SignatureStatus) IsSigned() bool {
	return s == SignedValid
}

// ---------------------------------------------------------------------------
// WinVerifyTrust via wintrust.dll
// ---------------------------------------------------------------------------

var (
	modWintrust              = windows.NewLazySystemDLL("wintrust.dll")
	procWinVerifyTrust       = modWintrust.NewProc("WinVerifyTrust")
)

// GUID for authenticode verification
// WINTRUST_ACTION_GENERIC_VERIFY_V2
var wintrustActionGenericVerifyV2 = windows.GUID{
	Data1: 0x00AAC56B,
	Data2: 0xCD44,
	Data3: 0x11D0,
	Data4: [8]byte{0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE},
}

const (
	wtdUINone          = 2
	wtdRevokeNone      = 0
	wtdChoiceFile      = 1
	wtdStateActionVerify = 1
	wtdStateActionClose  = 2
	wtdSaferFlag       = 0x100
	wtdUseIEDefaults   = 0 // not actually used but kept for clarity
)

// WINTRUST_FILE_INFO
type wintrustFileInfo struct {
	CbStruct       uint32
	PcwszFilePath  *uint16
	HFile          windows.Handle
	PgKnownSubject *windows.GUID
}

// WINTRUST_DATA
type wintrustData struct {
	CbStruct            uint32
	PPolicyCallbackData uintptr
	PSIPClientData      uintptr
	DwUIChoice          uint32
	FdwRevocationChecks uint32
	DwUnionChoice       uint32
	PFile               *wintrustFileInfo
	DwStateAction       uint32
	HWVTStateData       windows.Handle
	PwszURLReference    *uint16
	DwProvFlags         uint32
	DwUIContext         uint32
	PSignatureSettings  uintptr
}

// signatureCache avoids re-verifying the same file.
var signatureCache sync.Map

// VerifySignature checks the Authenticode signature of a file.
func VerifySignature(filePath string) SignatureStatus {
	if filePath == "" {
		return SignatureError
	}

	// Check cache
	if cached, ok := signatureCache.Load(filePath); ok {
		return cached.(SignatureStatus)
	}

	status := verifySignatureUncached(filePath)
	signatureCache.Store(filePath, status)
	return status
}

func verifySignatureUncached(filePath string) SignatureStatus {
	pathPtr, err := windows.UTF16PtrFromString(filePath)
	if err != nil {
		return SignatureError
	}

	fileInfo := wintrustFileInfo{
		CbStruct:      uint32(unsafe.Sizeof(wintrustFileInfo{})),
		PcwszFilePath: pathPtr,
	}

	data := wintrustData{
		CbStruct:            uint32(unsafe.Sizeof(wintrustData{})),
		DwUIChoice:          wtdUINone,
		FdwRevocationChecks: wtdRevokeNone,
		DwUnionChoice:       wtdChoiceFile,
		PFile:               &fileInfo,
		DwStateAction:       wtdStateActionVerify,
		DwProvFlags:         wtdSaferFlag,
	}

	ret, _, _ := procWinVerifyTrust.Call(
		uintptr(0), // INVALID_HANDLE_VALUE equivalent for "no window"
		uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)

	// Close state
	data.DwStateAction = wtdStateActionClose
	procWinVerifyTrust.Call(
		uintptr(0),
		uintptr(unsafe.Pointer(&wintrustActionGenericVerifyV2)),
		uintptr(unsafe.Pointer(&data)),
	)

	// Interpret result
	const (
		trustE_nosignature       = 0x800B0100
		trustE_explicit_distrust = 0x800B0111
		trustE_subject_not_trusted = 0x800B0004
		certE_expired            = 0x800B0101
		certE_chaining           = 0x800B010A
		trustE_bad_digest        = 0x80096010
	)

	hr := int32(ret)
	switch {
	case hr == 0:
		return SignedValid
	case uint32(hr) == trustE_nosignature:
		return Unsigned
	case uint32(hr) == certE_expired:
		return SignedExpired
	case uint32(hr) == trustE_explicit_distrust,
		uint32(hr) == trustE_subject_not_trusted,
		uint32(hr) == certE_chaining,
		uint32(hr) == trustE_bad_digest:
		return SignedUntrusted
	default:
		// Any other HRESULT — we have *some* signature data but it's
		// not cleanly valid.  Still flag as signed-but-untrusted rather
		// than outright unsigned.
		if hr < 0 {
			return SignedUntrusted
		}
		return SignedValid
	}
}
