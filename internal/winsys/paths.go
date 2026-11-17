package winsys

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
)

// Location classifies where on disk a file lives, which is one of the
// strongest cheap signals available: software installs to Program Files,
// malware lands wherever a standard user can write.
type Location int

const (
	LocUnknown      Location = iota
	LocWindows               // %SystemRoot% (excluding its Temp)
	LocProgramFiles          // Program Files, Program Files (x86)
	LocProgramData           // %ProgramData%
	LocUserPrograms          // per-user installs: AppData\Local\Programs, AppData\Local\Microsoft
	LocAppData               // anywhere else under AppData
	LocTemp                  // any Temp directory
	LocDownloads
	LocDesktop
	LocUserProfile // elsewhere inside a user profile
	LocPublic      // C:\Users\Public
	LocRecycleBin
	LocNetwork // UNC path
	LocOther   // anywhere else on a local drive
)

func (l Location) String() string {
	switch l {
	case LocWindows:
		return "Windows directory"
	case LocProgramFiles:
		return "Program Files"
	case LocProgramData:
		return "ProgramData"
	case LocUserPrograms:
		return "per-user install folder"
	case LocAppData:
		return "AppData"
	case LocTemp:
		return "Temp folder"
	case LocDownloads:
		return "Downloads folder"
	case LocDesktop:
		return "Desktop"
	case LocUserProfile:
		return "user profile"
	case LocPublic:
		return "Public folder"
	case LocRecycleBin:
		return "Recycle Bin"
	case LocNetwork:
		return "network share"
	case LocOther:
		return "non-standard folder"
	default:
		return "unknown location"
	}
}

func (l Location) MarshalText() ([]byte, error) { return []byte(l.String()), nil }

// Installed reports locations that need administrator rights to write to.
func (l Location) Installed() bool { return l == LocWindows || l == LocProgramFiles }

// DropZone reports the places payloads are typically dropped and run from.
func (l Location) DropZone() bool {
	return l == LocTemp || l == LocPublic || l == LocRecycleBin || l == LocDownloads
}

// UserWritable reports locations a standard user can write to.
func (l Location) UserWritable() bool {
	switch l {
	case LocTemp, LocDownloads, LocDesktop, LocUserProfile, LocPublic, LocRecycleBin, LocAppData, LocUserPrograms:
		return true
	}
	return false
}

type knownDirs struct {
	sysRoot, programFiles, programFilesX86, programData, users, public string
}

var (
	dirsOnce sync.Once
	dirs     knownDirs
)

func env(name, fallback string) string {
	v := strings.TrimRight(strings.ToLower(os.Getenv(name)), `\`)
	if v == "" {
		return fallback
	}
	return v
}

func known() knownDirs {
	dirsOnce.Do(func() {
		dirs.sysRoot = env("SystemRoot", `c:\windows`)
		dirs.programFiles = env("ProgramW6432", env("ProgramFiles", `c:\program files`))
		dirs.programFilesX86 = env("ProgramFiles(x86)", `c:\program files (x86)`)
		dirs.programData = env("ProgramData", `c:\programdata`)
		dirs.public = env("PUBLIC", `c:\users\public`)
		dirs.users = filepath.Dir(dirs.public)
	})
	return dirs
}

// SystemRoot returns %SystemRoot% (normally C:\Windows).
func SystemRoot() string {
	if v := os.Getenv("SystemRoot"); v != "" {
		return strings.TrimRight(v, `\`)
	}
	return `C:\Windows`
}

// UsersDir returns the directory holding the user profiles (normally C:\Users).
func UsersDir() string {
	if v := os.Getenv("PUBLIC"); v != "" {
		return filepath.Dir(strings.TrimRight(v, `\`))
	}
	return `C:\Users`
}

func under(path, dir string) bool {
	return dir != "" && strings.HasPrefix(path, dir+`\`)
}

// Classify maps a path to a Location. Matching is anchored on the real
// system directories, so a folder merely *named* "windows" or "system32"
// somewhere else on disk is not mistaken for the real thing.
func Classify(path string) Location {
	if path == "" {
		return LocUnknown
	}
	p := strings.ToLower(filepath.Clean(path))
	p = strings.TrimPrefix(p, `\\?\`)
	if strings.HasPrefix(p, `\\`) {
		return LocNetwork
	}
	d := known()

	if strings.Contains(p, `\$recycle.bin\`) {
		return LocRecycleBin
	}
	if under(p, d.sysRoot+`\temp`) {
		return LocTemp
	}
	if under(p, d.sysRoot) {
		return LocWindows
	}
	if under(p, d.users) {
		switch {
		case under(p, d.public):
			return LocPublic
		case strings.Contains(p, `\appdata\local\temp\`), strings.Contains(p, `\appdata\locallow\temp\`):
			return LocTemp
		case strings.Contains(p, `\appdata\local\programs\`), strings.Contains(p, `\appdata\local\microsoft\`):
			return LocUserPrograms
		case strings.Contains(p, `\appdata\`):
			return LocAppData
		case strings.Contains(p, `\downloads\`):
			return LocDownloads
		case strings.Contains(p, `\desktop\`):
			return LocDesktop
		}
		return LocUserProfile
	}
	if under(p, d.programFiles) || under(p, d.programFilesX86) {
		return LocProgramFiles
	}
	if under(p, d.programData) {
		return LocProgramData
	}
	if strings.Contains(p, `\temp\`) || strings.Contains(p, `\tmp\`) {
		return LocTemp
	}
	return LocOther
}

// FileExists reports whether path names an existing regular file.
func FileExists(path string) bool {
	if path == "" {
		return false
	}
	st, err := os.Stat(path)
	return err == nil && !st.IsDir()
}

// Gone reports whether the path verifiably does not exist (as opposed to
// merely being unreadable with the current privileges).
func Gone(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err != nil && errors.Is(err, os.ErrNotExist)
}

// Expand resolves %VARIABLE% references the way cmd.exe would.
func Expand(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	src, err := windows.UTF16PtrFromString(s)
	if err != nil {
		return s
	}
	buf := make([]uint16, 1024)
	n, err := windows.ExpandEnvironmentStrings(src, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return s
	}
	if int(n) > len(buf) {
		buf = make([]uint16, n)
		n, err = windows.ExpandEnvironmentStrings(src, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			return s
		}
	}
	return windows.UTF16ToString(buf)
}

// NormalizePath turns the various spellings Windows uses for image paths
// (\??\C:\..., \SystemRoot\..., system32\..., bare names) into a plain DOS path.
func NormalizePath(p string) string {
	p = strings.TrimSpace(strings.Trim(strings.TrimSpace(p), `"`))
	if p == "" {
		return ""
	}
	p = Expand(p)
	p = strings.ReplaceAll(p, "/", `\`)
	lower := strings.ToLower(p)
	root := SystemRoot()
	switch {
	case strings.HasPrefix(lower, `\??\`):
		p = p[4:]
	case strings.HasPrefix(lower, `\\?\`):
		p = p[4:]
	case strings.HasPrefix(lower, `\systemroot\`):
		p = root + p[len(`\systemroot`):]
	case strings.HasPrefix(lower, `system32\`), strings.HasPrefix(lower, `syswow64\`):
		p = root + `\` + p
	case strings.HasPrefix(lower, `\windows\`):
		p = filepath.VolumeName(root) + p
	case strings.HasPrefix(lower, `\device\`):
		p = DevicePathToDOS(p)
	}
	if !strings.ContainsAny(p, `\:`) {
		// A bare name: Windows resolves it through the system directories.
		for _, dir := range []string{root + `\System32`, root, root + `\System32\wbem`, root + `\SysWOW64`} {
			for _, cand := range []string{p, p + ".exe"} {
				full := filepath.Join(dir, cand)
				if FileExists(full) {
					return full
				}
			}
		}
		return p
	}
	if filepath.Ext(p) == "" && !FileExists(p) && FileExists(p+".exe") {
		p += ".exe"
	}
	return p
}

var exeBoundaries = []string{".exe", ".dll", ".sys", ".com", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".hta", ".msi", ".cpl", ".ocx", ".lnk"}

// SplitCommandLine separates a command line into the program it launches and
// the remaining arguments. Unquoted paths containing spaces are resolved the
// way CreateProcess does it: by trying progressively longer prefixes until
// one names a real file.
func SplitCommandLine(cmd string) (exe, args string) {
	cmd = strings.TrimSpace(Expand(cmd))
	if cmd == "" {
		return "", ""
	}
	if cmd[0] == '"' {
		if end := strings.IndexByte(cmd[1:], '"'); end >= 0 {
			return NormalizePath(cmd[1 : 1+end]), strings.TrimSpace(cmd[2+end:])
		}
		cmd = cmd[1:]
	}
	if !strings.ContainsAny(cmd, " \t") {
		return NormalizePath(cmd), ""
	}

	// Progressive prefixes that exist on disk.
	for i := 0; i < len(cmd); i++ {
		if cmd[i] != ' ' && cmd[i] != '\t' {
			continue
		}
		cand := NormalizePath(cmd[:i])
		if FileExists(cand) {
			return cand, strings.TrimSpace(cmd[i:])
		}
	}
	if whole := NormalizePath(cmd); FileExists(whole) {
		return whole, ""
	}

	// Nothing exists (target deleted?): cut at the first executable-looking extension.
	lower := strings.ToLower(cmd)
	best := -1
	for _, ext := range exeBoundaries {
		from := 0
		for {
			i := strings.Index(lower[from:], ext)
			if i < 0 {
				break
			}
			end := from + i + len(ext)
			if end == len(lower) || lower[end] == ' ' || lower[end] == '\t' || lower[end] == ',' {
				if best < 0 || end < best {
					best = end
				}
				break
			}
			from = end
		}
	}
	if best > 0 {
		return NormalizePath(cmd[:best]), strings.TrimSpace(strings.TrimLeft(cmd[best:], ","))
	}
	i := strings.IndexAny(cmd, " \t")
	return NormalizePath(cmd[:i]), strings.TrimSpace(cmd[i:])
}

// Tokenize splits an argument string on whitespace, honouring double quotes.
func Tokenize(s string) []string {
	var out []string
	var cur strings.Builder
	inQuote := false
	flush := func() {
		if cur.Len() > 0 {
			out = append(out, cur.String())
			cur.Reset()
		}
	}
	for _, r := range s {
		switch {
		case r == '"':
			inQuote = !inQuote
		case (r == ' ' || r == '\t') && !inQuote:
			flush()
		default:
			cur.WriteRune(r)
		}
	}
	flush()
	return out
}

// ---------------------------------------------------------------------------
// NT device paths
// ---------------------------------------------------------------------------

var (
	devOnce sync.Once
	devMap  map[string]string // lower-case "\device\harddiskvolume3" -> "C:"
)

func loadDeviceMap() {
	devMap = make(map[string]string)
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return
	}
	buf := make([]uint16, 512)
	for i := 0; i < 26; i++ {
		if mask&(1<<uint(i)) == 0 {
			continue
		}
		drive := string(rune('A'+i)) + ":"
		dp, _ := windows.UTF16PtrFromString(drive)
		n, err := windows.QueryDosDevice(dp, &buf[0], uint32(len(buf)))
		if err != nil || n == 0 {
			continue
		}
		devMap[strings.ToLower(windows.UTF16ToString(buf))] = drive
	}
}

// DevicePathToDOS converts "\Device\HarddiskVolume3\Windows\x.exe" into
// "C:\Windows\x.exe". Unknown devices are returned unchanged.
func DevicePathToDOS(p string) string {
	devOnce.Do(loadDeviceMap)
	lower := strings.ToLower(p)
	if strings.HasPrefix(lower, `\device\mup\`) {
		return `\\` + p[len(`\device\mup\`):]
	}
	best := ""
	for dev := range devMap {
		if strings.HasPrefix(lower, dev+`\`) && len(dev) > len(best) {
			best = dev
		}
	}
	if best == "" {
		return p
	}
	return devMap[best] + p[len(best):]
}

// SHA256File hashes a file, refusing anything larger than maxBytes so a
// stray multi-gigabyte image cannot stall the scan.
func SHA256File(path string, maxBytes int64) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if st, err := f.Stat(); err == nil && st.Size() > maxBytes {
		return "", errors.New("file too large to hash")
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
