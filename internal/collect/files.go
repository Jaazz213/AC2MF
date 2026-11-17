package collect

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// FileEntry is an executable, script or disguised program found in one of
// the folders malware is typically dropped into.
type FileEntry struct {
	Path     string    `json:"path"`
	Name     string    `json:"name"`
	Kind     string    `json:"kind"` // executable, script, shortcut, disguised
	Zone     string    `json:"zone"` // which drop folder it was found in
	Owner    string    `json:"owner,omitempty"`
	Size     int64     `json:"size"`
	Modified time.Time `json:"modified"`
	Created  time.Time `json:"created"`

	Hidden      bool   `json:"hidden,omitempty"` // hidden or system attribute set
	DoubleExt   bool   `json:"double_extension,omitempty"`
	RTLO        bool   `json:"rtlo_in_name,omitempty"` // right-to-left override used to fake the extension
	DisguisedPE bool   `json:"disguised_pe,omitempty"` // program code behind a document/media extension
	FromURL     string `json:"downloaded_from,omitempty"`
	FromZone    int    `json:"download_zone,omitempty"` // Mark-of-the-Web zone (3 = internet)

	Sig winsys.Signature `json:"signature"`
	Loc winsys.Location  `json:"location"`

	// Head is the beginning of a script, kept for content inspection.
	Head string `json:"-"`
}

var (
	execExt   = map[string]bool{".exe": true, ".dll": true, ".scr": true, ".com": true, ".cpl": true, ".pif": true, ".sys": true, ".ocx": true, ".msi": true}
	scriptExt = map[string]bool{".bat": true, ".cmd": true, ".ps1": true, ".psm1": true, ".vbs": true, ".vbe": true, ".js": true, ".jse": true, ".wsf": true, ".wsh": true, ".hta": true, ".sct": true}
	decoyExt  = map[string]bool{".txt": true, ".log": true, ".jpg": true, ".jpeg": true, ".png": true, ".gif": true, ".bmp": true, ".ico": true, ".pdf": true, ".doc": true, ".docx": true, ".xls": true, ".xlsx": true, ".ppt": true, ".pptx": true, ".rtf": true, ".mp3": true, ".mp4": true, ".csv": true, ".xml": true, ".json": true}

	doubleExtRe = regexp.MustCompile(`(?i)\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp[34]|avi|zip|rar|csv)\s*\.(exe|scr|com|pif|bat|cmd|vbs|vbe|js|jse|lnk|hta|ps1|wsf|cpl)$`)
	skipDirs    = map[string]bool{"node_modules": true, ".git": true, "__pycache__": true}
)

const (
	maxEntriesPerRoot = 40000
	fileAttrHidden    = 0x2
	fileAttrSystem    = 0x4
	fileAttrReparse   = 0x400
)

type fileScanner struct {
	out    []FileEntry
	budget int
}

func collectFiles(s *Snapshot) string {
	fs := &fileScanner{}
	users := winsys.UsersDir()

	fs.scan(filepath.Join(winsys.SystemRoot(), "Temp"), "Windows Temp", "SYSTEM", 3)
	fs.scan(filepath.Join(users, "Public"), "Public", "", 3)
	fs.scan(os.Getenv("ProgramData"), "ProgramData", "", 1)

	if entries, err := os.ReadDir(users); err == nil {
		for _, e := range entries {
			name := e.Name()
			switch strings.ToLower(name) {
			case "public", "default", "default user", "all users":
				continue
			}
			if !e.IsDir() {
				continue
			}
			home := filepath.Join(users, name)
			fs.scan(filepath.Join(home, `AppData\Local\Temp`), "Temp", name, 4)
			fs.scan(filepath.Join(home, "Downloads"), "Downloads", name, 2)
			fs.scan(filepath.Join(home, `AppData\Roaming`), "AppData", name, 1)
			fs.scan(filepath.Join(home, `AppData\Local`), "AppData", name, 0)
			fs.scan(home, "profile root", name, 0)
		}
	}

	// Signatures: embedded only. Catalog-signed files are not expected in
	// drop folders, and hashing thousands of temp files would be slow.
	var paths []string
	for _, f := range fs.out {
		if f.Kind == "executable" || f.Kind == "disguised" {
			paths = append(paths, f.Path)
		}
	}
	winsys.VerifyMany(paths, false)
	unsigned := 0
	for i := range fs.out {
		f := &fs.out[i]
		if f.Kind == "executable" || f.Kind == "disguised" {
			f.Sig = winsys.VerifyEmbedded(f.Path)
			if f.Sig.Unsigned() {
				unsigned++
			}
		}
	}
	s.Files = fs.out
	return fmt.Sprintf("%d programs and scripts, %d unsigned", len(fs.out), unsigned)
}

func (fs *fileScanner) scan(root, zone, owner string, depth int) {
	if root == "" {
		return
	}
	fs.budget = maxEntriesPerRoot
	fs.walk(root, zone, owner, depth)
}

func (fs *fileScanner) walk(dir, zone, owner string, depth int) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if fs.budget <= 0 {
			return
		}
		fs.budget--
		full := filepath.Join(dir, e.Name())

		if e.IsDir() {
			if depth > 0 && !skipDirs[strings.ToLower(e.Name())] && e.Type()&os.ModeSymlink == 0 {
				fs.walk(full, zone, owner, depth-1)
			}
			continue
		}
		ext := strings.ToLower(filepath.Ext(e.Name()))
		kind := ""
		switch {
		case execExt[ext]:
			kind = "executable"
		case scriptExt[ext]:
			kind = "script"
		case ext == ".lnk":
			kind = "shortcut"
		case decoyExt[ext]:
			kind = "decoy?"
		default:
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		f := FileEntry{
			Path: full, Name: e.Name(), Kind: kind, Zone: zone, Owner: owner,
			Size: info.Size(), Modified: info.ModTime(), Loc: winsys.Classify(full),
		}
		if d, ok := info.Sys().(*syscall.Win32FileAttributeData); ok {
			f.Created = time.Unix(0, d.CreationTime.Nanoseconds())
			f.Hidden = d.FileAttributes&(fileAttrHidden|fileAttrSystem) != 0
			if d.FileAttributes&fileAttrReparse != 0 {
				continue
			}
		}

		if kind == "decoy?" {
			// Only keep it when the "document" is really a program.
			if f.Size < 1024 || !startsWithMZ(full) {
				continue
			}
			f.Kind, f.DisguisedPE = "disguised", true
		}
		// Shortcuts are only interesting where nobody keeps shortcuts.
		if kind == "shortcut" && zone != "Temp" && zone != "Windows Temp" && zone != "Public" && zone != "Downloads" {
			continue
		}

		f.DoubleExt = doubleExtRe.MatchString(e.Name())
		f.RTLO = strings.ContainsRune(e.Name(), '‮')
		f.FromZone, f.FromURL = markOfTheWeb(full)
		if kind == "script" && f.Size <= 4<<20 {
			f.Head = readHead(full, 48*1024)
		}
		fs.out = append(fs.out, f)
	}
}

func startsWithMZ(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	var magic [2]byte
	if _, err := io.ReadFull(f, magic[:]); err != nil {
		return false
	}
	return magic[0] == 'M' && magic[1] == 'Z'
}

// markOfTheWeb reads the Zone.Identifier alternate data stream that browsers
// and mail clients attach to downloaded files.
func markOfTheWeb(path string) (zone int, url string) {
	data, err := os.ReadFile(path + ":Zone.Identifier")
	if err != nil || len(data) > 8192 {
		return 0, ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "ZoneId="):
			zone, _ = strconv.Atoi(strings.TrimPrefix(line, "ZoneId="))
		case strings.HasPrefix(line, "HostUrl="):
			url = strings.TrimPrefix(line, "HostUrl=")
		case strings.HasPrefix(line, "ReferrerUrl=") && url == "":
			url = strings.TrimPrefix(line, "ReferrerUrl=")
		}
	}
	return zone, url
}

// readHead returns the first n bytes of a text file as UTF-8, decoding
// UTF-16 (the default encoding of many PowerShell scripts).
func readHead(path string, n int) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, n)
	read, _ := io.ReadFull(f, buf)
	buf = buf[:read]
	if len(buf) >= 2 && buf[0] == 0xFF && buf[1] == 0xFE {
		u := make([]uint16, 0, len(buf)/2)
		for i := 2; i+1 < len(buf); i += 2 {
			u = append(u, uint16(buf[i])|uint16(buf[i+1])<<8)
		}
		return string(utf16.Decode(u))
	}
	return string(buf)
}
