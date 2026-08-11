package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// TempFileInfo holds metadata about a suspicious file found in a temp directory.
type TempFileInfo struct {
	Path       string
	Name       string
	Extension  string
	SizeBytes  int64
	SizeMB     float64
	ModTime    time.Time
	DaysOld    int
	IsRecent   bool // < 7 days
	IsLarge    bool // > 50 MB
	Owner      string // which user's temp dir

	// Analysis
	Signature    SignatureStatus
	IsExecutable bool
	IsScript     bool
	IsArchive    bool
	IsShortcut   bool
	Score        int
}

// ScanTempDirectories scans Windows and per-user temp folders for suspicious
// files (executables, scripts, shortcuts, archives).
func ScanTempDirectories(progress func(string)) []TempFileInfo {
	var results []TempFileInfo

	// System temp
	progress("Scanning Windows Temp directory...")
	results = append(results, scanDir(`C:\Windows\Temp`, "SYSTEM", 3, progress)...)

	// Per-user temps
	progress("Scanning per-user Temp directories...")
	userDirs, err := os.ReadDir(`C:\Users`)
	if err == nil {
		for _, u := range userDirs {
			if !u.IsDir() {
				continue
			}
			name := u.Name()
			lower := strings.ToLower(name)
			if lower == "public" || lower == "default" || lower == "default user" || lower == "all users" || strings.HasPrefix(name, ".") {
				continue
			}
			tempDir := filepath.Join(`C:\Users`, name, `AppData\Local\Temp`)
			if _, err := os.Stat(tempDir); err == nil {
				progress(fmt.Sprintf("  Scanning %s's Temp...", name))
				results = append(results, scanDir(tempDir, name, 3, progress)...)
			}
		}
	}

	// Also check Downloads for risky files (common malware landing zone)
	progress("Scanning Downloads folders for risky files...")
	for _, u := range userDirs {
		if !u.IsDir() {
			continue
		}
		name := u.Name()
		lower := strings.ToLower(name)
		if lower == "public" || lower == "default" || lower == "default user" || lower == "all users" || strings.HasPrefix(name, ".") {
			continue
		}
		dlDir := filepath.Join(`C:\Users`, name, `Downloads`)
		if _, err := os.Stat(dlDir); err == nil {
			results = append(results, scanDir(dlDir, name+"(Downloads)", 1, progress)...)
		}
	}

	progress(fmt.Sprintf("  Found %d suspicious temp/download files", len(results)))
	return results
}

func scanDir(root, owner string, maxDepth int, progress func(string)) []TempFileInfo {
	var results []TempFileInfo
	now := time.Now()

	walkDir(root, owner, 0, maxDepth, now, &results)

	return results
}

func walkDir(dir, owner string, depth, maxDepth int, now time.Time, results *[]TempFileInfo) {
	if depth > maxDepth {
		return
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}

	for _, e := range entries {
		fullPath := filepath.Join(dir, e.Name())

		if e.IsDir() {
			walkDir(fullPath, owner, depth+1, maxDepth, now, results)
			continue
		}

		ext := strings.ToLower(filepath.Ext(e.Name()))

		// Only interested in suspicious extensions
		if !IsSuspiciousTempExtension(ext) {
			continue
		}

		info, err := e.Info()
		if err != nil {
			continue
		}

		fi := TempFileInfo{
			Path:      fullPath,
			Name:      e.Name(),
			Extension: ext,
			SizeBytes: info.Size(),
			SizeMB:    float64(info.Size()) / (1024 * 1024),
			ModTime:   info.ModTime(),
			DaysOld:   int(now.Sub(info.ModTime()).Hours() / 24),
			Owner:     owner,
		}

		fi.IsRecent = fi.DaysOld < 7
		fi.IsLarge = fi.SizeMB > 50

		// Classify
		switch ext {
		case ".exe", ".dll", ".scr", ".com", ".cpl", ".pif", ".msi", ".msp":
			fi.IsExecutable = true
		case ".bat", ".cmd", ".ps1", ".vbs", ".vbe", ".wsf", ".wsh", ".hta", ".sct":
			fi.IsScript = true
		case ".7z", ".zip", ".rar", ".cab":
			fi.IsArchive = true
		case ".lnk":
			fi.IsShortcut = true
		case ".inf", ".reg", ".rgs":
			fi.IsScript = true // treat as script-like
		}

		// Signature check for executables
		if fi.IsExecutable {
			fi.Signature = VerifySignature(fullPath)
		}

		*results = append(*results, fi)
	}
}
