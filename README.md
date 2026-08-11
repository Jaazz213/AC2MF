<p align="center">
  <img src="docs/banner.png" alt="AC2MF Banner" width="600">
</p>

<h1 align="center">AC2MF — Active C2 Malware Finder</h1>

<p align="center">
  <strong>Offline situational-awareness scanner for Windows</strong><br>
  Surfaces what hides between the lines — processes, persistence, services, and network anomalies.
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-0.1.0--alpha-blue" alt="Version">
  <img src="https://img.shields.io/badge/platform-Windows-0078D6?logo=windows" alt="Platform">
  <img src="https://img.shields.io/badge/language-Go-00ADD8?logo=go" alt="Language">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/offline-100%25-brightgreen" alt="Offline">
</p>

---

## What is AC2MF?

AC2MF is a **portable, offline** Windows scanner designed to detect signs of **active Command & Control (C2) malware** — the kind that's already running on your machine, hiding in memory, using persistence to survive reboots, and communicating with remote servers.

> **⚠️ This is NOT an antivirus.** AC2MF provides situational awareness. It tells you what's suspicious so you can investigate further.

### Why AC2MF?

Traditional antivirus relies on signature databases and cloud lookups. AC2MF takes a different approach:

- **🔍 Behavioral analysis** — Looks at *what processes are doing*, not what they're named
- **🔗 Cross-module correlation** — Connects the dots between processes, persistence, tasks, and network activity
- **📡 Injection detection** — Flags trusted system processes (explorer.exe, lsass.exe) that suddenly have remote connections
- **🧠 Narrative reports** — Explains findings in plain language, not just alert codes
- **✈️ Fully offline** — No internet needed. Safe for sandboxes and quarantined machines

---

## What It Scans

| Module | What It Checks |
|--------|---------------|
| **Processes** | Running executables, their location (Temp? AppData?), digital signatures, memory usage, typosquatting detection |
| **Network** | TCP connections per process, flags system processes with unexpected remote connections (injection indicator) |
| **Scheduled Tasks** | Non-Microsoft tasks, especially those pointing to Temp folders or running scripts |
| **Persistence** | Registry Run keys, IFEO debuggers, AppInit_DLLs, Winlogon modifications, WMI subscriptions |
| **Services** | Windows services running from unusual locations, unsigned binaries |
| **Temp Files** | Executables, scripts, and archives in Temp/Downloads directories |

### Correlation Engine

AC2MF doesn't just scan — it **correlates**. Some examples:

- **Process in Temp** + **Scheduled task referencing it** → Score ×2.0 (persistence + execution = C2 pattern)
- **Unsigned process** + **Registry persistence** → Score ×1.5
- **System process** + **Remote connections** → Injection detection (very high severity)
- **Script in Temp** + **Persistence entry** → Score ×2.5

---

## Quick Start

### Download & Run

1. Download `AC2MF.exe` from the [Releases](https://github.com/Jaazz213/AC2MF/releases) page
2. **Right-click → Run as Administrator** (recommended for full scan coverage)
3. Wait for the scan to complete (~30-60 seconds)
4. Review the findings
5. Optionally save the report as a `.txt` file

### Build from Source

```bash
git clone https://github.com/Jaazz213/AC2MF.git
cd AC2MF
go build -o AC2MF.exe .
```

> Requires Go 1.21+ and Windows (uses Windows-specific APIs).

---

## Understanding the Output

### Severity Levels

| Level | Score | Meaning |
|-------|-------|---------|
| 🔴 **CRITICAL** | >90 | Strong indicators of active malware. Investigate immediately. |
| 🟠 **HIGH** | 61-90 | Suspicious activity that warrants investigation. |
| 🟡 **MEDIUM** | 31-60 | Unusual but could be legitimate. Worth a look. |
| 🟢 **LOW** | 0-30 | Normal activity. Not reported unless relevant. |

### Unsigned Software Inventory

Programs without digital signatures that are running from **legitimate locations** (like `AppData\Local\Programs`) are listed in an informational inventory — not as threat findings. Many popular apps (Electron-based tools, indie software) are unsigned but perfectly safe.

### Finding Anatomy

Each finding includes:
- **Narrative** — A human-readable description of what was found
- **Details** — Key-value pairs with technical specifics
- **Why This Matters** — Context on why this pattern is suspicious
- **Suggestion** — Actionable next steps (for High/Critical findings)

---

## Project Structure

```
AC2MF/
├── main.go           # Entry point, scan orchestration, CLI flow
├── processes.go      # Process enumeration via Windows API snapshots
├── network.go        # TCP connection enumeration, injection detection
├── tasks.go          # Scheduled task scanning via COM/OLE
├── persistence.go    # Registry persistence mechanism scanning
├── services.go       # Windows Service Control Manager analysis
├── tempfiles.go      # Temp/Downloads directory scanning
├── sysinfo.go        # System information collection (OS, users, VM detection)
├── signature.go      # Authenticode digital signature verification
├── whitelist.go      # Trusted processes, paths, task prefixes, typosquat targets
├── scoring.go        # Scoring engine, cross-module correlation, finding builders
├── output.go         # Console rendering, text export, progress display
├── docs/             # Documentation and assets
├── go.mod
└── go.sum
```

---

## Roadmap

- [x] Process analysis with signature verification
- [x] Network connection mapping with injection detection
- [x] Scheduled task analysis
- [x] Persistence mechanism scanning (Registry, WMI, IFEO, AppInit, Winlogon)
- [x] Service analysis
- [x] Cross-module correlation engine
- [x] Narrative report generation
- [x] Unsigned software inventory (informational)
- [ ] DLL injection detection (loaded DLL analysis)
- [ ] YARA rule integration
- [ ] ETW-based runtime behavior monitoring
- [ ] HTML report export
- [ ] Remote IP reputation lookup (optional, opt-in)

---

## Disclaimer

This tool is provided for **educational and defensive security purposes only**. AC2MF does not modify, delete, or quarantine any files. It only reads system state and reports findings.

The author is not responsible for any misuse of this tool. Always verify findings before taking action on a production system.

---

## License

[MIT License](LICENSE) — Free to use, modify, and distribute.

---

<p align="center">
  <strong>AC2MF by Jazz</strong><br>
  <em>Built for the paranoid. Designed for the practical.</em>
</p>
