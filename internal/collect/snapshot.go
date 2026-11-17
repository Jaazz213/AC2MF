// Package collect gathers facts about the machine. Collectors only observe
// and describe; deciding what is suspicious is the job of package analyze.
package collect

import (
	"fmt"
	"runtime"
	"time"

	"github.com/go-ole/go-ole"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// Snapshot is everything AC2MF learned about the machine in one run.
type Snapshot struct {
	Taken    time.Time `json:"taken"`
	Elevated bool      `json:"elevated"`

	System      SystemInfo      `json:"system"`
	Security    SecurityPosture `json:"security"`
	Users       []UserAccount   `json:"users"`
	Processes   []Process       `json:"processes"`
	Connections []Connection    `json:"connections"`
	Services    []Service       `json:"services"`
	Tasks       []Task          `json:"tasks"`
	Autoruns    []Autorun       `json:"autoruns"`
	Files       []FileEntry     `json:"files"`
	DNS         []winsys.DNSCacheRecord `json:"dns_cache"`

	// Notes records collection problems (access denied, API failures) so the
	// report can be honest about what it could not see.
	Notes []string `json:"notes,omitempty"`
}

func (s *Snapshot) note(format string, a ...interface{}) {
	s.Notes = append(s.Notes, fmt.Sprintf(format, a...))
}

// Options tunes what gets collected.
type Options struct {
	NetworkOnly bool // only what the connection table needs (-netstat)
}

// Reporter receives progress as each collector starts and finishes.
type Reporter interface {
	StepStart(name string)
	StepDone(name, summary string, took time.Duration)
}

type step struct {
	name string
	run  func(*Snapshot) string
}

// Collect runs every collector in order and returns the resulting snapshot.
func Collect(opt Options, rep Reporter) *Snapshot {
	// COM (Task Scheduler, WMI, shell links) is used by several collectors;
	// they all run on this goroutine, so pin it and initialise COM once.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := ole.CoInitializeEx(0, ole.COINIT_MULTITHREADED); err == nil {
		defer ole.CoUninitialize()
	}

	snap := &Snapshot{Taken: time.Now(), Elevated: winsys.IsElevated()}
	if snap.Elevated {
		winsys.EnableDebugPrivilege()
	}

	steps := []step{
		{"System", collectSystem},
		{"Security posture", collectSecurity},
		{"User accounts", collectUsers},
		{"Services & drivers", collectServices},
		{"Processes", collectProcesses},
		{"DNS cache", collectDNS},
		{"Network", collectNetwork},
		{"Scheduled tasks", collectTasks},
		{"Autostart entries", collectAutoruns},
		{"Drop folders", collectFiles},
	}
	if opt.NetworkOnly {
		steps = []step{
			{"Services & drivers", collectServices},
			{"Processes", collectProcesses},
			{"DNS cache", collectDNS},
			{"Network", collectNetwork},
		}
	}

	for _, st := range steps {
		rep.StepStart(st.name)
		start := time.Now()
		summary := runStep(snap, st)
		rep.StepDone(st.name, summary, time.Since(start))
	}
	return snap
}

// runStep shields the scan from a single misbehaving collector: a panic in
// one module is recorded and the remaining modules still run.
func runStep(snap *Snapshot, st step) (summary string) {
	defer func() {
		if r := recover(); r != nil {
			snap.note("%s: collector failed: %v", st.name, r)
			summary = "failed (see notes)"
		}
	}()
	return st.run(snap)
}

func collectDNS(s *Snapshot) string {
	s.DNS = winsys.DNSCache()
	return fmt.Sprintf("%d cached names", len(s.DNS))
}

func plural(n int, one, many string) string {
	if n == 1 {
		return fmt.Sprintf("%d %s", n, one)
	}
	return fmt.Sprintf("%d %s", n, many)
}
