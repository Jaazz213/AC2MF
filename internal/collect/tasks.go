package collect

import (
	"encoding/xml"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// Task is a scheduled task.
type Task struct {
	Path        string       `json:"path"`
	Name        string       `json:"name"`
	Enabled     bool         `json:"enabled"`
	Hidden      bool         `json:"hidden"`
	State       string       `json:"state"`
	Author      string       `json:"author,omitempty"`
	Description string       `json:"description,omitempty"`
	Created     time.Time    `json:"created"`
	RunAs       string       `json:"run_as,omitempty"`
	Highest     bool         `json:"highest_privileges"`
	Triggers    []string     `json:"triggers,omitempty"`
	Actions     []TaskAction `json:"actions,omitempty"`
	LastRun     time.Time    `json:"last_run"`
	NextRun     time.Time    `json:"next_run"`

	// NoSecurityDescriptor: the registry entry has had its SD value removed,
	// which hides the task from the Task Scheduler UI and schtasks while it
	// keeps running (the "Tarrask" technique).
	NoSecurityDescriptor bool `json:"no_security_descriptor,omitempty"`
	// RegistryOnly: present in the registry task cache but not returned by
	// the Task Scheduler API.
	RegistryOnly bool `json:"registry_only,omitempty"`
}

// TaskAction is one thing a task does when it fires.
type TaskAction struct {
	Kind    string `json:"kind"` // "exec" or "com"
	Command string `json:"command,omitempty"`
	Args    string `json:"args,omitempty"`
	ClassID string `json:"class_id,omitempty"`

	Target string           `json:"target,omitempty"`
	Sig    winsys.Signature `json:"signature"`
	Loc    winsys.Location  `json:"location"`
	Gone   bool             `json:"target_missing,omitempty"`
}

type taskXML struct {
	Reg struct {
		Date        string `xml:"Date"`
		Author      string `xml:"Author"`
		Description string `xml:"Description"`
	} `xml:"RegistrationInfo"`
	Triggers struct {
		Items []struct {
			XMLName xml.Name
		} `xml:",any"`
	} `xml:"Triggers"`
	Principals struct {
		Principal []struct {
			UserID   string `xml:"UserId"`
			GroupID  string `xml:"GroupId"`
			RunLevel string `xml:"RunLevel"`
		} `xml:"Principal"`
	} `xml:"Principals"`
	Settings struct {
		Hidden string `xml:"Hidden"`
	} `xml:"Settings"`
	Actions struct {
		Exec []struct {
			Command   string `xml:"Command"`
			Arguments string `xml:"Arguments"`
		} `xml:"Exec"`
		Com []struct {
			ClassID string `xml:"ClassId"`
		} `xml:"ComHandler"`
	} `xml:"Actions"`
}

var triggerNames = map[string]string{
	"LogonTrigger":              "at logon",
	"BootTrigger":               "at boot",
	"TimeTrigger":               "at a set time",
	"CalendarTrigger":           "on a schedule",
	"IdleTrigger":               "when idle",
	"EventTrigger":              "on an event",
	"RegistrationTrigger":       "when registered",
	"SessionStateChangeTrigger": "on session change",
	"WnfStateChangeTrigger":     "on a system state change",
}

var taskStates = map[int64]string{0: "unknown", 1: "disabled", 2: "queued", 3: "ready", 4: "running"}

func collectTasks(s *Snapshot) string {
	unk, err := oleutil.CreateObject("Schedule.Service")
	if err != nil {
		s.note("Task Scheduler could not be reached (%v)", err)
		return "unavailable"
	}
	defer unk.Release()
	svc, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		s.note("Task Scheduler could not be reached (%v)", err)
		return "unavailable"
	}
	defer svc.Release()
	if _, err := oleutil.CallMethod(svc, "Connect"); err != nil {
		s.note("Task Scheduler connection failed (%v)", err)
		return "unavailable"
	}

	if root := comCall(svc, "GetFolder", `\`); root != nil {
		walkTaskFolder(root, &s.Tasks)
		root.Release()
	}

	// Cross-check against the registry cache for tasks hidden from the API.
	known := make(map[string]int, len(s.Tasks))
	for i, t := range s.Tasks {
		known[lower(t.Path)] = i
	}
	stealth := 0
	for path, hasSD := range registryTasks() {
		i, listed := known[lower(path)]
		switch {
		case listed && !hasSD:
			s.Tasks[i].NoSecurityDescriptor = true
			stealth++
		case !listed && (!hasSD || s.Elevated):
			// Without elevation the API legitimately hides tasks we may not
			// read, so "registry only" is meaningful only when elevated.
			s.Tasks = append(s.Tasks, Task{
				Path: path, Name: lastSegment(path), Enabled: true, State: "unknown",
				NoSecurityDescriptor: !hasSD, RegistryOnly: true,
			})
			stealth++
		}
	}

	var paths []string
	for _, t := range s.Tasks {
		for _, a := range t.Actions {
			paths = append(paths, a.Target)
		}
	}
	winsys.VerifyMany(paths, true)
	for i := range s.Tasks {
		for j := range s.Tasks[i].Actions {
			a := &s.Tasks[i].Actions[j]
			if a.Target == "" {
				continue
			}
			a.Sig = winsys.Verify(a.Target)
			a.Loc = winsys.Classify(a.Target)
			a.Gone = winsys.Gone(a.Target)
		}
	}

	if stealth > 0 {
		return fmt.Sprintf("%d tasks, %d hidden from the scheduler API", len(s.Tasks), stealth)
	}
	return fmt.Sprintf("%d tasks", len(s.Tasks))
}

func walkTaskFolder(folder *ole.IDispatch, out *[]Task) {
	const includeHidden = 1
	if tasks := comCall(folder, "GetTasks", includeHidden); tasks != nil {
		oleutil.ForEach(tasks, func(v *ole.VARIANT) error {
			t := v.ToIDispatch()
			if t == nil {
				return nil
			}
			defer t.Release()
			*out = append(*out, readTask(t))
			return nil
		})
		tasks.Release()
	}
	if subs := comCall(folder, "GetFolders", 0); subs != nil {
		oleutil.ForEach(subs, func(v *ole.VARIANT) error {
			sub := v.ToIDispatch()
			if sub == nil {
				return nil
			}
			defer sub.Release()
			walkTaskFolder(sub, out)
			return nil
		})
		subs.Release()
	}
}

func readTask(t *ole.IDispatch) Task {
	task := Task{
		Path:    comString(t, "Path"),
		Name:    comString(t, "Name"),
		Enabled: comBool(t, "Enabled"),
		State:   taskStates[comInt(t, "State")],
		LastRun: comTime(t, "LastRunTime"),
		NextRun: comTime(t, "NextRunTime"),
	}

	var def taskXML
	dec := xml.NewDecoder(strings.NewReader(comString(t, "Xml")))
	// The definition declares UTF-16 but arrives as a Go (UTF-8) string.
	dec.CharsetReader = func(_ string, in io.Reader) (io.Reader, error) { return in, nil }
	if err := dec.Decode(&def); err != nil {
		return task
	}

	task.Author = def.Reg.Author
	task.Description = def.Reg.Description
	task.Hidden = strings.EqualFold(strings.TrimSpace(def.Settings.Hidden), "true")
	for _, layout := range []string{"2006-01-02T15:04:05.9999999", "2006-01-02T15:04:05", time.RFC3339Nano} {
		if when, err := time.ParseInLocation(layout, strings.TrimSpace(def.Reg.Date), time.Local); err == nil {
			task.Created = when
			break
		}
	}
	for _, p := range def.Principals.Principal {
		id := p.UserID
		if id == "" {
			id = p.GroupID
		}
		task.RunAs = accountName(id)
		task.Highest = strings.EqualFold(p.RunLevel, "HighestAvailable")
	}
	seen := map[string]bool{}
	for _, tr := range def.Triggers.Items {
		name := triggerNames[tr.XMLName.Local]
		if name == "" {
			name = tr.XMLName.Local
		}
		if !seen[name] {
			seen[name] = true
			task.Triggers = append(task.Triggers, name)
		}
	}
	for _, e := range def.Actions.Exec {
		a := TaskAction{Kind: "exec", Command: strings.TrimSpace(e.Command), Args: strings.TrimSpace(e.Arguments)}
		a.Target = winsys.NormalizePath(a.Command)
		if !winsys.FileExists(a.Target) {
			// Some tasks put the whole command line in <Command>.
			if exe, rest := winsys.SplitCommandLine(a.Command); winsys.FileExists(exe) {
				a.Target = exe
				a.Args = strings.TrimSpace(rest + " " + a.Args)
			}
		}
		task.Actions = append(task.Actions, a)
	}
	for _, c := range def.Actions.Com {
		task.Actions = append(task.Actions, TaskAction{Kind: "com", ClassID: c.ClassID})
	}
	return task
}

// accountName turns a SID string into DOMAIN\name when possible.
func accountName(id string) string {
	if !strings.HasPrefix(strings.ToUpper(id), "S-1-") {
		return id
	}
	sid, err := windows.StringToSid(id)
	if err != nil {
		return id
	}
	account, domain, _, err := sid.LookupAccount("")
	if err != nil {
		return id
	}
	if domain == "" {
		return account
	}
	return domain + `\` + account
}

// registryTasks walks the scheduler's registry cache and reports, for every
// task found there, whether it still has a security descriptor.
func registryTasks() map[string]bool {
	const tree = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree`
	out := make(map[string]bool)
	var walk func(rel string, depth int)
	walk = func(rel string, depth int) {
		if depth > 12 {
			return
		}
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, tree+rel, registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			return
		}
		defer k.Close()
		if _, _, err := k.GetStringValue("Id"); err == nil {
			_, _, sdErr := k.GetValue("SD", nil)
			out[rel] = sdErr != registry.ErrNotExist
		}
		subs, _ := k.ReadSubKeyNames(-1)
		for _, sub := range subs {
			walk(rel+`\`+sub, depth+1)
		}
	}
	walk("", 0)
	return out
}

func lastSegment(path string) string {
	if i := strings.LastIndexByte(path, '\\'); i >= 0 {
		return path[i+1:]
	}
	return path
}
