package collect

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"

	"github.com/Jaazz213/AC2MF/internal/winsys"
)

// UserAccount describes a local account or a profile present on the machine.
type UserAccount struct {
	Name     string `json:"name"`
	FullName string `json:"full_name,omitempty"`
	Comment  string `json:"comment,omitempty"`
	SID      string `json:"sid,omitempty"`
	Kind     string `json:"kind"`               // "local" or "profile" (domain / Microsoft / deleted account)
	BuiltIn  string `json:"built_in,omitempty"` // Administrator, Guest, ...

	Admin                bool `json:"admin"`
	Enabled              bool `json:"enabled"`
	Locked               bool `json:"locked,omitempty"`
	PasswordRequired     bool `json:"password_required"`
	PasswordNeverExpires bool `json:"password_never_expires"`
	HiddenFromLogon      bool `json:"hidden_from_logon_screen"`
	LoggedOn             bool `json:"logged_on"`

	PasswordSet    time.Time `json:"password_set"`
	LastLogon      time.Time `json:"last_logon"`
	Logons         uint32    `json:"logon_count"`
	ProfilePath    string    `json:"profile_path,omitempty"`
	ProfileCreated time.Time `json:"profile_created"`
}

// USER_INFO_2 (lmaccess.h).
type userInfo2 struct {
	Name         *uint16
	Password     *uint16
	PasswordAge  uint32
	Priv         uint32
	HomeDir      *uint16
	Comment      *uint16
	Flags        uint32
	ScriptPath   *uint16
	AuthFlags    uint32
	FullName     *uint16
	UsrComment   *uint16
	Parms        *uint16
	Workstations *uint16
	LastLogon    uint32
	LastLogoff   uint32
	AcctExpires  uint32
	MaxStorage   uint32
	UnitsPerWeek uint32
	LogonHours   *byte
	BadPwCount   uint32
	NumLogons    uint32
	LogonServer  *uint16
	CountryCode  uint32
	CodePage     uint32
}

const (
	filterNormalAccount = 0x0002
	maxPreferredLength  = 0xFFFFFFFF
	userPrivAdmin       = 2

	ufAccountDisable   = 0x0002
	ufLockout          = 0x0010
	ufPasswdNotReqd    = 0x0020
	ufDontExpirePasswd = 0x10000
)

var builtInRIDs = map[string]string{
	"500": "Administrator",
	"501": "Guest",
	"503": "DefaultAccount",
	"504": "WDAGUtilityAccount",
}

func collectUsers(s *Snapshot) string {
	users, err := localAccounts()
	if err != nil {
		s.note("local accounts could not be enumerated (%v)", err)
	}

	// Attach profiles, and add profiles that have no local account behind
	// them (domain users, Microsoft accounts, or accounts since deleted).
	const profileList = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`
	for _, sid := range regSubKeys(registry.LOCAL_MACHINE, profileList) {
		if !strings.HasPrefix(sid, "S-1-5-21-") && !strings.HasPrefix(sid, "S-1-12-1-") {
			continue
		}
		path := winsys.Expand(regString(registry.LOCAL_MACHINE, profileList+`\`+sid, "ProfileImagePath"))
		created := time.Time{}
		if st, err := os.Stat(path); err == nil {
			if d, ok := st.Sys().(*syscall.Win32FileAttributeData); ok {
				created = time.Unix(0, d.CreationTime.Nanoseconds())
			}
		}
		matched := false
		for i := range users {
			if strings.EqualFold(users[i].SID, sid) {
				users[i].ProfilePath, users[i].ProfileCreated = path, created
				matched = true
				break
			}
		}
		if matched {
			continue
		}
		name := sid
		if parsed, err := windows.StringToSid(sid); err == nil {
			if acct, dom, _, err := parsed.LookupAccount(""); err == nil {
				name = dom + `\` + acct
			}
		}
		users = append(users, UserAccount{
			Name: name, SID: sid, Kind: "profile", Enabled: true, PasswordRequired: true,
			ProfilePath: path, ProfileCreated: created,
		})
	}

	// Accounts hidden from the sign-in screen: a classic way to keep a
	// backdoor account out of sight.
	const hidden = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList`
	for _, name := range regValueNames(registry.LOCAL_MACHINE, hidden) {
		if v, ok := regDWORD(registry.LOCAL_MACHINE, hidden, name); ok && v == 0 {
			for i := range users {
				if strings.EqualFold(users[i].Name, name) {
					users[i].HiddenFromLogon = true
				}
			}
		}
	}

	s.Users = users
	admins := 0
	for _, u := range users {
		if u.Admin && u.Enabled {
			admins++
		}
	}
	return fmt.Sprintf("%s, %d with admin rights", plural(len(users), "account", "accounts"), admins)
}

func localAccounts() ([]UserAccount, error) {
	var out []UserAccount
	var resume uint32
	for {
		var buf *byte
		var read, total uint32
		err := windows.NetUserEnum(nil, 2, filterNormalAccount, &buf, maxPreferredLength, &read, &total, &resume)
		if err != nil && err != windows.ERROR_MORE_DATA {
			return out, err
		}
		if buf != nil {
			for _, e := range unsafe.Slice((*userInfo2)(unsafe.Pointer(buf)), read) {
				u := UserAccount{
					Name:                 windows.UTF16PtrToString(e.Name),
					FullName:             windows.UTF16PtrToString(e.FullName),
					Comment:              windows.UTF16PtrToString(e.Comment),
					Kind:                 "local",
					Admin:                e.Priv == userPrivAdmin,
					Enabled:              e.Flags&ufAccountDisable == 0,
					Locked:               e.Flags&ufLockout != 0,
					PasswordRequired:     e.Flags&ufPasswdNotReqd == 0,
					PasswordNeverExpires: e.Flags&ufDontExpirePasswd != 0,
					Logons:               e.NumLogons,
				}
				if e.LastLogon != 0 {
					u.LastLogon = time.Unix(int64(e.LastLogon), 0)
				}
				if e.PasswordAge != 0 {
					u.PasswordSet = time.Now().Add(-time.Duration(e.PasswordAge) * time.Second).Truncate(time.Minute)
				}
				if sid, _, _, err := windows.LookupSID("", u.Name); err == nil {
					u.SID = sid.String()
					if i := strings.LastIndexByte(u.SID, '-'); i >= 0 {
						rid := u.SID[i+1:]
						u.BuiltIn = builtInRIDs[rid]
						if n, err := strconv.Atoi(rid); err == nil && n >= 1000 {
							u.BuiltIn = ""
						}
					}
				}
				out = append(out, u)
			}
			windows.NetApiBufferFree(buf)
		}
		if err == nil {
			return out, nil
		}
	}
}
