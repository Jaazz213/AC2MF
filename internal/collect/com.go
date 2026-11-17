package collect

import (
	"fmt"
	"time"

	"github.com/go-ole/go-ole"
	"github.com/go-ole/go-ole/oleutil"
)

// wmiQuery runs a WQL query through the WMI scripting API and hands each
// result object to fn. COM must already be initialised on this thread.
func wmiQuery(namespace, query string, fn func(item *ole.IDispatch)) error {
	unk, err := oleutil.CreateObject("WbemScripting.SWbemLocator")
	if err != nil {
		return err
	}
	defer unk.Release()
	locator, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return err
	}
	defer locator.Release()

	svcV, err := oleutil.CallMethod(locator, "ConnectServer", ".", namespace)
	if err != nil {
		return err
	}
	svc := svcV.ToIDispatch()
	defer svc.Release()

	resV, err := oleutil.CallMethod(svc, "ExecQuery", query)
	if err != nil {
		return err
	}
	res := resV.ToIDispatch()
	defer res.Release()

	return oleutil.ForEach(res, func(v *ole.VARIANT) error {
		item := v.ToIDispatch()
		if item == nil {
			return nil
		}
		defer item.Release()
		fn(item)
		return nil
	})
}

// comValue reads a property and returns its Go value (nil on any failure).
func comValue(d *ole.IDispatch, name string) interface{} {
	v, err := oleutil.GetProperty(d, name)
	if err != nil || v == nil {
		return nil
	}
	defer v.Clear()
	return v.Value()
}

func comString(d *ole.IDispatch, name string) string {
	switch v := comValue(d, name).(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func comInt(d *ole.IDispatch, name string) int64 {
	switch v := comValue(d, name).(type) {
	case int:
		return int64(v)
	case int8:
		return int64(v)
	case int16:
		return int64(v)
	case int32:
		return int64(v)
	case int64:
		return v
	case uint8:
		return int64(v)
	case uint16:
		return int64(v)
	case uint32:
		return int64(v)
	case uint64:
		return int64(v)
	case float64:
		return int64(v)
	}
	return 0
}

func comBool(d *ole.IDispatch, name string) bool {
	b, _ := comValue(d, name).(bool)
	return b
}

func comTime(d *ole.IDispatch, name string) time.Time {
	t, _ := comValue(d, name).(time.Time)
	// The Task Scheduler reports "never" as 1899-12-30.
	if t.Year() < 1980 {
		return time.Time{}
	}
	return t
}

// comChild fetches an object-valued property. The caller releases it.
func comChild(d *ole.IDispatch, name string, params ...interface{}) *ole.IDispatch {
	v, err := oleutil.GetProperty(d, name, params...)
	if err != nil || v == nil {
		return nil
	}
	return v.ToIDispatch()
}

// comCall invokes a method that returns an object. The caller releases it.
func comCall(d *ole.IDispatch, name string, params ...interface{}) *ole.IDispatch {
	v, err := oleutil.CallMethod(d, name, params...)
	if err != nil || v == nil {
		return nil
	}
	return v.ToIDispatch()
}

// resolveShortcut returns the target and arguments of a .lnk file.
func resolveShortcut(lnk string) (target, args string) {
	unk, err := oleutil.CreateObject("WScript.Shell")
	if err != nil {
		return "", ""
	}
	defer unk.Release()
	shell, err := unk.QueryInterface(ole.IID_IDispatch)
	if err != nil {
		return "", ""
	}
	defer shell.Release()

	sc := comCall(shell, "CreateShortcut", lnk)
	if sc == nil {
		return "", ""
	}
	defer sc.Release()
	return comString(sc, "TargetPath"), comString(sc, "Arguments")
}
