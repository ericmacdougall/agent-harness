//go:build windows

package main

import (
	"os"
	"syscall"
	"unsafe"
)

var settingsMoveFile = settingsKernel32.NewProc("MoveFileExW")

func settingsSyncFile(f *os.File) error { return f.Sync() }

// MoveFileExW WRITE_THROUGH supplies the Windows rename barrier; ordinary
// directory handles do not support Go's directory Sync consistently.
func settingsSyncParent(string) error { return nil }
func settingsReplace(source, target string) error {
	src, e := syscall.UTF16PtrFromString(source)
	if e != nil {
		return e
	}
	dst, e := syscall.UTF16PtrFromString(target)
	if e != nil {
		return e
	}
	ok, _, callErr := settingsMoveFile.Call(uintptr(unsafe.Pointer(src)), uintptr(unsafe.Pointer(dst)), 1|8)
	if ok == 0 {
		return callErr
	}
	return nil
}
