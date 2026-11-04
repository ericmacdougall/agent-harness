//go:build windows

package main

import (
	"errors"
	"syscall"
	"unsafe"
)

var settingsKernel32 = syscall.NewLazyDLL("kernel32.dll")
var settingsLockFile = settingsKernel32.NewProc("LockFileEx")
var settingsUnlockFile = settingsKernel32.NewProc("UnlockFileEx")

func settingsPlatformLock(path string, exclusive bool) (func(), error) {
	f, e := settingsOpenLockFile(path)
	if e != nil {
		return nil, e
	}
	overlap := &syscall.Overlapped{}
	flags := uintptr(1)
	if exclusive {
		flags |= 2
	}
	ok, _, _ := settingsLockFile.Call(f.Fd(), flags, 0, 1, 0, uintptr(unsafe.Pointer(overlap)))
	if ok == 0 {
		f.Close()
		return nil, errors.New("settings transaction is owned by another live writer")
	}
	return func() { settingsUnlockFile.Call(f.Fd(), 0, 1, 0, uintptr(unsafe.Pointer(overlap))); _ = f.Close() }, nil
}
