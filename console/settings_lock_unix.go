//go:build darwin || linux

package main

import (
	"errors"
	"syscall"
)

func settingsPlatformLock(path string, exclusive bool) (func(), error) {
	f, e := settingsOpenLockFile(path)
	if e != nil {
		return nil, e
	}
	mode := syscall.LOCK_SH
	if exclusive {
		mode = syscall.LOCK_EX
	}
	if e = syscall.Flock(int(f.Fd()), mode|syscall.LOCK_NB); e != nil {
		f.Close()
		return nil, errors.New("settings transaction is owned by another live writer")
	}
	return func() { _ = syscall.Flock(int(f.Fd()), syscall.LOCK_UN); _ = f.Close() }, nil
}
