//go:build darwin

package main

import (
	"os"
	"syscall"
)

func settingsSyncFile(f *os.File) error {
	if e := f.Sync(); e != nil {
		return e
	}
	_, _, e := syscall.Syscall(syscall.SYS_FCNTL, f.Fd(), syscall.F_FULLFSYNC, 0)
	if e != 0 {
		return e
	}
	return nil
}
func settingsSyncParent(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return settingsSyncFile(f)
}
func settingsReplace(source, target string) error { return os.Rename(source, target) }
