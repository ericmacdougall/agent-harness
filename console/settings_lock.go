package main

import (
	"errors"
	"os"
)

func settingsLock(path string) (func(), error)     { return settingsPlatformLock(path, true) }
func settingsReadLock(path string) (func(), error) { return settingsPlatformLock(path, false) }

func settingsOpenLockFile(path string) (*os.File, error) {
	if e := settingsCheckParents(path); e != nil {
		return nil, e
	}
	before, e := os.Lstat(path)
	if e != nil && !os.IsNotExist(e) {
		return nil, e
	}
	if before != nil && (!before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0) {
		return nil, errors.New("unsafe settings lock")
	}
	f, e := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	after, e := os.Lstat(path)
	opened, se := f.Stat()
	if e != nil || se != nil || after.Mode()&os.ModeSymlink != 0 || !os.SameFile(after, opened) || (before != nil && !os.SameFile(before, opened)) {
		f.Close()
		return nil, errors.New("settings lock identity changed")
	}
	return f, nil
}
