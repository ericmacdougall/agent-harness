//go:build linux

package main

import "os"

func settingsSyncFile(f *os.File) error { return f.Sync() }
func settingsSyncParent(path string) error {
	f, e := os.Open(path)
	if e != nil {
		return e
	}
	defer f.Close()
	return f.Sync()
}
func settingsReplace(source, target string) error { return os.Rename(source, target) }
