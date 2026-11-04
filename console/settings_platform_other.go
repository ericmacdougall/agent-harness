//go:build !darwin && !linux && !windows

package main

import (
	"errors"
	"os"
)

func settingsPlatformLock(string, bool) (func(), error) {
	return nil, errors.New("settings file locks unsupported on this platform")
}
func settingsSyncFile(*os.File) error {
	return errors.New("durable settings writes unsupported on this platform")
}
func settingsSyncParent(string) error             { return errSettingsDurability }
func settingsReplace(source, target string) error { return os.Rename(source, target) }
