//go:build windows

package eventlog

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

func lockDir(path string) (func(), error) {
	if info, err := os.Lstat(path); err == nil && !info.Mode().IsRegular() {
		return nil, errors.New("console lock must be a regular file")
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	handle := windows.Handle(f.Fd())
	overlapped := new(windows.Overlapped)
	if err = windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, overlapped); err != nil {
		f.Close()
		return nil, ErrLocked
	}
	return func() { _ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped); _ = f.Close() }, nil
}
