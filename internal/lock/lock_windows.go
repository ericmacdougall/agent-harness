//go:build windows

package lock

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

var (
	kernel32       = syscall.NewLazyDLL("kernel32.dll")
	procLockFileEx = kernel32.NewProc("LockFileEx")
	errWouldBlock  = errors.New("would block")
)

const (
	lockfileExclusiveLock   = 0x2
	lockfileFailImmediately = 0x1
	errorLockViolation      = syscall.Errno(33)
)

func openPrivate(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && fi.Mode()&os.ModeSymlink != 0 {
		return nil, ErrUnsafe
	}
	return os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0o600)
}

// Windows has no owner/mode bits in the Python sense; require a regular file.
func checkPrivate(f *os.File) error {
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return ErrUnsafe
	}
	return nil
}

func lockFile(f *os.File, block bool) error {
	flags := uint32(lockfileExclusiveLock)
	if !block {
		flags |= lockfileFailImmediately
	}
	var ol syscall.Overlapped
	r, _, err := procLockFileEx.Call(f.Fd(), uintptr(flags), 0, 1, 0, uintptr(unsafe.Pointer(&ol)))
	if r != 0 {
		return nil
	}
	if errors.Is(err, errorLockViolation) {
		return errWouldBlock
	}
	return err
}
