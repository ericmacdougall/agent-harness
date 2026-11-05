//go:build unix

package lock

import (
	"errors"
	"os"
	"syscall"
)

var errWouldBlock = syscall.EWOULDBLOCK

func openPrivate(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_CLOEXEC|syscall.O_NONBLOCK, 0o600)
	if err != nil {
		if errors.Is(err, syscall.ELOOP) {
			return nil, ErrUnsafe
		}
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(fd), path), nil
}

func checkPrivate(f *os.File) error {
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil {
		return err
	}
	if st.Mode&syscall.S_IFMT != syscall.S_IFREG || int(st.Uid) != os.Geteuid() || st.Nlink != 1 || st.Mode&0o7777 != 0o600 {
		return ErrUnsafe
	}
	return nil
}

func lockFile(f *os.File, block bool) error {
	how := syscall.LOCK_EX
	if !block {
		how |= syscall.LOCK_NB
	}
	for {
		err := syscall.Flock(int(f.Fd()), how)
		if err == syscall.EINTR {
			continue
		}
		if err == syscall.EAGAIN {
			return errWouldBlock
		}
		return err
	}
}
