//go:build !windows

package writer

import (
	"errors"
	"os"
	"syscall"
)

// Inode returns the inode number of path (not following a final symlink).
func Inode(path string) (uint64, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return 0, err
	}
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("no inode")
	}
	return uint64(st.Ino), nil
}
