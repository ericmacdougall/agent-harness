//go:build unix

package safefs

import (
	"io/fs"
	"os"
	"syscall"
)

func links(fi fs.FileInfo) uint64 {
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		return uint64(st.Nlink)
	}
	return 0
}

// privateDir: owned by the effective user with mode exactly 0700.
func privateDir(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid() && fi.Mode().Perm() == 0o700
}
