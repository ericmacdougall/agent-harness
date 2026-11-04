//go:build unix

package impl

import (
	"io/fs"
	"os"
	"syscall"
)

func owner(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// private: the switch file is owner-only (no group/other bits at all), as the installer writes it.
func private(fi fs.FileInfo) bool { return owner(fi) && fi.Mode().Perm()&0o077 == 0 }

// safeBinary: owner-owned with no group or other write bit (F10).
func safeBinary(fi fs.FileInfo) bool { return owner(fi) && fi.Mode().Perm()&0o022 == 0 }
