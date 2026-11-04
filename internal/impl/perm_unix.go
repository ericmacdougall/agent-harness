//go:build unix

package impl

import (
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
)

func owner(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	return ok && int(st.Uid) == os.Geteuid()
}

// private: the switch file is owner-only (no group/other bits at all), as the installer writes it.
func private(fi fs.FileInfo) bool { return owner(fi) && fi.Mode().Perm()&0o077 == 0 }

// safeBinary: owner-owned, owner-executable, no group or other write bit (F10). Without the exec bit
// the front door's execve would fail after the decision, so such a binary never selects Go.
func safeBinary(fi fs.FileInfo) bool {
	return owner(fi) && fi.Mode().Perm()&0o022 == 0 && fi.Mode().Perm()&0o100 != 0
}

// safeAncestors: every directory above path, along both the lexical chain and the symlink-resolved one,
// is owned by us or root and not group/other-writable unless sticky, so nobody else can swap the binary
// between hashing and exec (a symlinked ancestor into a shared tree is caught by the resolved chain).
func safeAncestors(path string) bool {
	dir := filepath.Dir(path)
	resolved, err := filepath.EvalSymlinks(dir)
	return err == nil && safeChain(dir) && safeChain(resolved)
}

func safeChain(dir string) bool {
	for ; ; dir = filepath.Dir(dir) {
		fi, err := os.Stat(dir)
		if err != nil || !fi.IsDir() {
			return false
		}
		st, ok := fi.Sys().(*syscall.Stat_t)
		if !ok || (int(st.Uid) != os.Geteuid() && st.Uid != 0) {
			return false
		}
		if fi.Mode().Perm()&0o022 != 0 && fi.Mode()&fs.ModeSticky == 0 {
			return false
		}
		if filepath.Dir(dir) == dir {
			return true
		}
	}
}

// openRegular never follows a link and never blocks on a FIFO swapped in after Lstat.
func openRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
