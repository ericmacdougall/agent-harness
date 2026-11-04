//go:build unix

package impl

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
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

// maxLinkHops bounds symlink resolution in safeAncestors (MAX_LINK_HOPS in frontdoor.py).
const maxLinkHops = 40

// safeDir: ours or root's, and not group/other-writable unless sticky.
func safeDir(fi fs.FileInfo) bool {
	st, ok := fi.Sys().(*syscall.Stat_t)
	if !fi.IsDir() || !ok || (int(st.Uid) != os.Geteuid() && st.Uid != 0) {
		return false
	}
	return fi.Mode().Perm()&0o022 == 0 || fi.Mode()&fs.ModeSticky != 0
}

// safeAncestors resolves filepath.Dir(path) one component at a time from "/" (frontdoor._safe_ancestors,
// line for line). Every directory entered must be safe. A symlink met on the way must be ours or root's
// and sits in a directory already verified, so nobody else can retarget it; its target (relative to that
// directory) is walked the same way, up to maxLinkHops. Nobody else can then swap the binary between
// hashing and exec.
func safeAncestors(path string) bool {
	if fi, err := os.Lstat("/"); err != nil || !safeDir(fi) {
		return false
	}
	current, todo, hops := "/", components(filepath.Dir(path)), 0
	for len(todo) > 0 {
		name := todo[0]
		todo = todo[1:]
		switch name {
		case ".":
			continue
		case "..":
			current = filepath.Dir(current)
			continue
		}
		following := filepath.Join(current, name)
		fi, err := os.Lstat(following)
		if err != nil {
			return false
		}
		if fi.Mode()&fs.ModeSymlink != 0 {
			hops++
			st, ok := fi.Sys().(*syscall.Stat_t)
			if hops > maxLinkHops || !ok || (int(st.Uid) != os.Geteuid() && st.Uid != 0) {
				return false
			}
			target, err := os.Readlink(following)
			if err != nil {
				return false
			}
			if strings.HasPrefix(target, "/") {
				current = "/"
			}
			todo = append(components(target), todo...)
			continue
		}
		if !safeDir(fi) {
			return false
		}
		current = following
	}
	return true
}

// components splits a slash path into its non-empty names, as [p for p in path.split("/") if p].
func components(p string) []string {
	var out []string
	for _, c := range strings.Split(p, "/") {
		if c != "" {
			out = append(out, c)
		}
	}
	return out
}

// openRegular never follows a link and never blocks on a FIFO swapped in after Lstat.
func openRegular(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}
