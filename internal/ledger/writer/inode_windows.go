//go:build windows

package writer

import "os"

// Inode on Windows: 0a only compiles there (brief section 2, out of scope); the fingerprint then depends on
// the machine id alone. A file-index based identity is a 0b item.
func Inode(path string) (uint64, error) {
	_, err := os.Lstat(path)
	return 0, err
}
