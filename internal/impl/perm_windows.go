//go:build windows

package impl

import (
	"io/fs"
	"os"
)

// Windows has no Python front door (plan PRT-win-rollback); ACL checks are the installer's job there.
func private(fs.FileInfo) bool               { return true }
func safeBinary(fs.FileInfo) bool            { return true }
func safeAncestors(string) bool              { return true }
func openRegular(p string) (*os.File, error) { return os.Open(p) }
