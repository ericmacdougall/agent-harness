//go:build windows

package impl

import "io/fs"

// Windows has no Python front door (plan PRT-win-rollback); ACL checks are the installer's job there.
func private(fs.FileInfo) bool    { return true }
func safeBinary(fs.FileInfo) bool { return true }
