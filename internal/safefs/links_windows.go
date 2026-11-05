//go:build windows

package safefs

import "io/fs"

// FileInfo on Windows does not expose the link count without another handle query; the hard-link
// publication path is not used by Windows helpers (plan D2), so report a single link.
func links(fs.FileInfo) uint64 { return 1 }

// privateDir: Windows has no mode bits to check; ACLs are the installer's job there.
func privateDir(fs.FileInfo) bool { return true }
