package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func workspaceFilesystem(stats unix.Statfs_t) (uint64, string) {
	// Explicit local filesystem types only. Network and userspace filesystems
	// have different admission and capacity accounting.
	switch uint32(stats.Type) {
	case unix.EXT4_SUPER_MAGIC, unix.XFS_SUPER_MAGIC, unix.BTRFS_SUPER_MAGIC, unix.F2FS_SUPER_MAGIC, unix.TMPFS_MAGIC, unix.OVERLAYFS_SUPER_MAGIC:
	default:
		return 0, ""
	}
	if stats.Frsize > 0 {
		return uint64(stats.Frsize), fmt.Sprintf("%d:%v", stats.Type, stats.Fsid)
	}
	if stats.Bsize <= 0 {
		return 0, ""
	}
	return uint64(stats.Bsize), fmt.Sprintf("%d:%v", stats.Type, stats.Fsid)
}
