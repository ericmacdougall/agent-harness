package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func workspaceFilesystem(stats unix.Statfs_t) (uint64, string) {
	if stats.Flags&unix.MNT_LOCAL == 0 {
		return 0, ""
	}
	return uint64(stats.Bsize), fmt.Sprintf("%d:%v", stats.Type, stats.Fsid)
}
