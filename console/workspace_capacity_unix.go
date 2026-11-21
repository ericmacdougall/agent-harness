//go:build darwin || linux

package main

import (
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

func workspaceCapacitySupported() bool { return true }

func probeWorkspaceCapacity(cwd string) (workspaceCapacitySample, error) {
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	if len(cwd) > 4096 || !filepath.IsAbs(cwd) || filepath.Clean(cwd) != cwd {
		return workspaceCapacitySample{}, errors.New("workspace path is not canonical")
	}
	fd, err := unix.Open("/", flags, 0)
	if err != nil {
		return workspaceCapacitySample{}, err
	}
	if cwd != "/" {
		for _, part := range strings.Split(cwd[1:], "/") {
			next, openErr := unix.Openat(fd, part, flags, 0)
			_ = unix.Close(fd)
			if openErr != nil {
				return workspaceCapacitySample{}, openErr
			}
			fd = next
		}
	}
	dir := os.NewFile(uintptr(fd), cwd)
	defer dir.Close()
	info, err := dir.Stat()
	if err != nil {
		return workspaceCapacitySample{}, err
	}
	var stats unix.Statfs_t
	if err := unix.Fstatfs(fd, &stats); err != nil {
		return workspaceCapacitySample{}, err
	}
	size, identity := workspaceFilesystem(stats)
	available := uint64(stats.Bavail)
	if identity == "" || size == 0 || available > uint64(stats.Blocks) || available > math.MaxUint64/size {
		return workspaceCapacitySample{}, errors.New("local capacity could not be calculated")
	}
	return workspaceCapacitySample{directory: info, filesystem: identity, available: available * size}, nil
}
