//go:build linux

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// observeExit blocks until the child has exited without reaping it, so the
// zombie keeps its pid and process group ID reserved.
func observeExit(pid int) error {
	var info unix.Siginfo
	for {
		err := unix.Waitid(unix.P_PID, pid, &info, unix.WEXITED|unix.WNOWAIT, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		return err
	}
}
