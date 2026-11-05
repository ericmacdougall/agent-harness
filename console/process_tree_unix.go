//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

// signalProcessGroup signals every member of the group the leader created with
// Setpgid. The caller holds the processTree lock after checking the tree has not
// decided its fate, so the group ID is still pinned by the leader.
func signalProcessGroup(pid int, force bool) error {
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	return syscall.Kill(-pid, sig)
}

func treeSignaler(*exec.Cmd) (func(int, bool) error, func(), error) {
	return signalProcessGroup, nil, nil
}
