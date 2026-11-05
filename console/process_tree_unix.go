//go:build !windows

package main

import "syscall"

// signalProcessGroup signals every member of the group the leader created with
// Setpgid. The caller must hold the processTree lock and must have checked
// that the leader has not been reaped, so the group ID cannot have been reused.
func signalProcessGroup(pid int, force bool) error {
	sig := syscall.SIGTERM
	if force {
		sig = syscall.SIGKILL
	}
	return syscall.Kill(-pid, sig)
}
