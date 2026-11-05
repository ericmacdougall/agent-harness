//go:build windows

package main

import (
	"os/exec"
	"strconv"
)

// signalProcessGroup always ends the whole tree: Windows has no polite group
// signal that this console can deliver. Only the exact child it created is
// eligible, and the caller holds the processTree lock after a reaped check.
func signalProcessGroup(pid int, force bool) error {
	return exec.Command("taskkill.exe", "/PID", strconv.Itoa(pid), "/T", "/F").Run()
}
