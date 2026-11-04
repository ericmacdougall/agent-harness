//go:build windows

package main

import (
	"os/exec"
	"strconv"
	"syscall"
)

func configureProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{CreationFlags: 0x00000200}
}
func terminateProcess(command *exec.Cmd) {
	if command == nil || command.Process == nil {
		return
	}
	// Only the exact child created by this console is eligible for tree shutdown.
	_ = exec.Command("taskkill.exe", "/PID", strconv.Itoa(command.Process.Pid), "/T", "/F").Run()
}
