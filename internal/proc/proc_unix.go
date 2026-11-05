//go:build unix

package proc

import (
	"os/exec"
	"syscall"
)

const (
	sigTerm = syscall.SIGTERM
	sigKill = syscall.SIGKILL
)

func newGroup(cmd *exec.Cmd) { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }

// signalGroup ignores a group that vanished or became inaccessible between TERM and KILL.
func signalGroup(pgid int, sig syscall.Signal) { _ = syscall.Kill(-pgid, sig) }

func groupAlive(pgid int) bool {
	err := syscall.Kill(-pgid, 0)
	return err == nil || err == syscall.EPERM
}
