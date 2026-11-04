//go:build windows

package proc

import (
	"os"
	"os/exec"
	"syscall"
)

// Windows has no POSIX process groups. The helpers that depend on group cleanup (deliver, integrate,
// rescue) refuse to run on Windows (plan D2), so a direct kill of the leader is enough here.
type winSignal int

const (
	sigTerm winSignal = iota
	sigKill
)

func newGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}

func signalGroup(pid int, _ winSignal) {
	if p, err := os.FindProcess(pid); err == nil {
		_ = p.Kill()
	}
}

func groupAlive(int) bool { return false }
