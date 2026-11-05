//go:build windows

package main

import (
	"os/exec"
	"unsafe"

	"golang.org/x/sys/windows"
)

// treeSignaler puts the child in a Job Object right after Start so the whole
// tree can be ended by handle, never by a pid that may have been recycled. There
// is no polite phase on Windows: both signals terminate the job. A descendant
// spawned before the assignment is outside the job; Go cannot start a process
// suspended, so that gap is stated rather than hidden. The job has no
// kill-on-close flag: releasing the handle leaves surviving background work alone,
// like the Unix true-final policy.
func treeSignaler(cmd *exec.Cmd) (func(int, bool) error, func(), error) {
	job, err := windows.CreateJobObject(nil, nil)
	if err != nil {
		return nil, nil, err
	}
	var info windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	if _, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation, uintptr(unsafe.Pointer(&info)), uint32(unsafe.Sizeof(info))); err != nil {
		_ = windows.CloseHandle(job)
		return nil, nil, err
	}
	proc, err := windows.OpenProcess(windows.PROCESS_SET_QUOTA|windows.PROCESS_TERMINATE, false, uint32(cmd.Process.Pid))
	if err != nil {
		_ = windows.CloseHandle(job)
		return nil, nil, err
	}
	defer windows.CloseHandle(proc)
	if err = windows.AssignProcessToJobObject(job, proc); err != nil {
		_ = windows.CloseHandle(job)
		return nil, nil, err
	}
	signal := func(int, bool) error { return windows.TerminateJobObject(job, 1) }
	release := func() { _ = windows.CloseHandle(job) }
	return signal, release, nil
}
