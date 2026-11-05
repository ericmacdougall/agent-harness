//go:build darwin

package main

import (
	"errors"

	"golang.org/x/sys/unix"
)

// observeExit blocks until the child has exited without reaping it (kqueue
// NOTE_EXIT), so the zombie keeps its pid and process group ID reserved.
func observeExit(pid int) error {
	kq, err := unix.Kqueue()
	if err != nil {
		return err
	}
	defer unix.Close(kq)
	change := []unix.Kevent_t{{
		Ident:  uint64(pid),
		Filter: unix.EVFILT_PROC,
		Flags:  unix.EV_ADD | unix.EV_ONESHOT,
		Fflags: unix.NOTE_EXIT,
	}}
	events := make([]unix.Kevent_t, 1)
	for {
		n, err := unix.Kevent(kq, change, events, nil)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.ESRCH) {
			return nil // already exited and not yet reaped: nobody else waits on it
		}
		if err != nil {
			return err
		}
		if n > 0 {
			return nil
		}
		change = nil
	}
}
