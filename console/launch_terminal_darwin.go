//go:build darwin

package main

import "golang.org/x/sys/unix"

func fdIsTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TIOCGETA)
	return err == nil
}
