//go:build linux

package main

import "golang.org/x/sys/unix"

func fdIsTerminal(fd int) bool {
	_, err := unix.IoctlGetTermios(fd, unix.TCGETS)
	return err == nil
}
