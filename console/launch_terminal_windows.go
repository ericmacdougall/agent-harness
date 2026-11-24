//go:build windows

package main

func fdIsTerminal(fd int) bool {
	return false
}
