//go:build !darwin && !linux && !windows

package main

func fdIsTerminal(fd int) bool {
	return false
}
