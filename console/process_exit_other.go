//go:build !linux && !darwin

package main

import "errors"

// No exit observation without reaping on this platform: the tree falls back to
// treating Wait as the observation.
func observeExit(int) error { return errors.New("exit observation unsupported") }
