//go:build !darwin && !linux

package main

import "errors"

func workspaceCapacitySupported() bool { return false }

func probeWorkspaceCapacity(string) (workspaceCapacitySample, error) {
	return workspaceCapacitySample{}, errors.New("descriptor-based local capacity is unavailable")
}
