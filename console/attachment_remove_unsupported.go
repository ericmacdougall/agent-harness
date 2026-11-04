//go:build !darwin && !linux

package main

import (
	"errors"
	"os"
)

func ownedDirectoryIdentity(os.FileInfo) string { return "" }

func attachmentCleanupSupported() bool { return false }

func removeOwnedAttachment(string, os.FileInfo, string, string) error {
	return errors.New("descriptor-confined attachment cleanup is unsupported on this platform")
}
