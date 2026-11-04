//go:build darwin || linux

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

func ownedDirectoryIdentity(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ""
	}
	return fmt.Sprintf("%d:%d", stat.Dev, stat.Ino)
}

func attachmentCleanupSupported() bool { return true }

func removeOwnedAttachment(dataDir string, expected os.FileInfo, name, expectedDirectory string) error {
	if name == "" || name == "." || filepath.Base(name) != name {
		return errors.New("invalid attachment basename")
	}
	dataFD, err := unix.Open(dataDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	dataFile := os.NewFile(uintptr(dataFD), dataDir)
	defer dataFile.Close()
	actual, err := dataFile.Stat()
	if err != nil || expected == nil || !os.SameFile(expected, actual) {
		return errors.New("private data directory identity changed")
	}
	attachmentsFD, err := unix.Openat(dataFD, "attachments", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	attachmentsFile := os.NewFile(uintptr(attachmentsFD), "attachments")
	defer attachmentsFile.Close()
	attachmentsInfo, err := attachmentsFile.Stat()
	if err != nil || expectedDirectory == "" || ownedDirectoryIdentity(attachmentsInfo) != expectedDirectory {
		return errors.New("private attachment directory identity changed")
	}
	if err = unix.Unlinkat(attachmentsFD, name, 0); err != nil && !errors.Is(err, unix.ENOENT) {
		return err
	}
	return unix.Fsync(attachmentsFD)
}
