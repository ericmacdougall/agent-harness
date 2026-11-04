package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// This tree is an unreleased baseline kept on main so later slices review as small
// diffs. It must never open a real console data directory: the installed 0.1.0
// console owns that, and this code has known defects that the event-log rebuild
// replaces. The guard admits only a directory this baseline created itself.

const (
	baselineMarker  = ".unreleased-baseline"
	baselineContent = "agent-harness console unreleased baseline: not for real data\n"
)

var errRealDataDir = errors.New("unreleased baseline refuses this data directory")

// baselineDataDir admits dir only when it is new, empty, or already marked by this
// baseline, and never when it is the default console directory or a link to it. It
// writes the marker into a new or empty directory. Refusals change nothing.
func baselineDataDir(dir, defaultDir string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("%w: pass --data-dir with a new directory; the default console directory is never used", errRealDataDir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if defaultDir != "" && sameDir(abs, defaultDir) {
		return "", fmt.Errorf("%w: it is the default console directory", errRealDataDir)
	}
	info, err := os.Lstat(abs)
	switch {
	case os.IsNotExist(err):
		if err = os.MkdirAll(abs, 0o700); err != nil {
			return "", err
		}
		return abs, writeMarker(abs)
	case err != nil:
		return "", err
	case info.Mode()&os.ModeSymlink != 0:
		return "", fmt.Errorf("%w: the data directory may not be a symbolic link", errRealDataDir)
	case !info.IsDir():
		return "", fmt.Errorf("%w: not a directory", errRealDataDir)
	}
	marker := filepath.Join(abs, baselineMarker)
	if m, err := os.Lstat(marker); err == nil {
		if !m.Mode().IsRegular() {
			return "", fmt.Errorf("%w: its marker is not a regular file", errRealDataDir)
		}
		data, err := os.ReadFile(marker)
		if err != nil || string(data) != baselineContent {
			return "", fmt.Errorf("%w: its marker was not written by this baseline", errRealDataDir)
		}
		return abs, nil
	}
	entries, err := os.ReadDir(abs)
	if err != nil {
		return "", err
	}
	if len(entries) > 0 {
		return "", fmt.Errorf("%w: it holds files this baseline did not create; use a new directory", errRealDataDir)
	}
	return abs, writeMarker(abs)
}

func writeMarker(dir string) error {
	f, err := os.OpenFile(filepath.Join(dir, baselineMarker), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.WriteString(baselineContent); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

// sameDir compares after resolving links, so a path that reaches the default
// directory through a symlinked parent is caught too.
func sameDir(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	if errA != nil {
		ra = filepath.Clean(a)
	}
	if errB != nil {
		rb = filepath.Clean(b)
	}
	return ra == rb
}
