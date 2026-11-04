package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// This tree is an unreleased baseline kept on main so later slices review as small
// diffs. It must never open a real console data directory: the installed 0.1.0
// console owns that, and this code has known defects that the event-log rebuild
// replaces. The guard admits only a directory this baseline created itself, outside
// the agent-harness configuration directory.

const (
	baselineMarker  = ".unreleased-baseline"
	baselineContent = "agent-harness console unreleased baseline: not for real data\n"
)

var errRealDataDir = errors.New("unreleased baseline refuses this data directory")

// protectedRoot is the agent-harness directory under the user's configuration
// directory. The installed console keeps its data under it, so nothing at or under
// it is ever admitted, whatever its spelling.
func protectedRoot() string {
	config, err := os.UserConfigDir()
	if err != nil || config == "" {
		return ""
	}
	return filepath.Join(config, "agent-harness")
}

// baselineDataDir admits dir only when it is outside the protected root and is new,
// empty, or already marked by this baseline. It writes the marker into a new or empty
// directory. Refusals change nothing.
func baselineDataDir(dir, protected string) (string, error) {
	if dir == "" {
		return "", fmt.Errorf("%w: pass --data-dir with a new directory; the default console directory is never used", errRealDataDir)
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	if err = outside(abs, protected); err != nil {
		return "", err
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
	case !info.IsDir():
		// Lstat reports a symbolic link as a link, never as a directory.
		return "", fmt.Errorf("%w: not a directory (symbolic links are refused)", errRealDataDir)
	}
	if err = marked(abs); err == nil {
		return abs, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
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

// baselineAdmitted is the read-only check for helper modes, which receive a data
// directory from a ticket or snapshot: it must be outside the protected root and
// already marked.
func baselineAdmitted(dir string) error {
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("%w: helper data directory must be absolute", errRealDataDir)
	}
	if err := outside(dir, protectedRoot()); err != nil {
		return err
	}
	if info, err := os.Lstat(dir); err != nil || !info.IsDir() {
		return fmt.Errorf("%w: helper data directory is not a directory", errRealDataDir)
	}
	if err := marked(dir); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("%w: it was not created by this baseline", errRealDataDir)
		}
		return err
	}
	return nil
}

// marked returns nil for a directory holding this baseline's marker, an error that
// wraps os.ErrNotExist when there is none, and a refusal for anything else there.
func marked(dir string) error {
	marker := filepath.Join(dir, baselineMarker)
	m, err := os.Lstat(marker)
	if err != nil {
		return err
	}
	if !m.Mode().IsRegular() {
		return fmt.Errorf("%w: its marker is not a regular file", errRealDataDir)
	}
	data, err := os.ReadFile(marker)
	if err != nil || string(data) != baselineContent {
		return fmt.Errorf("%w: its marker was not written by this baseline", errRealDataDir)
	}
	return nil
}

// outside refuses path when it is, or lies under, protected. It compares two ways,
// so that neither a link, a case variant, a short name nor a missing directory gets
// through: canonical spellings (links resolved over the longest existing prefix, case
// folded where the filesystem usually ignores case), and file identity of every
// existing ancestor of path against protected.
func outside(path, protected string) error {
	if protected == "" {
		return nil
	}
	refuse := fmt.Errorf("%w: it is inside the agent-harness configuration directory", errRealDataDir)
	p, root := canonical(path), canonical(protected)
	if p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
		return refuse
	}
	rootInfo, err := os.Stat(protected)
	if err != nil {
		return nil
	}
	for dir := filepath.Clean(path); ; {
		if info, err := os.Stat(dir); err == nil && os.SameFile(info, rootInfo) {
			return refuse
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// canonical resolves links over the longest existing prefix of path, keeps the rest
// as written, and folds case on macOS and Windows.
func canonical(path string) string {
	path = filepath.Clean(path)
	rest := ""
	for dir := path; ; {
		if resolved, err := filepath.EvalSymlinks(dir); err == nil {
			path = filepath.Join(resolved, rest)
			break
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		rest = filepath.Join(filepath.Base(dir), rest)
		dir = parent
	}
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		path = strings.ToLower(path)
	}
	return path
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
