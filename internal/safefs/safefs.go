// Package safefs ports the harness's pinned-directory file publication (usage_guard._publish,
// report_file.ReportTarget): operate relative to a pinned directory, never follow a symlink in the final
// component, publish new files by hard-linking a fully written private temp file (so a reader sees all
// of it or nothing and an existing name is never overwritten), and re-check every identity afterwards.
//
// It is built on os.Root, which refuses any path that escapes the directory, including through symlinks.
package safefs

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

var (
	ErrUnsafe  = errors.New("safefs: unsafe path")
	ErrChanged = errors.New("safefs: identity changed")
	ErrExists  = fs.ErrExist
	ErrTooBig  = errors.New("safefs: file exceeds the size limit")
)

// Dir is a directory pinned at open time.
type Dir struct {
	path string
	root *os.Root
	id   fs.FileInfo
}

// OpenDir pins path, which must be an existing real directory (not a symlink).
func OpenDir(path string) (*Dir, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("%w: %s is not absolute", ErrUnsafe, path)
	}
	li, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !li.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrUnsafe, path)
	}
	r, err := os.OpenRoot(path)
	if err != nil {
		return nil, err
	}
	id, err := r.Stat(".")
	if err != nil || !os.SameFile(id, li) {
		r.Close()
		return nil, fmt.Errorf("%w: %s changed while opening", ErrChanged, path)
	}
	return &Dir{path: path, root: r, id: id}, nil
}

// Close releases the pinned directory.
func (d *Dir) Close() error { return d.root.Close() }

// Current reports ErrChanged if the path no longer names the pinned directory.
func (d *Dir) Current() error {
	li, err := os.Lstat(d.path)
	if err != nil || !li.IsDir() || !os.SameFile(li, d.id) {
		return fmt.Errorf("%w: %s", ErrChanged, d.path)
	}
	return nil
}

func validName(name string) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\`) || strings.ContainsRune(name, 0) {
		return fmt.Errorf("%w: bad file name %q", ErrUnsafe, name)
	}
	return nil
}

// ReadRegular reads name, refusing symlinks, non-regular files, multiply linked files and files over max.
func (d *Dir) ReadRegular(name string, max int64) ([]byte, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	li, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !li.Mode().IsRegular() || links(li) != 1 {
		return nil, fmt.Errorf("%w: %s is not a single-link regular file", ErrUnsafe, name)
	}
	f, err := d.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || !os.SameFile(fi, li) {
		return nil, fmt.Errorf("%w: %s changed while opening", ErrChanged, name)
	}
	body, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > max {
		return nil, ErrTooBig
	}
	return body, nil
}

// PublishNew atomically creates name with body (mode 0600). It never replaces an existing name.
func (d *Dir) PublishNew(name string, body []byte) error {
	if err := validName(name); err != nil {
		return err
	}
	if err := d.Current(); err != nil {
		return err
	}
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return err
	}
	tmp := ".stage-" + hex.EncodeToString(rnd[:])
	f, err := d.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer d.root.Remove(tmp)
	_, werr := f.Write(body)
	if werr == nil {
		werr = f.Sync()
	}
	written, serr := f.Stat()
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return werr
	}
	if serr != nil {
		return serr
	}
	if err := d.Current(); err != nil {
		return err
	}
	if err := d.root.Link(tmp, name); err != nil {
		if errors.Is(err, fs.ErrExist) {
			return fmt.Errorf("%w: %s", ErrExists, name)
		}
		return err
	}
	syncDir(d.root)
	if err := d.Current(); err != nil {
		return err
	}
	visible, err := d.root.Lstat(name)
	if err != nil || !os.SameFile(visible, written) {
		return fmt.Errorf("%w: published %s is not the written file", ErrChanged, name)
	}
	// After the temp name is removed (deferred), the published file has one link again.
	if err := d.root.Remove(tmp); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	got, err := d.ReadRegular(name, int64(len(body)))
	if err != nil {
		return err
	}
	if !bytes.Equal(got, body) {
		return fmt.Errorf("%w: published %s content differs", ErrChanged, name)
	}
	return nil
}

func syncDir(r *os.Root) {
	if f, err := r.Open("."); err == nil {
		_ = f.Sync() // best effort, as on platforms where directory fsync is unsupported
		f.Close()
	}
}
