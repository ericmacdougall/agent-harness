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
	tmp, written, err := d.stage(body)
	if err != nil {
		return err
	}
	defer d.root.Remove(tmp)
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

// MkdirPrivate creates name (mode 0700) inside d, or accepts an existing real directory that is ours with
// mode exactly 0700 (usage_guard's rule), and pins it. A symlink, a foreign or wider directory, or
// anything else at that name, is refused, as is a directory swapped between the check and the pin.
func (d *Dir) MkdirPrivate(name string) (*Dir, error) {
	if err := validName(name); err != nil {
		return nil, err
	}
	if err := d.Current(); err != nil {
		return nil, err
	}
	if err := d.root.Mkdir(name, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, err
	}
	li, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !li.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrUnsafe, name)
	}
	if !privateDir(li) {
		return nil, fmt.Errorf("%w: %s is not a private directory of this user", ErrUnsafe, name)
	}
	sub, err := OpenDir(filepath.Join(d.path, name))
	if err != nil {
		return nil, err
	}
	if !os.SameFile(sub.id, li) {
		sub.Close()
		return nil, fmt.Errorf("%w: %s changed while opening", ErrChanged, name)
	}
	return sub, nil
}

// Identity is what Replace requires the current file to still be; nil means "must not exist yet".
type Identity struct {
	info fs.FileInfo
	body []byte
}

// Snapshot records name's identity and content for a later Replace (the usage_guard prior check).
func (d *Dir) Snapshot(name string, max int64) (*Identity, error) {
	body, err := d.ReadRegular(name, max)
	if err != nil {
		return nil, err
	}
	li, err := d.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	return &Identity{info: li, body: body}, nil
}

// Replace atomically renames a fully written 0600 temp file over name, but only if name still matches
// prior (same inode, size, mtime and bytes), or is still absent when prior is nil.
func (d *Dir) Replace(name string, body []byte, prior *Identity) error {
	if err := validName(name); err != nil {
		return err
	}
	tmp, written, err := d.stage(body)
	if err != nil {
		return err
	}
	defer d.root.Remove(tmp)
	if err := d.Current(); err != nil {
		return err
	}
	li, lerr := d.root.Lstat(name)
	switch {
	case prior == nil && lerr == nil:
		return fmt.Errorf("%w: %s", ErrExists, name)
	case prior == nil && !errors.Is(lerr, fs.ErrNotExist):
		return lerr
	case prior != nil:
		if lerr != nil || !os.SameFile(li, prior.info) || li.Size() != prior.info.Size() || !li.ModTime().Equal(prior.info.ModTime()) {
			return fmt.Errorf("%w: %s changed since it was read", ErrChanged, name)
		}
		now, err := d.ReadRegular(name, int64(len(prior.body)))
		if err != nil || !bytes.Equal(now, prior.body) {
			return fmt.Errorf("%w: %s changed since it was read", ErrChanged, name)
		}
	}
	if err := d.root.Rename(tmp, name); err != nil {
		return err
	}
	syncDir(d.root)
	visible, err := d.root.Lstat(name)
	if err != nil || !os.SameFile(visible, written) {
		return fmt.Errorf("%w: replaced %s is not the written file", ErrChanged, name)
	}
	return d.Current()
}

// stage writes body to a new private temp file and returns its name and identity.
func (d *Dir) stage(body []byte) (string, fs.FileInfo, error) {
	var rnd [16]byte
	if _, err := rand.Read(rnd[:]); err != nil {
		return "", nil, err
	}
	tmp := ".stage-" + hex.EncodeToString(rnd[:])
	f, err := d.root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return "", nil, err
	}
	_, werr := f.Write(body)
	if werr == nil {
		werr = f.Sync()
	}
	fi, serr := f.Stat()
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = serr
	}
	if werr != nil {
		d.root.Remove(tmp)
		return "", nil, werr
	}
	return tmp, fi, nil
}

// Remove deletes a regular file name inside the pinned directory (never a symlink target or a directory).
func (d *Dir) Remove(name string) error {
	if err := validName(name); err != nil {
		return err
	}
	li, err := d.root.Lstat(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	if li.IsDir() {
		return fmt.Errorf("%w: %s is a directory", ErrUnsafe, name)
	}
	return d.root.Remove(name)
}
