package legacyimport

import (
	"os"
	"runtime"
)

// fileOps is the filesystem seam for the swap, rollback and preflight. Tests record
// the order of these calls, since a kill cannot show whether an fsync came first.
type fileOps interface {
	// WriteSync creates path, writes data, fsyncs and closes it. With exclusive it
	// fails if path exists; otherwise it truncates.
	WriteSync(path string, data []byte, exclusive bool) error
	// Link makes a hard link and fails if newname exists.
	Link(oldname, newname string) error
	Rename(oldname, newname string) error
	// SyncDir makes the directory's entries durable. Windows has no directory fsync;
	// NTFS journals the metadata, and the preflight requires hard links, so NTFS.
	SyncDir(dir string) error
}

type osOps struct{}

func (osOps) WriteSync(path string, data []byte, exclusive bool) error {
	flags := os.O_WRONLY | os.O_CREATE
	if exclusive {
		flags |= os.O_EXCL
	} else {
		flags |= os.O_TRUNC
	}
	f, err := os.OpenFile(path, flags, 0o600)
	if err != nil {
		return err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}

func (osOps) Link(oldname, newname string) error   { return os.Link(oldname, newname) }
func (osOps) Rename(oldname, newname string) error { return os.Rename(oldname, newname) }

func (osOps) SyncDir(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	err = f.Sync()
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
