// Package lock takes the private exclusive file locks the Python helpers take, on the same files, so a
// Go and a Python process exclude each other during the strangler migration.
//
// Python (usage_guard._lock, integrate_local): open O_RDWR|O_CREAT|O_NOFOLLOW 0600, require a regular
// file owned by us with one link and mode 0600, flock(LOCK_EX [|LOCK_NB]), then confirm the path still
// names the locked inode. flock on Unix; LockFileEx on Windows (no Python helper locks there).
//
// wal.py differs: it fchmods the WAL to 0600 before flock instead of refusing a wider mode. Acquire
// refuses such a file (ErrUnsafe); the flock itself still excludes wal.py. The wal group port (P2) must
// choose between repairing the mode and refusing before it uses Acquire on a WAL.
package lock

import (
	"errors"
	"fmt"
	"os"
	"time"
)

var (
	ErrBusy    = errors.New("lock: busy")
	ErrUnsafe  = errors.New("lock: lock file is unsafe")
	ErrChanged = errors.New("lock: lock file changed while locking")
)

// Wait selects how Acquire waits: Forever blocks, Never tries once, and a positive value polls until then.
type Wait time.Duration

const (
	Never   Wait = 0
	Forever Wait = -1
)

// pollInterval matches usage_guard's 20 ms retry sleep.
const pollInterval = 20 * time.Millisecond

// Lock is a held lock. Close releases it.
type Lock struct{ f *os.File }

// Acquire creates or opens path and takes an exclusive lock on it.
func Acquire(path string, wait Wait) (*Lock, error) {
	f, err := openPrivate(path)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			f.Close()
		}
	}()
	if err := checkPrivate(f); err != nil {
		return nil, err
	}
	switch {
	case wait == Forever:
		if err := lockFile(f, true); err != nil {
			return nil, fmt.Errorf("lock: %w", err)
		}
	default:
		deadline := time.Now().Add(time.Duration(wait))
		for {
			err := lockFile(f, false)
			if err == nil {
				break
			}
			if !errors.Is(err, errWouldBlock) {
				return nil, fmt.Errorf("lock: %w", err)
			}
			if !time.Now().Before(deadline) {
				return nil, ErrBusy
			}
			time.Sleep(min(pollInterval, time.Until(deadline)))
		}
	}
	if !sameFile(f, path) {
		return nil, ErrChanged
	}
	ok = true
	return &Lock{f: f}, nil
}

// File exposes the locked descriptor for callers that keep data in the lock file (as wal.py does).
func (l *Lock) File() *os.File { return l.f }

// Close releases the lock by closing the descriptor, as the Python helpers do.
func (l *Lock) Close() error { return l.f.Close() }

func sameFile(f *os.File, path string) bool {
	a, err := f.Stat()
	if err != nil {
		return false
	}
	b, err := os.Lstat(path)
	return err == nil && os.SameFile(a, b)
}
