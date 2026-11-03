package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
)

type attachmentSnapshot struct {
	Path string
	Hash string
	Size int64
}

func credentialFile(path string) bool {
	for _, part := range strings.Split(filepath.ToSlash(strings.ToLower(path)), "/") {
		if strings.HasPrefix(part, ".env") || part == ".ssh" || part == ".aws" || part == ".gnupg" || part == "auth.json" || part == "credentials.json" || strings.Contains(part, "id_rsa") || strings.Contains(part, "id_ed25519") {
			return true
		}
	}
	return false
}
func (a *app) selectAttachments(id string, paths []string) error {
	if err := a.validateAttachments(paths); err != nil {
		return err
	}
	selected := map[string]attachmentSnapshot{}
	for _, path := range paths {
		item, err := a.snapshotAttachment(path)
		if err != nil {
			for _, saved := range selected {
				_ = os.Remove(saved.Path)
			}
			return err
		}
		selected[path] = item
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	current := a.findLocked(id)
	if current == nil {
		for _, saved := range selected {
			_ = os.Remove(saved.Path)
		}
		return errors.New("session not found")
	}
	for _, saved := range current.attachmentSnapshots {
		_ = os.Remove(saved.Path)
	}
	current.attachmentSnapshots = selected
	current.Attachments = append([]string{}, paths...)
	a.changedLocked()
	return nil
}

// Called under app.mu: the provider receives only private snapshots, never the mutable original.
func (a *app) selectedAttachments(current *session, paths []string) ([]string, error) {
	result := []string{}
	if len(paths) > 16 {
		return nil, errors.New("at most 16 attachments per message")
	}
	for _, path := range paths {
		saved, ok := current.attachmentSnapshots[path]
		if !ok {
			return nil, errors.New("select attachments before sending")
		}
		resolved, err := filepath.EvalSymlinks(saved.Path)
		if err != nil || resolved != saved.Path {
			return nil, errors.New("attachment snapshot was redirected")
		}
		info, err := os.Lstat(saved.Path)
		if err != nil || !info.Mode().IsRegular() || info.Size() != saved.Size {
			return nil, errors.New("attachment snapshot changed")
		}
		bytes, err := os.ReadFile(saved.Path)
		if err != nil {
			return nil, errors.New("attachment snapshot cannot be read")
		}
		digest := sha256.Sum256(bytes)
		if hex.EncodeToString(digest[:]) != saved.Hash {
			return nil, errors.New("attachment snapshot changed")
		}
		result = append(result, saved.Path)
	}
	return result, nil
}
func (a *app) snapshotAttachment(path string) (attachmentSnapshot, error) {
	result := attachmentSnapshot{}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(canonical) != filepath.Clean(path) {
		return result, errors.New("attachment path contains a redirect; select the real file")
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Size() > 16<<20 {
		return result, errors.New("attachment must be a bounded regular file")
	}
	source, err := os.Open(path)
	if err != nil {
		return result, err
	}
	defer source.Close()
	opened, err := source.Stat()
	if err != nil || !os.SameFile(before, opened) {
		return result, errors.New("attachment changed during selection")
	}
	data, err := io.ReadAll(io.LimitReader(source, 16<<20+1))
	if err != nil || len(data) > 16<<20 {
		return result, errors.New("attachment could not be read within its bound")
	}
	after, err := source.Stat()
	named, nameErr := os.Lstat(path)
	resolved, resolveErr := filepath.EvalSymlinks(path)
	if err != nil || nameErr != nil || resolveErr != nil || resolved != canonical || !os.SameFile(opened, named) || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return result, errors.New("attachment changed while being copied")
	}
	if utf8.Valid(data) && a.clean(string(data)) != string(data) {
		return result, errors.New("attachment contains a configured secret; remove it before sending")
	}
	directory := filepath.Join(a.dataDir, "attachments")
	if err = os.MkdirAll(directory, 0700); err != nil {
		return result, err
	}
	info, err := os.Lstat(directory)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return result, errors.New("attachment snapshot directory is redirected")
	}
	destination := filepath.Join(directory, freshID()+"-"+filepath.Base(path))
	file, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, err
	}
	if _, err = file.Write(data); err == nil {
		if a.attachmentSyncFile != nil {
			err = a.attachmentSyncFile(file)
		} else {
			err = settingsSyncFile(file)
		}
	}
	closeErr := file.Close()
	if err != nil || closeErr != nil {
		_ = os.Remove(destination)
		return result, errors.New("attachment snapshot could not be saved")
	}
	syncDir := a.attachmentSyncDir
	if syncDir == nil {
		syncDir = settingsSyncParent
	}
	if err = syncDir(directory); err == nil {
		err = syncDir(a.dataDir)
	}
	if err != nil {
		_ = os.Remove(destination)
		return result, errors.New("attachment namespace durability could not be established")
	}
	digest := sha256.Sum256(data)
	return attachmentSnapshot{Path: destination, Hash: hex.EncodeToString(digest[:]), Size: int64(len(data))}, nil
}
