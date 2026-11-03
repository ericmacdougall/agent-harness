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

// Called under app.mu after send admission. Transfer immutable snapshots out of
// the composer before another selection can replace them. The queue store gives
// accepted/uncertain provider consumers durable ownership and explicit cleanup.
func (a *app) retainOrdinaryAttachmentsLocked(s *session, request, text string, paths []string, runtime string) error {
	if len(paths) == 0 {
		return nil
	}
	if len(s.inputs) >= queueReceiptLimit {
		return errors.New("input receipt limit reached; discard retained inputs")
	}
	snapshots := map[string]attachmentSnapshot{}
	for _, path := range paths {
		snapshots[path] = s.attachmentSnapshots[path]
	}
	entry := &queuedInput{
		RetentionOnly:         true,
		RequestID:             request,
		RequestHash:           objectiveHash(text + "\x00" + strings.Join(paths, "\x00")),
		Status:                "dispatching",
		CreatedAt:             now(),
		Reason:                "Provider write intent; files retained for delayed consumers",
		TaskID:                s.task.ID,
		Generation:            s.task.Generation,
		QueuedAtInputRevision: s.task.InputRevision,
		CWD:                   s.CWD,
		PolicyRevision:        s.PolicyRevision,
		PayloadHash:           objectiveHash(text + "\x00" + request),
		PolicyHash:            policyHash(s.policy),
		RuntimeHash:           runtime,
		Snapshots:             snapshots,
	}
	s.inputs = append(s.inputs, entry)
	if err := a.saveInputsLocked(s); err != nil {
		if !s.queueUncertain {
			s.inputs = s.inputs[:len(s.inputs)-1]
			return err
		}
		entry.Status = "unknown"
		entry.Reason = "Attachment ownership commit is uncertain; preserve files and restart to reconcile"
		for _, path := range paths {
			delete(s.attachmentSnapshots, path)
		}
		s.Attachments = []string{}
		return err
	}
	for _, path := range paths {
		delete(s.attachmentSnapshots, path)
	}
	s.Attachments = []string{}
	return nil
}

// Called under app.mu. cleanup_pending is the durable owner until every
// console-owned path is absent and that directory removal is durable.
func (a *app) finishAttachmentCleanupLocked(s *session, entry *queuedInput) error {
	if entry.Status != "cleanup_pending" {
		return errors.New("attachment cleanup has no durable pending owner")
	}
	root := filepath.Join(a.dataDir, "attachments")
	remove := a.attachmentRemove
	if remove == nil {
		remove = os.Remove
	}
	for _, saved := range entry.Snapshots {
		clean := filepath.Clean(saved.Path)
		rel, err := filepath.Rel(root, clean)
		if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return errors.New("attachment cleanup path escaped private storage")
		}
		info, err := os.Lstat(clean)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return errors.New("attachment cleanup path is not an owned regular file")
		}
		if err = remove(clean); err != nil && !os.IsNotExist(err) {
			return errors.New("attachment cleanup could not remove an owned snapshot")
		}
	}
	if len(entry.Snapshots) > 0 {
		if err := settingsSyncParent(root); err != nil {
			return errors.New("attachment cleanup directory durability is unknown")
		}
	}
	old := *entry
	entry.Status = "discarded"
	entry.Reason = entry.CleanupReason
	if entry.Reason == "" {
		entry.Reason = "Private attachment ownership released"
	}
	entry.CleanupReason = ""
	entry.Snapshots = nil
	if err := a.saveInputsLocked(s); err != nil {
		*entry = old
		return err
	}
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
