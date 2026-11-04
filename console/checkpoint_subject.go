package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

type reviewSubject struct {
	InputRevision uint64 `json:"inputRevision"`
	ObjectiveHash string `json:"objectiveHash"`
	GitCommonDir  string `json:"gitCommonDir,omitempty"`
	commonInfo    os.FileInfo
	Root          string   `json:"root"`
	Kind          string   `json:"kind"`
	Head          string   `json:"head,omitempty"`
	Digest        string   `json:"digest"`
	Evidence      []string `json:"evidence"`
	Files         []string `json:"files"`
}

func (a *app) captureSubject(cwd, kind, head string, paths []string) (reviewSubject, error) {
	out := reviewSubject{Root: cwd, Kind: kind, Head: head, Evidence: append([]string{}, paths...), Files: []string{}}
	if kind != "code" && kind != "artifact" {
		return out, errors.New("review subject must be code or artifact")
	}
	if len(paths) == 0 || len(paths) > 24 {
		return out, errors.New("review requires 1–24 bounded evidence files")
	}
	if common, commonErr := gitCommonDirectory(cwd); commonErr == nil {
		out.GitCommonDir = common
		out.commonInfo, _ = os.Stat(common)
	}
	hash := sha256.New()
	total := int64(0)
	capture := func(path string) error {
		if len(out.Files) >= 4096 || len(path) > 1024 {
			return errors.New("review file count or path exceeds snapshot bound")
		}
		if !filepath.IsAbs(path) {
			path = filepath.Join(cwd, path)
		}
		path = filepath.Clean(path)
		rel, e := filepath.Rel(cwd, path)
		if e != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || credentialFile(path) {
			return errors.New("evidence must stay inside this working directory and exclude credentials")
		}
		resolved, e := filepath.EvalSymlinks(path)
		if e != nil || resolved != path {
			return errors.New("review file is missing or redirected")
		}
		info, e := os.Lstat(path)
		if e != nil || !info.Mode().IsRegular() || info.Size() > 16<<20 {
			return errors.New("review file must be bounded regular data")
		}
		total += info.Size()
		if total > 64<<20 {
			return errors.New("review snapshot exceeds 64 MiB")
		}
		data, e := os.ReadFile(path)
		if e != nil || int64(len(data)) != info.Size() {
			return errors.New("review file changed during capture")
		}
		after, e := os.Stat(path)
		if e != nil || !os.SameFile(info, after) || !info.ModTime().Equal(after.ModTime()) {
			return errors.New("review file changed during capture")
		}
		if a.clean(string(data)) != string(data) {
			return errors.New("review file contains configured secret")
		}
		sum := sha256.Sum256(data)
		hash.Write([]byte(rel))
		hash.Write([]byte{0})
		hash.Write(sum[:])
		out.Files = append(out.Files, rel)
		return nil
	}
	if kind == "code" {
		actual, e := gitOutput(cwd, "rev-parse", "HEAD")
		if e != nil || strings.TrimSpace(actual) != head {
			return out, errors.New("review head does not match actual repository")
		}
		status, e := gitOutput(cwd, "status", "--porcelain")
		if e != nil || strings.TrimSpace(status) != "" {
			return out, errors.New("commit scoped changes and clean the worktree before code review")
		}
		files, e := gitOutput(cwd, "ls-files", "-z")
		if e != nil {
			return out, e
		}
		for _, file := range strings.Split(files, "\x00") {
			if file != "" {
				if e = capture(file); e != nil {
					return out, e
				}
			}
		}
	}
	for _, path := range paths {
		if err := capture(path); err != nil {
			return out, err
		}
	}
	hash.Write([]byte(out.GitCommonDir))
	hash.Write([]byte{0})
	hash.Write([]byte(cwd))
	hash.Write([]byte{0})
	hash.Write([]byte(kind))
	hash.Write([]byte(head))
	out.Digest = hex.EncodeToString(hash.Sum(nil))
	return out, nil
}
