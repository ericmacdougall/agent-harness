package main

import (
	"errors"
	"path/filepath"
	"strings"
)

func allowedSubjectRoot(cwd, selected string) (string, error) {
	if selected == "" {
		selected = cwd
	}
	root, err := validCWD(selected)
	if err != nil {
		return "", err
	}
	if root == cwd {
		return root, nil
	}

	expected, e := gitCommonDirectory(cwd)
	if e != nil {
		return "", errors.New("foreign review root requires a registered worktree of the current repository")
	}
	actual, e := gitCommonDirectory(root)
	if e != nil || actual != expected {
		return "", errors.New("review root belongs to a different repository")
	}
	trees, e := gitOutput(cwd, "worktree", "list", "--porcelain", "-z")
	if e != nil {
		return "", e
	}
	for _, field := range strings.Split(trees, "\x00") {
		if strings.HasPrefix(field, "worktree ") {
			registered, e := filepath.EvalSymlinks(strings.TrimPrefix(field, "worktree "))
			if e == nil && registered == root {
				return root, nil
			}
		}
	}
	return "", errors.New("review root is not a registered worktree")
}

func gitCommonDirectory(path string) (string, error) {
	value, e := gitOutput(path, "rev-parse", "--git-common-dir")
	if e != nil {
		return "", e
	}
	value = strings.TrimSpace(value)
	if !filepath.IsAbs(value) {
		value = filepath.Join(path, value)
	}
	return filepath.EvalSymlinks(value)
}
