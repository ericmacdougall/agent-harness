package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepairOwnerFeatureWorktreeSubjectWithoutMovingMain(t *testing.T) {
	base, _ := filepath.EvalSymlinks(t.TempDir())
	main := filepath.Join(base, "main")
	if err := os.Mkdir(main, 0700); err != nil {
		t.Fatal(err)
	}
	git := func(cwd string, args ...string) string {
		t.Helper()
		out, err := gitOutput(cwd, args...)
		if err != nil {
			t.Fatalf("git %v: %v", args, err)
		}
		return strings.TrimSpace(out)
	}
	git(main, "init", "-b", "main")
	git(main, "config", "user.name", "Console Test")
	git(main, "config", "user.email", "test@example.invalid")
	_ = os.WriteFile(filepath.Join(main, "proof.txt"), []byte("initial"), 0600)
	git(main, "add", "proof.txt")
	git(main, "commit", "-m", "initial")
	original := git(main, "rev-parse", "HEAD")
	feature := filepath.Join(base, "feature")
	git(main, "worktree", "add", "-b", "feature", feature)
	_ = os.WriteFile(filepath.Join(feature, "proof.txt"), []byte("feature proof"), 0600)
	git(feature, "add", "proof.txt")
	git(feature, "commit", "-m", "feature")
	head := git(feature, "rev-parse", "HEAD")
	root, err := allowedSubjectRoot(main, feature)
	if err != nil || root != feature {
		t.Fatal("registered owner worktree refused", err)
	}
	a, err := newApp(t.TempDir(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer a.close()
	subject, err := a.captureSubject(root, "code", head, []string{"proof.txt"})
	if err != nil || subject.Root != feature || subject.Head == original {
		t.Fatal("feature subject not captured", err)
	}
	if git(main, "rev-parse", "HEAD") != original {
		t.Fatal("review moved main checkout")
	}
	foreign := filepath.Join(base, "foreign")
	_ = os.Mkdir(foreign, 0700)
	git(foreign, "init", "-b", "main")
	if _, err = allowedSubjectRoot(main, foreign); err == nil {
		t.Fatal("foreign repository admitted")
	}
	_ = os.WriteFile(filepath.Join(feature, "proof.txt"), []byte("dirty"), 0600)
	if _, err = a.captureSubject(feature, "code", head, []string{"proof.txt"}); err == nil {
		t.Fatal("same-head dirty feature worktree admitted")
	}
}
