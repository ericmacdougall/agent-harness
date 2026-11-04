package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
)

func writeReadiness(path, origin string) error {
	if path == "" {
		return nil
	}
	parent, err := os.Lstat(filepath.Dir(path))
	if err != nil || !parent.IsDir() || parent.Mode()&os.ModeSymlink != 0 {
		return errors.New("ready-file parent must be a real private directory")
	}
	if runtime.GOOS != "windows" && parent.Mode().Perm() != 0700 {
		return errors.New("ready-file parent requires mode0700")
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("ready-file must be a new private file")
	}
	defer file.Close()
	data, err := json.Marshal(map[string]any{"status": "UI_READY", "origin": origin, "pid": os.Getpid(), "version": version})
	if err != nil {
		return err
	}
	if _, err = file.Write(append(data, '\n')); err != nil {
		return err
	}
	return file.Sync()
}
