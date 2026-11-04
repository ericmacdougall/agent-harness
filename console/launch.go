package main

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
	"unicode/utf16"
)

func openURL(url string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		command = exec.Command("/usr/bin/open", url)
	case "windows":
		command = exec.Command("rundll32.exe", "url.dll,FileProtocolHandler", url)
	default:
		command = exec.Command("xdg-open", url)
	}
	if e := command.Start(); e != nil {
		return e
	}
	go func() { _ = command.Wait() }()
	return nil
}
func shellQuote(value string) string      { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }
func powershellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "''") + "'" }
func windowsArgument(value string) string {
	result := "\""
	slashes := 0
	for _, r := range value {
		if r == '\\' {
			slashes++
			continue
		}
		if r == '"' {
			result += strings.Repeat("\\", slashes*2+1) + "\""
		} else {
			result += strings.Repeat("\\", slashes) + string(r)
		}
		slashes = 0
	}
	return result + strings.Repeat("\\", slashes*2) + "\""
}
func encodedPowerShell(script string) string {
	runes := utf16.Encode([]rune(script))
	data := make([]byte, len(runes)*2)
	for i, value := range runes {
		binary.LittleEndian.PutUint16(data[i*2:], value)
	}
	return base64.StdEncoding.EncodeToString(data)
}
func launchTerminal(binary, cwd, dir string, args ...string) error {
	var command *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		path := filepath.Join(dir, "launch-"+freshID()+".command")
		contents := "#!/bin/sh\ncd " + shellQuote(cwd) + " || exit 1\nexec " + shellQuote(binary) + func() string {
			result := ""
			for _, arg := range args {
				result += " " + shellQuote(arg)
			}
			return result
		}() + "\n"
		if e := os.WriteFile(path, []byte(contents), 0700); e != nil {
			return e
		}
		command = exec.Command("/usr/bin/open", "-a", "Terminal", path)
	case "windows":
		script := "Start-Process -FilePath " + powershellQuote(binary) + " -WorkingDirectory " + powershellQuote(cwd) + " -ArgumentList @(" + func() string {
			quoted := []string{}
			for _, arg := range args {
				quoted = append(quoted, powershellQuote(windowsArgument(arg)))
			}
			return strings.Join(quoted, ",")
		}() + ")"
		command = exec.Command("powershell.exe", "-NoProfile", "-NonInteractive", "-EncodedCommand", encodedPowerShell(script))
	default:
		if terminal, e := exec.LookPath("gnome-terminal"); e == nil {
			command = exec.Command(terminal, append([]string{"--working-directory", cwd, "--", binary}, args...)...)
		} else if terminal, e = exec.LookPath("xterm"); e == nil {
			command = exec.Command(terminal, append([]string{"-e", binary}, args...)...)
			command.Dir = cwd
		} else {
			return errors.New("install a terminal emulator to open a CLI window")
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command.Stdout = &cappedBuffer{limit: 4096}
	command.Stderr = &cappedBuffer{limit: 4096}
	done := make(chan error, 1)
	if e := command.Start(); e != nil {
		return e
	}
	go func() { done <- command.Wait() }()
	select {
	case e := <-done:
		return e
	case <-ctx.Done():
		return errors.New("terminal launch outcome is unknown")
	}
}
func (a *app) launchHTTP(w http.ResponseWriter, r *http.Request) {
	var input struct {
		SessionID string `json:"sessionId"`
		Provider  string `json:"provider"`
	}
	if e := decodeJSON(w, r, &input); e != nil {
		apiError(w, e)
		return
	}
	a.mu.Lock()
	current := a.findLocked(input.SessionID)
	if current == nil {
		a.mu.Unlock()
		apiError(w, errors.New("session not found"))
		return
	}
	cwd := current.CWD
	profile := ""
	if input.Provider == current.Provider {
		profile = current.ProfileID
	}
	a.mu.Unlock()
	binary, args, e := a.prepareCLILaunch(input.Provider, profile, cwd)
	if e != nil {
		apiError(w, e)
		return
	}
	if e = launchTerminal(binary, cwd, a.dataDir, args...); e != nil {
		apiError(w, e)
		return
	}
	writeJSON(w, 200, map[string]string{"status": "LAUNCH_REQUESTED", "note": "The operating system accepted the terminal request; CLI readiness is not confirmed"})
}
