package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type cliLaunchTicket struct {
	Schema   int    `json:"schema"`
	DataDir  string `json:"dataDir"`
	Provider string `json:"provider"`
	Profile  string `json:"profile"`
	Revision string `json:"revision"`
	CWD      string `json:"cwd"`
	Expires  string `json:"expires"`
}

func (a *app) prepareCLILaunch(provider, profile, cwd string) (string, []string, error) {
	policy, err := a.policyFor(provider, profile, "main")
	if err != nil {
		return "", nil, err
	}
	if _, _, _, err = a.resolveRuntime(policy); err != nil {
		return "", nil, err
	}
	directory := filepath.Join(a.dataDir, "launches")
	if err = settingsPrivateDirectory(directory); err != nil {
		return "", nil, err
	}
	ticket := cliLaunchTicket{Schema: 1, DataDir: a.dataDir, Provider: policy.Provider, Profile: policy.ProfileID, Revision: policy.Revision, CWD: cwd, Expires: time.Now().Add(2 * time.Minute).UTC().Format(time.RFC3339)}
	data, _ := json.Marshal(ticket)
	path := filepath.Join(directory, freshID()+".json")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", nil, err
	}
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	file.Close()
	if err != nil {
		return "", nil, err
	}
	binary, err := os.Executable()
	return binary, []string{"--launch-cli", "--ticket", path, "--sha256", settingsDigest(data)}, err
}
func runCLILaunch(args []string, in io.Reader, out, errOut io.Writer) error {
	flags := flag.NewFlagSet("launch-cli", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("ticket", "", "private launch metadata")
	digest := flags.String("sha256", "", "metadata digest")
	if flags.Parse(args) != nil || flags.NArg() != 0 {
		return errors.New("invalid launch admission")
	}
	ticket, err := loadCLILaunchTicket(*path, *digest)
	if err != nil {
		return err
	}
	// Before the ticket is consumed or settings are opened.
	if err = baselineAdmitted(ticket.DataDir); err != nil {
		return err
	}
	if err = os.Remove(*path); err != nil {
		return errors.New("launch ticket already consumed or unavailable")
	}
	settings, err := openSettings(ticket.DataDir, newCredentialVault())
	if err != nil {
		return err
	}
	a := &app{runtime: settings.runtime, resolvePolicy: settings.policy}
	policy, err := a.policyFor(ticket.Provider, ticket.Profile, "main")
	if err != nil || policy.Revision != ticket.Revision {
		return errors.New("settings changed before CLI launch; request a fresh launch")
	}
	binary, env, _, err := a.resolveRuntime(policy)
	if err != nil {
		return err
	}
	return executeCLILaunch(ticket, binary, env, in, out, errOut)
}
func executeCLILaunch(ticket cliLaunchTicket, binary string, env []string, in io.Reader, out, errOut io.Writer) error {
	actualCWD, err := validCWD(ticket.CWD)
	if err != nil || actualCWD != ticket.CWD {
		return errors.New("launch working directory changed or was redirected")
	}
	command := exec.Command(binary)
	if wrap, tmuxBin, session := cliTmuxWrap(env, stdinIsTerminal(in) && stdoutIsTerminal(out), exec.LookPath); wrap {
		command = exec.Command(tmuxBin, tmuxLaunchArgs(session, actualCWD, binary)...)
	}
	command.Dir = ticket.CWD
	command.Env = env
	command.Stdin = in
	command.Stdout = out
	command.Stderr = errOut
	return command.Run()
}

func envLookup(env []string, key string) (string, bool) {
	prefix := key + "="
	for i := len(env) - 1; i >= 0; i-- {
		if strings.HasPrefix(env[i], prefix) {
			return strings.TrimPrefix(env[i], prefix), true
		}
	}
	return "", false
}

func envOrProcess(env []string, key string) string {
	if value, ok := envLookup(env, key); ok {
		return value
	}
	return os.Getenv(key)
}

func stdinIsTerminal(in io.Reader) bool {
	file, ok := in.(*os.File)
	if !ok || file == nil {
		return false
	}
	return fdIsTerminal(int(file.Fd()))
}

func stdoutIsTerminal(out io.Writer) bool {
	file, ok := out.(*os.File)
	if !ok || file == nil {
		return false
	}
	return fdIsTerminal(int(file.Fd()))
}

// cliTmuxWrap reports whether a console CLI launch should run inside tmux, and if so the
// tmux binary and session name. Default is on when tmux is on PATH, stdin is a terminal,
// and the launch is not already inside tmux, on Windows, a test fixture, or explicitly disabled
// with HARNESS_CLI_TMUX=0 or HARNESS_NO_TMUX=1.
func cliTmuxWrap(env []string, isTerminal bool, lookPath func(string) (string, error)) (bool, string, string) {
	if runtime.GOOS == "windows" {
		return false, "", ""
	}
	if envOrProcess(env, "HARNESS_CONSOLE_CLI_FIXTURE") != "" {
		return false, "", ""
	}
	if envOrProcess(env, "HARNESS_CLI_TMUX") == "0" || envOrProcess(env, "HARNESS_NO_TMUX") == "1" {
		return false, "", ""
	}
	if envOrProcess(env, "TMUX") != "" {
		return false, "", ""
	}
	if !isTerminal {
		return false, "", ""
	}
	tmuxBin, err := lookPath("tmux")
	if err != nil || tmuxBin == "" {
		return false, "", ""
	}
	return true, tmuxBin, tmuxSessionName(envOrProcess(env, "HARNESS_CLI_TMUX_SESSION"))
}

func tmuxSessionName(override string) string {
	if override != "" && tmuxSessionNameOK(override) {
		return override
	}
	return "ah-cli-" + freshID()[:12]
}

func tmuxSessionNameOK(name string) bool {
	if name == "" || len(name) > 64 || strings.ContainsAny(name, ":. \t/") || strings.ContainsRune(name, '\n') {
		return false
	}
	for _, r := range name {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '-' && r != '_' {
			return false
		}
	}
	return true
}

func tmuxLaunchArgs(session, cwd, binary string, args ...string) []string {
	// A private socket (-L) starts a dedicated server that inherits this process's
	// environment (command.Env), so API keys are not put on a command line with -e,
	// and the caller's env is not written into the user's default tmux server.
	out := []string{"-u", "-L", session, "new-session", "-c", cwd, "-s", session, "--", binary}
	return append(out, args...)
}
func loadCLILaunchTicket(path, digest string) (cliLaunchTicket, error) {
	var ticket cliLaunchTicket
	data, err := settingsRead(path, 16384)
	if err != nil || settingsDigest(data) != digest || settingsDecode(data, &ticket) != nil {
		return ticket, errors.New("CLI launch metadata changed or is unsafe")
	}
	expiry, err := time.Parse(time.RFC3339, ticket.Expires)
	if err != nil || time.Now().After(expiry) || expiry.After(time.Now().Add(3*time.Minute)) || ticket.Schema != 1 || !oneOf(ticket.Provider, "codex", "claude") || !filepath.IsAbs(ticket.DataDir) || !filepath.IsAbs(ticket.CWD) {
		return ticket, errors.New("CLI launch admission expired or invalid")
	}
	root := filepath.Join(ticket.DataDir, "launches")
	if filepath.Dir(path) != root {
		return ticket, errors.New("launch ticket outside admitted metadata directory")
	}
	return ticket, nil
}
