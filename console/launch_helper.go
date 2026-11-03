package main

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"os/exec"
	"path/filepath"
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
	command.Dir = ticket.CWD
	command.Env = env
	command.Stdin = in
	command.Stdout = out
	command.Stderr = errOut
	return command.Run()
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
