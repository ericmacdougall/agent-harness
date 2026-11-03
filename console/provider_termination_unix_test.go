//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func providerScript(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "provider.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}

func recordedPID(t *testing.T, path string) int {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if data, err := os.ReadFile(path); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil && pid > 0 {
				return pid
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("provider never recorded its pid")
	return 0
}

// A zombie awaiting Wait still answers signal 0, so poll for real exit.
func waitForExit(pid int) bool {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return true
		}
		time.Sleep(20 * time.Millisecond)
	}
	return false
}

// A disconnected provider is a quarantined writer: its whole tree has to stop,
// or it keeps working while the console reports it gone.
func TestProviderTreeStopsOnEveryReadFailure(t *testing.T) {
	cases := map[string]string{
		"overflow":  `head -c 3000000 /dev/zero | tr '\0' a; echo`,
		"malformed": `echo not-json`,
	}
	for name, failure := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			leader, child := filepath.Join(dir, "leader"), filepath.Join(dir, "child")
			script := providerScript(t, `echo $$ > "`+leader+`"
sh -c 'echo $$ > "`+child+`"; exec sleep 30' &
until [ -s "`+child+`" ]; do sleep 0.01; done
read line
printf '{"id":1,"result":{}}\n'
read line
`+failure+`
sleep 30
`)
			closed := make(chan struct{})
			client, err := startRPC(script, os.Environ(), nil, nil, func(*rpcClient, error) { close(closed) })
			if err != nil {
				t.Fatal(err)
			}
			leaderPID, childPID := recordedPID(t, leader), recordedPID(t, child)
			t.Cleanup(func() { _ = syscall.Kill(-leaderPID, syscall.SIGKILL) })
			select {
			case <-closed:
			case <-time.After(5 * time.Second):
				t.Fatal("read failure did not disconnect the provider")
			}
			client.close()
			if !waitForExit(leaderPID) {
				t.Fatalf("provider leader %d survived %s", leaderPID, name)
			}
			if !waitForExit(childPID) {
				t.Fatalf("provider descendant %d survived %s", childPID, name)
			}
		})
	}
}
