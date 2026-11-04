package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Unreleased: see baseline_guard.go. Never package or install this tree.
const version = "0.2.0-unreleased-baseline"

var settingsInit func(*app) error
var settingsRegister func(*http.ServeMux, *app)
var settingsHelperMain func([]string, io.Reader, io.Writer, io.Writer) (bool, error)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "Console:", err)
		os.Exit(1)
	}
}
func run(args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "--launch-cli" {
		return runCLILaunch(args[1:], os.Stdin, out, os.Stderr)
	}
	if len(args) == 1 && args[0] == "--checkpoint-mcp" {
		return runCheckpointMCP(os.Stdin, out)
	}
	if settingsHelperMain != nil {
		handled, err := settingsHelperMain(args, os.Stdin, out, os.Stderr)
		if handled {
			return err
		}
	}
	flags := flag.NewFlagSet("harness-console", flag.ContinueOnError)
	flags.SetOutput(out)
	cwd := flags.String("cwd", ".", "Initial working directory")
	refFile := flags.String("reference-file", "", "Private supplied current-context file")
	refSHA := flags.String("reference-sha256", "", "SHA-256 of exact reference bytes")
	provider := flags.String("provider", "", "Initial provider: codex or claude (saved default when omitted)")
	sourceID := flags.String("session", "", "Explicit source conversation to import as context")
	readyFile := flags.String("ready-file", "", "Private GUI readiness receipt path")
	noOpen := flags.Bool("no-open", false, "Print the local URL without opening a browser")
	listen := flags.String("listen", "127.0.0.1:0", "Loopback listener address")
	dataDir := flags.String("data-dir", "", "New private directory for this unreleased baseline (required)")
	showVersion := flags.Bool("version", false, "Print version")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return nil
		}
		return err
	}
	if *showVersion {
		fmt.Fprintln(out, "Agent Harness Console", version)
		return nil
	}
	admitted, err := baselineDataDir(*dataDir, protectedRoot())
	if err != nil {
		return err
	}
	*dataDir = admitted
	host, _, err := net.SplitHostPort(*listen)
	if err != nil || host != "127.0.0.1" {
		return fmt.Errorf("listen address must use127.0.0.1")
	}
	directory, err := validCWD(*cwd)
	if err != nil {
		return err
	}
	ref, err := loadReference(*refFile, *refSHA)
	if err != nil {
		return err
	}
	a, err := newApp(*dataDir, ref)
	if err != nil {
		return err
	}
	defer a.close()
	a.defaultCWD = directory
	if settingsInit != nil {
		if err = settingsInit(a); err != nil {
			return err
		}
	}
	listener, err := net.Listen("tcp4", *listen)
	if err != nil {
		return err
	}
	tokenBytes := make([]byte, 32)
	if _, err = rand.Read(tokenBytes); err != nil {
		listener.Close()
		return err
	}
	token := hex.EncodeToString(tokenBytes)
	origin := "http://" + listener.Addr().String()
	a.origin = origin
	server := &http.Server{Handler: a.handler(listener.Addr().String(), token), ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384}
	stopped := make(chan struct{})
	var shutdownOnce sync.Once
	a.shutdown = func() { shutdownOnce.Do(func() { close(stopped) }) }
	go func() { _ = server.Serve(listener); a.shutdown() }()
	if err = writeReadiness(*readyFile, origin); err != nil {
		_ = server.Close()
		return err
	}
	address := origin + "/#token=" + token
	// The bootstrap capability is shown only for an explicitly requested local automation launch.
	if *noOpen {
		fmt.Fprintln(out, address)
	} else if err = openURL(address); err != nil {
		fmt.Fprintln(out, "Open the local console at", address)
	}
	go func() {
		current, e := a.createSession(*provider, directory, "")
		if e != nil {
			return
		}
		if ref != nil {
			a.mu.Lock()
			current.context = ref.Body
			a.addMessageLocked(current, message{Role: "context", Text: ref.Title + "\n\n" + ref.Body})
			a.changedLocked()
			a.mu.Unlock()
		}
		imported := *sourceID
		if imported == "" && ref != nil && strings.Contains(strings.ToLower(ref.Client), "codex") {
			imported = ref.SessionID
		}
		if imported != "" && current.Provider == "codex" {
			a.importContext(current, imported)
		}
	}()
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	select {
	case <-signals:
	case <-stopped:
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = server.Shutdown(ctx)
	_ = server.Close()
	return nil
}
