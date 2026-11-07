package mcp

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

var errTestIO = errors.New("test I/O failure")

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errTestIO }

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, errTestIO }

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

const initializeRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18"}}`

func TestServeReturnsPersistentReadError(t *testing.T) {
	var out bytes.Buffer
	if err := (&Server{}).Serve(errorReader{}, &out); !errors.Is(err, errTestIO) {
		t.Fatalf("Serve error = %v, want %v", err, errTestIO)
	}
	if out.Len() != 0 {
		t.Fatalf("read failure misreported as a protocol response: %s", out.String())
	}
}

func TestServeReturnsWriteErrors(t *testing.T) {
	for name, input := range map[string]string{
		"ordinary request":  initializeRequest + "\n",
		"oversized request": strings.Repeat(" ", MaxLine+1) + "\n",
	} {
		t.Run(name, func(t *testing.T) {
			if err := (&Server{}).Serve(strings.NewReader(input), errorWriter{}); !errors.Is(err, errTestIO) {
				t.Fatalf("Serve error = %v, want %v", err, errTestIO)
			}
		})
	}
}

func TestServeReturnsShortWrite(t *testing.T) {
	err := (&Server{}).Serve(strings.NewReader(initializeRequest+"\n"), shortWriter{})
	if !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("Serve error = %v, want %v", err, io.ErrShortWrite)
	}
}

func TestServeOversizedLineDoesNotHideFollowingRequest(t *testing.T) {
	input := strings.Repeat(" ", MaxLine+1) + "\n" + initializeRequest + "\n"
	var out bytes.Buffer
	if err := (&Server{}).Serve(strings.NewReader(input), &out); err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "request line too long") || !strings.Contains(lines[1], "protocolVersion") {
		t.Fatalf("unexpected responses: %q", out.String())
	}
}
