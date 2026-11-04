package main

import (
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"
	"time"
)

// credentialVault never receives a user-selected keychain service or path.
// Item IDs are immutable application-generated identifiers.
type credentialVault interface {
	Name() string
	Available() error
	Put(context.Context, string, string) error
	Get(context.Context, string) (string, error)
	Delete(context.Context, string) error
}

const credentialService = "agent-harness-console"

var errVault = errors.New("native credential store unavailable; unlock or configure your operating system credential store")

func validVaultItem(id string) bool {
	if len(id) != 32 {
		return false
	}
	for _, c := range id {
		if !strings.ContainsRune("0123456789abcdef", c) {
			return false
		}
	}
	return true
}
func validSecret(value string) bool {
	return len(value) >= 8 && len(value) <= 8192 && !strings.ContainsAny(value, "\x00\r\n")
}

// Bounded subprocess output is private memory. Never include it in API errors.
func credentialCommand(ctx context.Context, binary string, args []string, input string) (string, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 8*time.Second)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, binary, args...)
	cmd.Stdin = strings.NewReader(input)
	output := &cappedBuffer{limit: 32768}
	cmd.Stdout = output
	cmd.Stderr = io.Discard
	if cmd.Run() != nil {
		return "", errVault
	}
	return string(output.data), nil
}

// A stream retains any suffix which could start a secret. It scans before
// emitting, including matches that extend beyond the otherwise safe prefix.
type secretStream struct {
	secrets []string
	pending string
	longest int
}

func makeSecretStream(values []string) *secretStream {
	s := &secretStream{}
	for _, v := range values {
		if v != "" {
			s.secrets = append(s.secrets, v)
			if len(v) > s.longest {
				s.longest = len(v)
			}
		}
	}
	return s
}
func (s *secretStream) Push(value string) string { s.pending += value; return s.drain(false) }
func (s *secretStream) Flush() string            { return s.drain(true) }
func (s *secretStream) drain(final bool) string {
	limit := len(s.pending)
	if !final && s.longest > 1 {
		limit -= s.longest - 1
	}
	if limit < 0 {
		limit = 0
	}
	var out strings.Builder
	i := 0
	for i < limit {
		match := 0
		for _, secret := range s.secrets {
			if strings.HasPrefix(s.pending[i:], secret) && len(secret) > match {
				match = len(secret)
			}
		}
		if match > 0 {
			out.WriteString("[REDACTED]")
			i += match
			continue
		}
		// UTF-8 bytes are retained together, avoiding malformed incremental JSON text.
		n := 1
		for i+n < len(s.pending) && s.pending[i+n]&0xc0 == 0x80 {
			n++
		}
		if !final && i+n > limit {
			break
		}
		out.WriteString(s.pending[i : i+n])
		i += n
	}
	s.pending = s.pending[i:]
	return out.String()
}
