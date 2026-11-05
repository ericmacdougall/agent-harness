package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type rpcPacket struct {
	ID     json.RawMessage `json:"id,omitempty"`
	Method string          `json:"method,omitempty"`
	Params json.RawMessage `json:"params,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
	Error  *rpcError       `json:"error,omitempty"`
}
type providerRejectedError struct{ Message string }

func (e *providerRejectedError) Error() string { return "provider rejected request: " + e.Message }

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}
type rpcClient struct {
	disconnected atomic.Bool

	runtimeHash string
	authAdmit   inputAdmission
	mu          sync.Mutex
	writeOnce   sync.Once
	writer      *inputWriter
	next        uint64
	pending     map[string]chan rpcPacket
	input       io.WriteCloser
	command     *exec.Cmd
	tree        *processTree
	done        chan struct{}
	closeOnce   sync.Once
	onEvent     func(*rpcClient, string, json.RawMessage)
	onRequest   func(*rpcClient, rpcPacket)
	onClose     func(*rpcClient, error)
}

func startRPC(binary string, env []string, onEvent func(*rpcClient, string, json.RawMessage), onRequest func(*rpcClient, rpcPacket), onClose func(*rpcClient, error), configArgs ...string) (*rpcClient, error) {
	return startRPCWithAuthority(binary, env, nil, onEvent, onRequest, onClose, configArgs...)
}

func startRPCWithAuthority(binary string, env []string, authAdmit inputAdmission, onEvent func(*rpcClient, string, json.RawMessage), onRequest func(*rpcClient, rpcPacket), onClose func(*rpcClient, error), configArgs ...string) (*rpcClient, error) {
	args := append([]string{"app-server", "--stdio"}, configArgs...)
	command := exec.Command(binary, args...)
	command.Env = env
	configureProcess(command)
	input, err := command.StdinPipe()
	if err != nil {
		return nil, err
	}
	// Provider diagnostics can contain local paths and account information.
	// They remain outside the HTTP response and are bounded in memory.
	command.Stderr = &cappedBuffer{limit: 32768}
	tree, err := startProcessTree(command, nil)
	if err != nil {
		return nil, err
	}
	output := tree.Stdout()
	client := &rpcClient{pending: map[string]chan rpcPacket{}, input: input, command: command, tree: tree, done: make(chan struct{}), authAdmit: authAdmit, onEvent: onEvent, onRequest: onRequest, onClose: onClose}
	go func() {
		client.read(output)
		// Once its stream ends this provider cannot be supervised. The tree stops
		// the whole group while the leader still pins the group ID.
		client.stopTree()
		<-tree.Done()
		client.finish(tree.Err())
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	params := map[string]any{"clientInfo": map[string]any{"name": "agent-harness-console", "version": version}, "capabilities": map[string]any{"experimentalApi": true}}
	if err = client.call(ctx, "initialize", params, nil); err != nil {
		client.close()
		return nil, fmt.Errorf("Codex initialization failed: %w", err)
	}
	if err = client.write(map[string]any{"method": "initialized", "params": map[string]any{}}); err != nil {
		client.close()
		return nil, err
	}
	return client, nil
}

func (c *rpcClient) read(reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 65536), 2<<20)
	for scanner.Scan() {
		var packet rpcPacket
		if err := json.Unmarshal(scanner.Bytes(), &packet); err != nil {
			c.finish(errors.New("provider emitted malformed JSON"))
			return
		}
		if len(packet.ID) > 0 && packet.Method == "" {
			c.mu.Lock()
			ch := c.pending[string(packet.ID)]
			delete(c.pending, string(packet.ID))
			c.mu.Unlock()
			if ch != nil {
				ch <- packet
			}
			continue
		}
		if len(packet.ID) > 0 {
			if c.onRequest != nil {
				c.onRequest(c, packet)
			}
		} else if packet.Method != "" && c.onEvent != nil {
			c.onEvent(c, packet.Method, packet.Params)
		}
	}
	if err := scanner.Err(); err != nil {
		c.finish(errors.New("provider stream exceeded its bound or closed unexpectedly"))
	}
}

func (c *rpcClient) finish(err error) {
	c.closeOnce.Do(func() {
		c.writeOnce.Do(func() { c.writer = newInputWriter(c.input) })
		c.writer.close()
		close(c.done)
		if c.onClose != nil {
			c.onClose(c, err)
		}
	})
}
func (c *rpcClient) write(value any) error { return c.writeContext(context.Background(), value) }
func (c *rpcClient) writeContext(ctx context.Context, value any) error {
	return c.writeAdmitted(ctx, value, nil)
}
func (c *rpcClient) writeAdmitted(ctx context.Context, value any, admit inputAdmission) error {
	if c.disconnected.Load() {
		return refused("provider connection authority revoked")
	}
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	c.writeOnce.Do(func() { c.writer = newInputWriter(c.input) })
	select {
	case <-c.done:
		return errors.New("provider connection is closed")
	default:
	}
	err = c.writer.writeAdmitted(ctx, append(data, '\n'), func() (func(), error) {
		if c.disconnected.Load() {
			return nil, refused("provider connection authority revoked")
		}
		var authRelease, release func()
		var err error
		if c.authAdmit != nil {
			authRelease, err = c.authAdmit()
			if err != nil {
				return authRelease, err
			}
		}
		if admit != nil {
			release, err = admit()
			if err != nil {
				if authRelease != nil {
					authRelease()
				}
				return release, err
			}
		}
		releaseAll := func() {
			if release != nil {
				release()
			}
			if authRelease != nil {
				authRelease()
			}
		}
		// Admission itself may have waited across a disconnect.
		if c.disconnected.Load() {
			releaseAll()
			return nil, refused("provider connection authority revoked")
		}
		return releaseAll, nil
	})
	if err != nil && !isDispatchRefused(err) {
		go func() { c.finish(err); c.stopTree() }()
	}
	return err
}

func (c *rpcClient) call(ctx context.Context, method string, params any, out any) error {
	return c.callAdmitted(ctx, method, params, out, nil)
}
func (c *rpcClient) callAdmitted(ctx context.Context, method string, params any, out any, admit inputAdmission) error {
	c.mu.Lock()
	if len(c.pending) >= 128 {
		c.mu.Unlock()
		return errors.New("provider request capacity reached")
	}
	c.next++
	id := c.next
	key := strconv.FormatUint(id, 10)
	ch := make(chan rpcPacket, 1)
	c.pending[key] = ch
	c.mu.Unlock()
	defer func() { c.mu.Lock(); delete(c.pending, key); c.mu.Unlock() }()
	if err := c.writeAdmitted(ctx, map[string]any{"id": id, "method": method, "params": params}, admit); err != nil {
		return err
	}
	var reply rpcPacket
	select {
	case reply = <-ch:
	case <-ctx.Done():
		select {
		case reply = <-ch:
		default:
			return errors.New("provider request outcome is unknown after timeout")
		}
	case <-c.done:
		select {
		case reply = <-ch:
		default:
			return errors.New("provider disconnected; request outcome is unknown")
		}
	}
	if reply.Error != nil {
		return &providerRejectedError{Message: reply.Error.Message}
	}
	if out != nil {
		return json.Unmarshal(reply.Result, out)
	}
	return nil
}
func (c *rpcClient) respond(id json.RawMessage, result any) error {
	return c.write(map[string]any{"id": id, "result": result})
}
func (c *rpcClient) reject(id json.RawMessage, reason string) error {
	return c.write(map[string]any{"id": id, "error": map[string]any{"code": -32601, "message": reason}})
}
func (c *rpcClient) close() {
	c.writeOnce.Do(func() { c.writer = newInputWriter(c.input) })
	c.writer.close()
	select {
	case <-c.done:
		return
	case <-time.After(500 * time.Millisecond):
	}
	c.stopTree()
}

// stopTree ends the provider's whole process group.
func (c *rpcClient) stopTree() {
	if c.tree != nil {
		c.tree.Release(true)
		c.tree.Terminate(100 * time.Millisecond)
		return
	}
	terminateProcess(c.command)
}

type cappedBuffer struct {
	mu    sync.Mutex
	data  []byte
	limit int
}

func (b *cappedBuffer) Write(data []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - len(b.data)
	if remaining > 0 {
		if remaining > len(data) {
			remaining = len(data)
		}
		b.data = append(b.data, data[:remaining]...)
	}
	return len(data), nil
}
