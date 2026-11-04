package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"time"
)

type goodqaHTTP struct {
	endpoint, token, session, protocol string
	next                               uint64
	client                             *http.Client
	timeout                            time.Duration
}
type goodqaPacket struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}
type goodqaOutcomeError struct {
	message string
	unknown bool
}

func (e *goodqaOutcomeError) Error() string { return e.message }

func newGoodQAHTTP(endpoint, token string) *goodqaHTTP {
	return &goodqaHTTP{endpoint: endpoint, token: token, timeout: 10 * time.Second, client: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirect refused") }}}
}
func (c *goodqaHTTP) initialize(ctx context.Context) error {
	raw, e := c.call(ctx, "initialize", map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{}, "clientInfo": map[string]string{"name": "agent-harness-goodqa-proxy", "version": version}})
	if e != nil {
		return e
	}
	var result struct {
		ProtocolVersion string `json:"protocolVersion"`
		Capabilities    struct {
			Tools json.RawMessage `json:"tools"`
		} `json:"capabilities"`
	}
	if json.Unmarshal(raw, &result) != nil || !oneOf(result.ProtocolVersion, "2025-03-26", "2025-06-18") || len(result.Capabilities.Tools) == 0 {
		return errors.New("GoodQA did not negotiate supported tools protocol")
	}
	c.protocol = result.ProtocolVersion
	return c.notify(ctx, "notifications/initialized", map[string]any{})
}
func (c *goodqaHTTP) request(ctx context.Context, packet goodqaPacket) (*http.Response, error) {
	body, _ := json.Marshal(packet)
	if len(body) > goodqaFrameLimit {
		return nil, errors.New("GoodQA request exceeds bound")
	}
	req, e := http.NewRequestWithContext(ctx, "POST", c.endpoint, bytes.NewReader(body))
	if e != nil {
		return nil, errors.New("invalid GoodQA request endpoint")
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if c.session != "" {
		req.Header.Set("Mcp-Session-Id", c.session)
	}
	if c.protocol != "" {
		req.Header.Set("MCP-Protocol-Version", c.protocol)
	}
	resp, e := c.client.Do(req)
	if e != nil {
		return nil, errors.New("GoodQA transport failed; no raw transport diagnostic retained")
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		resp.Body.Close()
		return nil, fmt.Errorf("GoodQA returned HTTP %d", resp.StatusCode)
	}
	if session := resp.Header.Get("Mcp-Session-Id"); session != "" {
		if len(session) > 256 {
			resp.Body.Close()
			return nil, errors.New("invalid GoodQA session identifier")
		}
		for _, b := range []byte(session) {
			if b < 0x21 || b > 0x7e {
				resp.Body.Close()
				return nil, errors.New("invalid GoodQA session identifier")
			}
		}
		if c.session != "" && c.session != session {
			resp.Body.Close()
			return nil, errors.New("GoodQA unexpectedly changed session")
		}
		c.session = session
	}
	return resp, nil
}
func (c *goodqaHTTP) notify(ctx context.Context, method string, params any) error {
	raw, _ := json.Marshal(params)
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, e := c.request(ctx, goodqaPacket{JSONRPC: "2.0", Method: method, Params: raw})
	if e != nil {
		return e
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		return errors.New("GoodQA did not acknowledge lifecycle notification")
	}
	return nil
}
func (c *goodqaHTTP) call(ctx context.Context, method string, params any) (json.RawMessage, error) {
	c.next++
	id := json.RawMessage(fmt.Sprint(c.next))
	raw, _ := json.Marshal(params)
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	resp, e := c.request(ctx, goodqaPacket{JSONRPC: "2.0", ID: id, Method: method, Params: raw})
	if e != nil {
		return nil, &goodqaOutcomeError{message: "GoodQA request outcome unavailable after transport attempt; do not replay automatically", unknown: method == "tools/call"}
	}
	defer resp.Body.Close()
	result, e := c.readResponse(ctx, resp, id)
	if e == nil && method == "tools/call" {
		e = goodqaValidateCallResult(result, c.protocol)
	}
	if e != nil {
		return nil, &goodqaOutcomeError{message: "GoodQA response invalid, incomplete or unsupported; request outcome unavailable", unknown: method == "tools/call"}
	}
	return result, nil
}
func (c *goodqaHTTP) readResponse(ctx context.Context, resp *http.Response, id json.RawMessage) (json.RawMessage, error) {
	validate := func(raw []byte) (json.RawMessage, bool, error) {
		if len(raw) > goodqaFrameLimit || settingsUniqueJSON(raw) != nil {
			return nil, false, errors.New("invalid bounded MCP JSON")
		}
		var p goodqaPacket
		if json.Unmarshal(raw, &p) != nil || p.JSONRPC != "2.0" {
			return nil, false, errors.New("invalid MCP packet")
		}
		if p.Method != "" {
			if len(p.ID) > 0 {
				c.rejectServerRequest(ctx, p.ID)
				return nil, false, errors.New("unsupported server-initiated MCP request")
			}
			return nil, false, nil
		}
		if !bytes.Equal(bytes.TrimSpace(p.ID), id) || len(p.Result) == 0 || len(p.Error) > 0 {
			return nil, false, errors.New("mismatched or failed MCP response")
		}
		return p.Result, true, nil
	}
	contentType, _, mediaErr := mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if mediaErr != nil {
		return nil, errors.New("invalid MCP content type")
	}
	if contentType == "application/json" {
		raw, e := io.ReadAll(io.LimitReader(resp.Body, goodqaFrameLimit+1))
		if e != nil {
			return nil, e
		}
		result, done, e := validate(raw)
		if e != nil || !done {
			return nil, errors.New("unexpected MCP JSON response")
		}
		return result, nil
	}
	if contentType != "text/event-stream" {
		return nil, errors.New("unsupported MCP response type")
	}
	scanner := bufio.NewScanner(io.LimitReader(resp.Body, goodqaFrameLimit+1))
	scanner.Buffer(make([]byte, 4096), goodqaFrameLimit)
	event := []string{}
	total, notifications := 0, 0
	for scanner.Scan() {
		line := scanner.Text()
		total += len(line) + 1
		if total > goodqaFrameLimit {
			return nil, errors.New("MCP stream exceeds bound")
		}
		if line == "" {
			if len(event) > 0 {
				result, done, e := validate([]byte(strings.Join(event, "\n")))
				if e != nil {
					return nil, e
				}
				if done {
					return result, nil
				}
				notifications++
				if notifications > 32 {
					return nil, errors.New("too many MCP notifications")
				}
				event = nil
			}
			continue
		}
		if strings.HasPrefix(line, "data:") {
			event = append(event, strings.TrimSpace(strings.TrimPrefix(line, "data:")))
		}
	}
	return nil, errors.New("MCP stream closed before complete response")
}
func (c *goodqaHTTP) rejectServerRequest(ctx context.Context, id json.RawMessage) {
	if !goodqaValidID(id) {
		return
	}
	raw := json.RawMessage(`{"code":-32601,"message":"Server-initiated requests unsupported by this tools-only proxy"}`)
	resp, e := c.request(ctx, goodqaPacket{JSONRPC: "2.0", ID: id, Error: raw})
	if e == nil {
		resp.Body.Close()
	}
}

func (c *goodqaHTTP) tools(ctx context.Context) ([]goodqaTool, error) {
	out := []goodqaTool{}
	cursor := ""
	seen := map[string]bool{}
	for page := 0; page < 8; page++ {
		params := map[string]any{}
		if cursor != "" {
			params["cursor"] = cursor
		}
		raw, e := c.call(ctx, "tools/list", params)
		if e != nil {
			return nil, e
		}
		var result struct {
			Tools      []goodqaTool `json:"tools"`
			NextCursor string       `json:"nextCursor"`
		}
		if json.Unmarshal(raw, &result) != nil || len(out)+len(result.Tools) > 512 || len(result.NextCursor) > 1024 {
			return nil, errors.New("invalid or oversized GoodQA catalog")
		}
		for _, tool := range result.Tools {
			if !goodqaToolName.MatchString(tool.Name) || seen[tool.Name] || len(tool.InputSchema) == 0 {
				return nil, errors.New("invalid or duplicate GoodQA tool")
			}
			seen[tool.Name] = true
			out = append(out, tool)
		}
		if result.NextCursor == "" {
			return out, nil
		}
		if result.NextCursor == cursor {
			return nil, errors.New("GoodQA cursor did not advance")
		}
		cursor = result.NextCursor
	}
	return nil, errors.New("GoodQA catalog pagination exceeds bound")
}

// Decode, filter every string/key, then encode. Replacing raw JSON would miss
// escaped echoes or produce invalid JSON when a secret appeared in a number.
func goodqaFilterJSON(value any, secrets []string) any {
	data, _ := json.Marshal(value)
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var decoded any
	if decoder.Decode(&decoded) != nil {
		return map[string]any{"error": "GoodQA output could not be safely encoded"}
	}
	clean := func(s string) string { r := makeSecretStream(secrets); r.pending = s; return r.Flush() }
	var visit func(any) any
	visit = func(v any) any {
		switch x := v.(type) {
		case string:
			return clean(x)
		case json.Number:
			if clean(string(x)) != string(x) {
				return "[REDACTED]"
			}
			return x
		case []any:
			for i := range x {
				x[i] = visit(x[i])
			}
			return x
		case map[string]any:
			out := map[string]any{}
			for k, v := range x {
				out[clean(k)] = visit(v)
			}
			return out
		default:
			return x
		}
	}
	return visit(decoded)
}
