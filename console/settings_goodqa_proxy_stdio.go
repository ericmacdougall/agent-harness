package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"unicode/utf8"
)

var goodqaNumericID = regexp.MustCompile(`^-?[0-9]{1,20}$`)

func goodqaValidID(id json.RawMessage) bool {
	if len(id) == 0 || len(id) > 256 {
		return false
	}
	var text string
	if json.Unmarshal(id, &text) == nil {
		return len(text) <= 128
	}
	return goodqaNumericID.Match(bytes.TrimSpace(id))
}

type goodqaStdio struct {
	snapshot           goodqaProxySnapshot
	upstream           *goodqaHTTP
	initialized, ready bool
	protocol           string
	diagnostics        io.Writer
}

func serveGoodQAProxy(ctx context.Context, snapshot goodqaProxySnapshot, vault credentialVault, in io.Reader, out, diagnostics io.Writer) error {
	if e := goodqaCheckAuthority(snapshot, "", true); e != nil {
		return e
	}
	token := ""
	if snapshot.CredentialRef != "" {
		var e error
		token, e = vault.Get(ctx, snapshot.CredentialRef)
		if e != nil || !validSecret(token) {
			return errors.New("GoodQA scoped native credential unavailable")
		}
	}
	secrets := []string{}
	if token != "" {
		secrets = append(secrets, token)
	}
	server := goodqaStdio{snapshot: snapshot, upstream: newGoodQAHTTP(snapshot.Endpoint, token), diagnostics: diagnostics}
	scanner := bufio.NewScanner(in)
	scanner.Buffer(make([]byte, 4096), goodqaFrameLimit)
	seenIDs := map[string]bool{}
	for scanner.Scan() {
		line := scanner.Bytes()
		var request goodqaPacket
		result := any(map[string]any{})
		code := 0
		message := ""
		if !utf8.Valid(line) || settingsUniqueJSON(line) != nil || json.Unmarshal(line, &request) != nil || request.JSONRPC != "2.0" || request.Method == "" || len(request.Result) > 0 || len(request.Error) > 0 {
			request.ID = nil
			code = -32600
			message = "Invalid bounded MCP request"
		} else if len(request.ID) == 0 {
			if request.Method == "notifications/initialized" && server.initialized {
				server.ready = true
			}
			continue
		} else if !goodqaValidID(request.ID) {
			request.ID = nil
			code = -32600
			message = "Invalid MCP identifier"
		} else {
			key := string(request.ID)
			var text string
			if json.Unmarshal(request.ID, &text) == nil {
				normalized, _ := json.Marshal(text)
				key = string(normalized)
			}
			if seenIDs[key] {
				code = -32600
				message = "Request identifier already consumed; no upstream replay"
			} else if len(seenIDs) >= 4096 {
				return errors.New("GoodQA session request capacity reached; reconnect with current authority")
			} else {
				seenIDs[key] = true
				result, code, message = server.dispatch(ctx, request)
			}
		}
		packet := map[string]any{"jsonrpc": "2.0", "id": request.ID}
		if code != 0 {
			packet["error"] = map[string]any{"code": code, "message": message}
		} else {
			packet["result"] = result
		}
		safe := goodqaFilterJSON(packet, secrets)
		if request.Method == "tools/call" && code == 0 {
			safePacket, ok := safe.(map[string]any)
			var raw []byte
			if ok {
				raw, _ = json.Marshal(safePacket["result"])
			}
			if !ok || goodqaValidateCallResult(raw, server.protocol) != nil {
				packet["result"] = goodqaUnavailableCallResult("unknown")
				safe = goodqaFilterJSON(packet, secrets)
			}
		}
		data, e := json.Marshal(safe)
		if e != nil || len(data) > goodqaFrameLimit {
			return errors.New("GoodQA downstream response exceeds safe bound")
		}
		if _, e = out.Write(append(data, '\n')); e != nil {
			return errors.New("GoodQA downstream output closed")
		}
	}
	if scanner.Err() != nil {
		return errors.New("GoodQA stdin frame exceeded bound or failed")
	}
	return nil
}

func (s *goodqaStdio) dispatch(ctx context.Context, r goodqaPacket) (any, int, string) {
	switch r.Method {
	case "ping":
		return map[string]any{}, 0, ""
	case "initialize":
		if s.initialized {
			return nil, -32600, "Already initialized"
		}
		var p struct {
			ProtocolVersion string `json:"protocolVersion"`
		}
		if json.Unmarshal(r.Params, &p) != nil || p.ProtocolVersion == "" {
			return nil, -32602, "Protocol version required"
		}
		if e := s.upstream.initialize(ctx); e != nil {
			return nil, -32000, "GoodQA initialization rejected: unavailable or invalid upstream protocol"
		}
		protocol := p.ProtocolVersion
		if !oneOf(protocol, "2024-11-05", "2025-03-26", "2025-06-18") {
			protocol = "2025-06-18"
		}
		s.protocol = protocol
		s.initialized = true
		return map[string]any{"protocolVersion": protocol, "capabilities": map[string]any{"tools": map[string]any{"listChanged": false}}, "serverInfo": map[string]string{"name": "agent-harness-goodqa-allowlist", "version": version}}, 0, ""
	case "tools/list":
		if !s.ready {
			return nil, -32002, "Initialize and send initialized notification first"
		}
		if e := goodqaCheckAuthority(s.snapshot, "", true); e != nil {
			return nil, -32003, e.Error()
		}
		tools, e := s.upstream.tools(ctx)
		if e != nil {
			return nil, -32000, "GoodQA catalog response rejected"
		}
		allowed := map[string]bool{}
		for _, name := range s.snapshot.AllowedTools {
			allowed[name] = true
		}
		filtered := []goodqaTool{}
		for _, tool := range tools {
			if allowed[tool.Name] {
				filtered = append(filtered, tool)
			}
		}
		return map[string]any{"tools": filtered}, 0, ""
	case "tools/call":
		return s.call(ctx, r.Params)
	default:
		return nil, -32601, "This proxy supports initialize, ping and explicitly allowed tools only"
	}
}
func (s *goodqaStdio) call(ctx context.Context, raw json.RawMessage) (any, int, string) {
	if !s.ready {
		return nil, -32002, "Initialize first"
	}
	var p struct {
		Name      string          `json:"name"`
		Arguments json.RawMessage `json:"arguments"`
		Meta      json.RawMessage `json:"_meta,omitempty"`
	}
	if settingsDecode(raw, &p) != nil || !goodqaToolName.MatchString(p.Name) {
		return nil, -32602, "Invalid tools/call parameters"
	}
	if len(p.Arguments) == 0 {
		p.Arguments = json.RawMessage(`{}`)
	}
	if !strings.HasPrefix(strings.TrimSpace(string(p.Arguments)), "{") {
		return nil, -32602, "Tool arguments must be an object"
	}
	if e := goodqaCheckAuthority(s.snapshot, p.Name, false); e != nil {
		return nil, -32003, e.Error()
	}
	result, e := s.upstream.call(ctx, "tools/call", p)
	if e == nil {
		if validation := goodqaValidateCallResult(result, s.protocol); validation != nil {
			e = &goodqaOutcomeError{message: "tool result cannot be represented in negotiated protocol", unknown: true}
		}
	}
	if e == nil {
		return result, 0, ""
	}
	outcome := "failed"
	var uncertain *goodqaOutcomeError
	if errors.As(e, &uncertain) && uncertain.unknown {
		outcome = "unknown"
	}
	_, _ = io.WriteString(s.diagnostics, "goodqa_proxy upstream_response_rejected\n")
	return goodqaUnavailableCallResult(outcome), 0, ""
}
func goodqaUnavailableCallResult(outcome string) map[string]any {
	return map[string]any{"isError": true, "content": []map[string]string{{"type": "text", "text": "GoodQA result unavailable. Do not replay an accepted or uncertain request automatically."}}, "_meta": map[string]string{"outcome": outcome}}
}
