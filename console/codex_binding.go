package main

import (
	"bytes"
	"encoding/json"
	"io"
)

const (
	maxCodexPendingFrames  = 128
	maxCodexPendingBytes   = 256 * 1024
	maxCodexCompletedItems = 1024
	maxCodexItemIDBytes    = 1024
)

type codexPendingFrame struct {
	method string
	turnID string
	raw    json.RawMessage
}

// Last-key-wins decoding cannot establish unambiguous identity.
func uniqueCodexObject(raw json.RawMessage) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := map[string]json.RawMessage{}
	for d.More() {
		token, err = d.Token()
		if err != nil {
			return nil, false
		}
		key, ok := token.(string)
		if !ok {
			return nil, false
		}
		if _, exists := fields[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, false
	}
	if _, err = d.Token(); err != io.EOF {
		return nil, false
	}
	return fields, true
}

// Content/questions require turnId. Completion requires turn.id. Every
// supplied identity must be valid and agree; none is inferred from a session.
func codexFrameTurn(raw json.RawMessage, completion bool) string {
	fields, ok := uniqueCodexObject(raw)
	if !ok {
		return ""
	}
	var envelope, nested string
	if value, exists := fields["turnId"]; exists {
		if json.Unmarshal(value, &envelope) != nil || envelope == "" {
			return ""
		}
	} else if !completion {
		return ""
	}
	if value, exists := fields["turn"]; exists {
		turn, valid := uniqueCodexObject(value)
		if !valid {
			return ""
		}
		if json.Unmarshal(turn["id"], &nested) != nil || nested == "" {
			return ""
		}
	} else if completion {
		return ""
	}
	if envelope != "" && nested != "" && envelope != nested {
		return ""
	}
	if completion {
		return nested
	}
	return envelope
}
func activeCodexBinding(s *session, client *rpcClient) *codexTurnBinding {
	b := s.codexTurn
	if b == nil || s.codex != client || b.client != client || b.requestID != s.lastRequest || !oneOf(s.requests[b.requestID], "intent", "accepted") {
		return nil
	}
	return b
}
func boundCodexTurn(s *session, client *rpcClient, turn string) bool {
	b := activeCodexBinding(s, client)
	return turn != "" && b != nil && b.turnID != "" && b.turnID == turn && s.turnID == turn
}
func (b *codexTurnBinding) clearFrames() { b.frames = nil; b.frameBytes = 0 }
func (b *codexTurnBinding) bufferFrame(method, turn string, raw json.RawMessage) {
	if b.framesDropped {
		return
	}
	// A pending completion fences later content for that turn even before
	// the reply establishes authority. Keep earlier and other-turn frames.
	for _, completion := range b.pending {
		if completion.turnID == turn {
			return
		}
	}
	if len(b.frames) >= maxCodexPendingFrames || len(raw)+len(turn) > maxCodexPendingBytes-b.frameBytes {
		b.clearFrames()
		b.framesDropped = true
		return
	}
	b.frames = append(b.frames, codexPendingFrame{method: method, turnID: turn, raw: append(json.RawMessage(nil), raw...)})
	b.frameBytes += len(raw) + len(turn)
}

// Exhaustion suppresses new completed items rather than forgetting old IDs.
func (b *codexTurnBinding) acceptCompletedItem(id string) bool {
	if id == "" || len(id) > maxCodexItemIDBytes || b.completed[id] || len(b.completed) >= maxCodexCompletedItems {
		return false
	}
	if b.completed == nil {
		b.completed = map[string]bool{}
	}
	b.completed[id] = true
	return true
}
