package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

func object(raw json.RawMessage) map[string]any {
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	return value
}
func textField(value map[string]any, key string) string { text, _ := value[key].(string); return text }
func mapField(value map[string]any, key string) map[string]any {
	result, _ := value[key].(map[string]any)
	return result
}
func nestedText(value any, key string) string {
	switch v := value.(type) {
	case map[string]any:
		if s, ok := v[key].(string); ok {
			return s
		}
		for _, child := range v {
			if result := nestedText(child, key); result != "" {
				return result
			}
		}
	case []any:
		for _, child := range v {
			if result := nestedText(child, key); result != "" {
				return result
			}
		}
	}
	return ""
}
func (a *app) sessionForThreadLocked(thread string) (*session, *agent) {
	if thread == "" {
		return nil, nil
	}
	all := append(append([]*session{}, a.sessions...), a.reviews...)
	// Managed reviewers are roots even though displayed under the parent tree.
	for _, s := range all {
		if s.ProviderID == thread {
			return s, nil
		}
	}
	for _, s := range all {
		for i := range s.Agents {
			if s.Agents[i].ID == thread {
				return s, &s.Agents[i]
			}
		}
	}
	return nil, nil
}

func (a *app) codexEvent(client *rpcClient, method string, raw json.RawMessage) {
	value := object(raw)
	thread := textField(value, "threadId")
	if method == "thread/started" {
		data := mapField(value, "thread")
		id := textField(data, "id")
		parent := nestedText(data["source"], "parent_thread_id")
		if parent == "" {
			return
		}
		a.mu.Lock()
		current, _ := a.sessionForThreadLocked(parent)
		if current != nil && id != current.ProviderID {
			exists := false
			for _, child := range current.Agents {
				if child.ID == id {
					exists = true
				}
			}
			if !exists {
				stamp := now()
				current.Agents = append(current.Agents, agent{ID: id, CWD: textField(data, "cwd"), ParentID: parent, Name: textField(data, "agentNickname"), Role: textField(data, "agentRole"), Task: textField(data, "preview"), Model: textField(data, "model"), Provider: "codex", Status: "starting", LastSeen: &stamp, CanPause: true, CanStop: true, ControlReason: nativeChildResumeReason})
			}
			a.changedLocked()
		}
		a.mu.Unlock()
		return
	}
	a.mu.Lock()
	current, child := a.sessionForThreadLocked(thread)
	if current == nil || current.codex != client {
		a.mu.Unlock()
		return
	}
	stamp := now()
	if child != nil {
		child.LastSeen = &stamp
	}
	switch method {
	case "turn/started":
		turn := mapField(value, "turn")
		// Root notifications carry no request authority. Only the correlated
		// turn/start reply can establish the root request-to-turn binding.
		if child != nil {
			child.turnID = textField(turn, "id")
			child.Status = "running"
			child.CanPause = true
			child.CanResume = false
			child.CanStop = true
		}
	case "item/agentMessage/delta":
		id := textField(value, "itemId")
		delta := textField(value, "delta")
		filter := current.filters[id]
		if filter == nil {
			filter = a.streamFilter()
			current.filters[id] = filter
		}
		delta = filter.Push(delta)
		found := false
		for i := range current.Messages {
			if current.Messages[i].ID == id {
				if len(current.Messages[i].Text) < maxMessageBytes {
					current.Messages[i].Text += delta
				}
				current.Messages[i].Streaming = true
				found = true
				break
			}
		}
		if !found {
			a.addMessageLocked(current, message{ID: id, Role: "assistant", Text: delta, Streaming: true, AgentID: thread})
		}
	case "item/completed":
		item := mapField(value, "item")
		kind := textField(item, "type")
		if kind == "agentMessage" {
			delete(current.filters, textField(item, "id"))
			a.addMessageLocked(current, message{ID: textField(item, "id"), Role: "assistant", Text: textField(item, "text"), AgentID: thread})
		}
		if kind == "commandExecution" || kind == "fileChange" || kind == "mcpToolCall" {
			current.Supervision.progress++
			body := textField(item, "command")
			if out := textField(item, "aggregatedOutput"); out != "" {
				body += "\n" + out
			}
			if body == "" {
				b, _ := json.Marshal(item)
				body = string(b)
			}
			a.addMessageLocked(current, message{ID: textField(item, "id"), Role: "tool", Text: body, AgentID: thread})
			if kind == "fileChange" && child != nil {
				child.LastWrite = &stamp
			}
		}
	case "thread/tokenUsage/updated":
		current.Usage = mapField(value, "tokenUsage")
	case "turn/completed":
		turn := mapField(value, "turn")
		turnID := textField(turn, "id")
		status := textField(turn, "status")
		if child != nil {
			a.revokeQuestionsLocked(current, thread)
			child.Status = status
			child.CanPause = false
			child.CanStop = false
			denyNativeChildResume(child)
		} else {
			a.codexCompletionLocked(current, client, codexCompletion{turnID: turnID, status: status, message: textField(mapField(turn, "error"), "message")})
		}
	case "error":
		current.Error = a.clean(textField(mapField(value, "error"), "message"))
	}
	if current.reviewParent != "" {
		a.syncReviewAgentLocked(current)
	}
	a.changedLocked()
	a.mu.Unlock()
}

func (a *app) codexQuestion(client *rpcClient, packet rpcPacket) {
	params := object(packet.Params)

	if packet.Method == "currentTime/read" {
		_ = client.respond(packet.ID, map[string]any{"currentTimeAt": time.Now().Unix()})
		return
	}
	if packet.Method == "item/tool/call" {
		a.mu.Lock()
		current, _ := a.sessionForThreadLocked(textField(params, "threadId"))
		valid := current != nil && current.ProviderID == textField(params, "threadId") && current.codex == client && current.reviewParent == "" && current.turnID != "" && current.turnID == textField(params, "turnId") && textField(params, "tool") == "harness_console_checkpoint"
		a.mu.Unlock()
		var err error
		if !valid {
			err = fmt.Errorf("checkpoint call is not bound to an admitted main session")
		} else {
			var input checkpointInput
			input, err = parseCheckpoint(params["arguments"])
			if err == nil {
				err = a.checkpointUpdate(current.ID, input)
			}
		}
		body := "Checkpoint recorded. End turn after needs_review so independent review can run."
		if err != nil {
			body = err.Error()
		}
		_ = client.respond(packet.ID, map[string]any{"contentItems": []any{map[string]any{"type": "inputText", "text": a.clean(body)}}, "success": err == nil})
		return
	}
	allowed := packet.Method == "item/commandExecution/requestApproval" || packet.Method == "item/fileChange/requestApproval" || packet.Method == "item/tool/requestUserInput" || packet.Method == "mcpServer/elicitation/request"
	if !allowed {
		_ = client.reject(packet.ID, "This console does not support that server request; no approval was granted")
		return
	}
	a.mu.Lock()
	current, _ := a.sessionForThreadLocked(textField(params, "threadId"))
	if current == nil {
		a.mu.Unlock()
		_ = client.reject(packet.ID, "No matching console session for this question")
		return
	}
	if current.Supervision.State == "paused" || current.Status == "paused" || current.Restored || current.Status == "unknown" {
		a.mu.Unlock()
		_ = client.reject(packet.ID, "session lifecycle revoked this question")
		return
	}
	if current.codex != client {
		a.mu.Unlock()
		_ = client.reject(packet.ID, "question connection does not own this session")
		return
	}
	if current.reviewParent != "" {
		current.Status = "error"
		current.Error = "Independent reviewer requested user input; review blocked"
		a.finishReviewLocked(current)
		a.mu.Unlock()
		_ = client.reject(packet.ID, "independent review requires unattended read-only evidence")
		return
	}
	prompt, _ := json.MarshalIndent(params, "", "  ")
	choices := []string{}
	if packet.Method == "item/commandExecution/requestApproval" || packet.Method == "item/fileChange/requestApproval" {
		choices = []string{"accept", "decline", "cancel"}
		if values, ok := params["availableDecisions"].([]any); ok && len(values) > 0 {
			choices = []string{}
			for _, value := range values {
				if text, ok := value.(string); ok {
					choices = append(choices, text)
				}
			}
		}
	}
	q := question{ID: freshID(), Kind: packet.Method, Title: "Provider needs your answer", Prompt: a.clean(string(prompt)), Choices: choices, ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339), rpcID: packet.ID, method: packet.Method, params: params}
	if len(current.PendingQuestions) >= 16 {
		a.mu.Unlock()
		_ = client.reject(packet.ID, "Too many pending questions; session paused")
		return
	}
	a.bindQuestionLocked(current, &q, textField(params, "threadId"), textField(params, "turnId"))
	if q.turnID == "" {
		q.turnID = current.turnID
	}
	q.Questions, _ = params["questions"].([]any)
	q.Questions = a.cleanStructured(q.Questions)
	current.PendingQuestions = append(current.PendingQuestions, q)
	current.Status = "waiting"
	a.changedLocked()
	a.mu.Unlock()
	time.AfterFunc(15*time.Minute, func() { a.expireQuestion(current.ID, q.ID, client) })
}
func (a *app) expireQuestion(sessionID, questionID string, client *rpcClient) {
	a.mu.Lock()
	current := a.findLocked(sessionID)
	if current == nil {
		a.mu.Unlock()
		return
	}
	var id json.RawMessage
	for index, q := range current.PendingQuestions {
		if q.ID == questionID {
			id = q.rpcID
			current.PendingQuestions = append(current.PendingQuestions[:index], current.PendingQuestions[index+1:]...)
			current.Error = "A provider question expired without approval"
			a.changedLocked()
			break
		}
	}
	a.mu.Unlock()
	if id != nil {
		_ = client.reject(id, "User answer deadline expired")
	}
}
func (a *app) answerQuestion(sessionID, questionID string, answer any) error {
	a.mu.Lock()
	current := a.findLocked(sessionID)
	if current == nil {
		a.mu.Unlock()
		return fmt.Errorf("session not found")
	}
	var selected question
	index := -1
	for i, q := range current.PendingQuestions {
		if q.ID == questionID {
			selected = q
			index = i
			break
		}
	}
	if index < 0 {
		a.mu.Unlock()
		return fmt.Errorf("question is expired, unknown or already answered")
	}
	if expiry, err := time.Parse(time.RFC3339, selected.ExpiresAt); err == nil && time.Now().After(expiry) {
		a.mu.Unlock()
		return fmt.Errorf("question expired")
	}
	if selected.Kind == "claude/permission" {
		run := current.claude
		if run == nil {
			a.mu.Unlock()
			return fmt.Errorf("Claude connection is unavailable")
		}
		permission := map[string]any{"behavior": "deny", "message": "User denied permission"}
		if textField(selected.params, "tool_name") == "AskUserQuestion" {
			answers, ok := answer.(map[string]any)
			if !ok {
				a.mu.Unlock()
				return fmt.Errorf("answer all questions")
			}
			input := mapField(selected.params, "input")
			updated := map[string]any{}
			for k, v := range input {
				updated[k] = v
			}
			mapped := map[string]string{}
			for _, raw := range selected.Questions {
				q, _ := raw.(map[string]any)
				id := textField(q, "id")
				record, _ := answers[id].(map[string]any)
				values, _ := record["answers"].([]any)
				if len(values) != 1 {
					a.mu.Unlock()
					return fmt.Errorf("answer each actual question")
				}
				value, ok := values[0].(string)
				if !ok || strings.TrimSpace(value) == "" {
					a.mu.Unlock()
					return fmt.Errorf("answer each actual question")
				}
				mapped[textField(q, "question")] = value
			}
			updated["answers"] = mapped
			permission = map[string]any{"behavior": "allow", "updatedInput": updated}
		} else if decision, ok := answer.(string); ok && decision == "allow" {
			permission = map[string]any{"behavior": "allow", "updatedInput": mapField(selected.params, "input")}
		} else if decision != "deny" {
			a.mu.Unlock()
			return fmt.Errorf("choose allow or deny")
		}
		a.mu.Unlock()
		return run.writeAdmitted(context.Background(), map[string]any{"type": "control_response", "response": map[string]any{"subtype": "success", "request_id": selected.ID, "response": permission}}, a.questionAdmission(current, selected))
	}
	var result any
	switch selected.method {
	case "item/commandExecution/requestApproval", "item/fileChange/requestApproval":
		decision, ok := answer.(string)
		valid := false
		for _, choice := range selected.Choices {
			if choice == decision {
				valid = true
			}
		}
		if !ok || !valid {
			a.mu.Unlock()
			return fmt.Errorf("choose one of the actual provider decisions")
		}
		result = map[string]any{"decision": decision}
	case "item/tool/requestUserInput":
		answers, ok := answer.(map[string]any)
		if !ok {
			a.mu.Unlock()
			return fmt.Errorf("answer must be an object keyed by the question IDs shown")
		}
		result = map[string]any{"answers": answers}
	case "mcpServer/elicitation/request":
		object, ok := answer.(map[string]any)
		if !ok {
			a.mu.Unlock()
			return fmt.Errorf("elicitation answer must be a JSON object")
		}
		result = object
	}
	client := current.codex
	a.mu.Unlock()
	if client == nil {
		return fmt.Errorf("provider connection is unavailable")
	}
	return client.writeAdmitted(context.Background(), map[string]any{"id": selected.rpcID, "result": result}, a.questionAdmission(current, selected))
}
func (a *app) refreshAgents(current *session) {
	a.mu.Lock()
	client := current.codex
	thread := current.ProviderID
	a.mu.Unlock()
	if client == nil || thread == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var result struct {
		Data []map[string]any `json:"data"`
	}
	if err := client.call(ctx, "thread/list", map[string]any{"ancestorThreadId": thread, "limit": 100, "sourceKinds": []string{}, "useStateDbOnly": true}, &result); err != nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, data := range result.Data {
		id := textField(data, "id")
		if id == "" {
			continue
		}
		status := textField(mapField(data, "status"), "type")
		parent := nestedText(data["source"], "parent_thread_id")
		found := -1
		for i := range current.Agents {
			if current.Agents[i].ID == id {
				found = i
			}
		}
		if found < 0 {
			current.Agents = append(current.Agents, agent{ID: id})
			found = len(current.Agents) - 1
		}
		child := &current.Agents[found]
		child.CWD = textField(data, "cwd")
		child.ParentID = parent
		child.Name = textField(data, "agentNickname")
		child.Role = textField(data, "agentRole")
		child.Task = textField(data, "preview")
		child.Model = textField(data, "model")
		child.Provider = "codex"
		child.Status = status
		child.CanPause = status == "active"
		child.CanStop = child.CanPause
		denyNativeChildResume(child)
		if seconds, ok := data["updatedAt"].(float64); ok {
			stamp := time.Unix(int64(seconds), 0).UTC().Format(time.RFC3339)
			child.LastSeen = &stamp
		}
	}
	a.changedLocked()
}
func (a *app) transcript(current *session, thread string) ([]message, error) {
	a.mu.Lock()
	client := current.codex
	a.mu.Unlock()
	if client == nil {
		return nil, fmt.Errorf("provider is disconnected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var result struct {
		Data []struct {
			Item map[string]any `json:"item"`
		} `json:"data"`
	}
	if err := client.call(ctx, "thread/items/list", map[string]any{"threadId": thread, "limit": 100, "sortDirection": "desc"}, &result); err != nil {
		return nil, err
	}
	messages := []message{}
	for index := len(result.Data) - 1; index >= 0; index-- {
		item := result.Data[index].Item
		kind := textField(item, "type")
		text := textField(item, "text")
		role := "assistant"
		if kind == "userMessage" {
			role = "user"
			contents, _ := item["content"].([]any)
			for _, content := range contents {
				if part, ok := content.(map[string]any); ok {
					text += textField(part, "text")
				}
			}
		}
		if kind == "commandExecution" {
			role = "tool"
			text = textField(item, "command") + "\n" + textField(item, "aggregatedOutput")
		}
		if strings.TrimSpace(text) != "" {
			messages = append(messages, message{ID: textField(item, "id"), Role: role, Text: a.clean(text), AgentID: thread})
		}
	}
	return messages, nil
}
