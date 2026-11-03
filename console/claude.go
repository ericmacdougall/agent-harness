package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"time"
)

type claudeRun struct {
	command       *exec.Cmd
	input         io.WriteCloser
	writeOnce     sync.Once
	writer        *inputWriter
	done          chan struct{}
	cancelOnce    sync.Once
	cwd           string
	runtimeHash   string
	policy        resolvedPolicy
	taskID        string
	inputRevision uint64
}

func (r *claudeRun) cancel() {
	r.cancelOnce.Do(func() {
		r.writeOnce.Do(func() { r.writer = newInputWriter(r.input) })
		r.writer.close()
		terminateProcess(r.command)
	})
}
func (r *claudeRun) write(value any) error { return r.writeContext(context.Background(), value) }
func (r *claudeRun) writeContext(ctx context.Context, value any) error {
	return r.writeAdmitted(ctx, value, nil)
}
func (r *claudeRun) writeAdmitted(ctx context.Context, value any, admit inputAdmission) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	r.writeOnce.Do(func() { r.writer = newInputWriter(r.input) })
	select {
	case <-r.done:
		return errors.New("Claude process has ended")
	default:
	}
	err = r.writer.writeAdmitted(ctx, append(data, '\n'), admit)
	if err != nil && !isDispatchRefused(err) {
		r.cancel()
	}
	return err
}

func (a *app) sendClaude(current *session, requestID, prompt, cwd, profile string) error {
	a.mu.Lock()
	run := current.claude
	providerID := current.ProviderID
	hasHistory := current.claudeStarted
	policy := current.policy
	revision := uint64(0)
	taskID := ""
	taskMetadata := ""
	if current.task != nil {
		metadataTask := current.task
		if current.delivery != nil {
			metadataTask = &current.delivery.next
		}
		revision = metadataTask.InputRevision
		taskID = metadataTask.ID
		taskMetadata = checkpointMetadata(metadataTask)
	}
	a.mu.Unlock()
	binary, env, fingerprint, runtimeErr := a.resolveRuntime(policy)
	if runtimeErr != nil {
		a.rejectedSend(current, requestID, runtimeErr)
		return runtimeErr
	}
	if run != nil && ((run.taskID != taskID || run.inputRevision != revision) || run.runtimeHash != fingerprint || run.policy.Model != policy.Model || run.policy.Effort != policy.Effort || run.policy.Permissions != policy.Permissions || run.policy.HarnessInstructions != policy.HarnessInstructions || run.cwd != cwd) {
		a.mu.Lock()
		current.claude = nil
		a.mu.Unlock()
		run.cancel()
		select {
		case <-run.done:
		case <-time.After(5 * time.Second):
			err := errors.New("prior Claude process did not stop; no replacement was started")
			a.rejectedSend(current, requestID, err)
			return err
		}
		run = nil
	}
	if run == nil {
		var err error
		args := []string{"--print", "--input-format", "stream-json", "--output-format", "stream-json", "--verbose", "--include-partial-messages", "--forward-subagent-text", "--permission-prompts", "host", "--system-prompt-snapshot", "off", "--append-system-prompt", policy.HarnessInstructions + "\n" + taskMetadata}
		mcpPaths := []string{}
		mcpNames, configErr := policyMCPNames(policy)
		if configErr != nil {
			a.rejectedSend(current, requestID, configErr)
			return configErr
		}
		if current.task != nil && current.reviewParent == "" {
			path, extra, configErr := a.checkpointConfig(current)
			if configErr != nil {
				a.rejectedSend(current, requestID, configErr)
				return configErr
			}
			env = append(env, extra...)
			mcpPaths = append(mcpPaths, path)
			mcpNames = append(mcpNames, checkpointMCPName(current.ID))
		}
		if policy.MCPConfigPath != "" {
			if _, configErr := validateMCPConfig(policy.MCPConfigPath, policy.MCPConfigSHA256); configErr != nil {
				a.rejectedSend(current, requestID, configErr)
				return configErr
			}
			mcpPaths = append(mcpPaths, policy.MCPConfigPath)
		}
		if len(mcpPaths) > 0 {
			args = append(args, "--mcp-config")
			args = append(args, mcpPaths...)
		}
		if policy.Model != "" {
			args = append(args, "--model", policy.Model)
		}
		if policy.Effort != "" {
			args = append(args, "--effort", policy.Effort)
		}
		if policy.Permissions != "" {
			args = append(args, "--permission-mode", claudePermission(policy.Permissions))
		}
		if policy.ServiceTier != "" && policy.ServiceTier != "default" {
			err := errors.New("Claude does not expose this service tier through its installed CLI")
			a.unknownSend(current, requestID, err)
			return err
		}
		if hasHistory {
			args = append(args, "--resume", providerID)
		} else {
			args = append(args, "--session-id", providerID)
		}
		if guardErr := guardNativeMCP("claude", binary, env, cwd, mcpNames); guardErr != nil {
			a.rejectedSend(current, requestID, guardErr)
			return guardErr
		}
		command := exec.Command(binary, args...)
		command.Env = env
		command.Dir = cwd
		configureProcess(command)
		input, err := command.StdinPipe()
		if err != nil {
			return err
		}
		output, err := command.StdoutPipe()
		if err != nil {
			return err
		}
		command.Stderr = &cappedBuffer{limit: 32768}
		if err = command.Start(); err != nil {
			a.unknownSend(current, requestID, err)
			return err
		}
		run = &claudeRun{command: command, input: input, done: make(chan struct{}), cwd: cwd, runtimeHash: fingerprint, policy: policy}
		a.mu.Lock()
		if current.task != nil {
			run.taskID = taskID
			run.inputRevision = revision
		}
		current.claude = run
		a.mu.Unlock()
		go func() {
			a.readClaude(current, run, output)
			err := command.Wait()
			run.writeOnce.Do(func() { run.writer = newInputWriter(run.input) })
			run.writer.close()
			close(run.done)
			a.mu.Lock()
			defer a.mu.Unlock()
			if current.claude != run {
				return
			}
			current.claude = nil
			if current.Status == "running" || current.Status == "waiting" {
				current.Status = "unknown"
				current.Error = "Claude ended before a final result. No request was replayed."
				if err != nil {
					current.Error = "Claude exited before a final result. Check authentication and process availability."
				}
			}
			a.changedLocked()
		}()
	}
	frame := map[string]any{"type": "user", "message": map[string]any{"role": "user", "content": prompt}, "parent_tool_use_id": nil, "session_id": providerID}
	if err := run.writeAdmitted(context.Background(), frame, a.turnAdmission(current, current.dispatchEpoch, requestID)); err != nil {
		a.unknownSend(current, requestID, err)
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if current.requests[requestID] == "final" {
		return nil
	}
	current.context = ""
	current.requests[requestID] = "accepted"
	a.inputOutcomeLocked(current, requestID, "retained", "Provider accepted; attachment consumers may still be active")
	if err := a.record(current, requestID, "accepted"); err != nil {
		current.Status = "unknown"
		current.Error = "Claude input was accepted but its receipt could not be saved"
	}
	a.changedLocked()
	return nil
}
func (a *app) readClaude(current *session, run *claudeRun, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 65536), 2<<20)
	partialID := ""
	for scanner.Scan() {
		value := object(scanner.Bytes())
		kind := textField(value, "type")
		a.mu.Lock()
		if current.claude != run {
			a.mu.Unlock()
			return
		}
		switch kind {
		case "system":
			if id := textField(value, "session_id"); id != "" {
				current.ProviderID = id
				current.claudeStarted = true
			}
			if model := textField(value, "model"); model != "" {
				current.Model = model
			}
		case "stream_event":
			event := mapField(value, "event")
			if textField(event, "type") == "message_start" {
				partialID = textField(mapField(event, "message"), "id")
			}
			delta := mapField(event, "delta")
			if textField(delta, "type") == "text_delta" {
				if partialID == "" {
					partialID = "claude-" + freshID()
				}
				text := textField(delta, "text")
				filter := current.filters[partialID]
				if filter == nil {
					filter = a.streamFilter()
					current.filters[partialID] = filter
				}
				text = filter.Push(text)
				found := false
				for i := range current.Messages {
					if current.Messages[i].ID == partialID {
						if len(current.Messages[i].Text) < maxMessageBytes {
							current.Messages[i].Text += text
						}
						found = true
					}
				}
				if !found {
					a.addMessageLocked(current, message{ID: partialID, Role: "assistant", Text: text, Streaming: true})
				}
			}
		case "assistant":
			item := mapField(value, "message")
			id := textField(item, "id")
			text := ""
			content, _ := item["content"].([]any)
			for _, raw := range content {
				block, _ := raw.(map[string]any)
				switch textField(block, "type") {
				case "text":
					text += textField(block, "text")
				case "tool_use":
					current.Supervision.progress++
					name := textField(block, "name")
					toolID := textField(block, "id")
					a.addMessageLocked(current, message{ID: toolID, Role: "tool", Text: name, AgentID: textField(value, "parent_tool_use_id")})
					if name == "Agent" || name == "Task" {
						input := mapField(block, "input")
						stamp := now()
						current.Agents = append(current.Agents, agent{ID: toolID, Name: textField(input, "name"), Role: textField(input, "subagent_type"), Task: textField(input, "description"), Provider: "claude", Status: "running", LastSeen: &stamp})
					}
				}
			}
			delete(current.filters, id)
			if text != "" {
				a.addMessageLocked(current, message{ID: id, Role: "assistant", Text: text, AgentID: textField(value, "parent_tool_use_id")})
			}
			partialID = ""
		case "result":
			current.providerFinal = true
			a.revokeQuestionsLocked(current, "")
			current.Status = "idle"
			if current.Supervision.State == "paused" {
				current.Status = "paused"
			}
			current.Supervision.NextCheckpoint = "Review provider result and tracked work"
			if usage, ok := value["usage"].(map[string]any); ok {
				current.Usage = usage
			}
			if bad, _ := value["is_error"].(bool); bad {
				current.Status = "error"
				current.Error = "Claude returned an error result"
				current.Supervision.State = "blocked"
				current.Supervision.Reason = current.Error
			}
			if text := textField(value, "result"); text != "" {
				already := false
				for _, item := range current.Messages {
					if item.Role == "assistant" && item.Text == text {
						already = true
					}
				}
				if !already {
					a.addMessageLocked(current, message{Role: "assistant", Text: text})
				}
			}
			for id, status := range current.requests {
				if status == "accepted" {
					current.requests[id] = "final"
				}
			}
			_ = a.record(current, current.lastRequest, "final")
			a.inputOutcomeLocked(current, current.lastRequest, "retained", "Main turn final; files retained for possible owner/tool readers until explicit discard")
			if current.queueUncertain {
				current.Status = "unknown"
				current.Supervision.State = "paused"
			}
			if current.reviewParent != "" {
				a.finishReviewLocked(current)
			} else {
				go a.advance(current.ID)
			}
		case "control_request":
			request := mapField(value, "request")
			if current.Supervision.State == "paused" || current.Status == "paused" || current.reviewParent != "" {
				if current.reviewParent != "" {
					current.Status = "error"
					current.Error = "Independent reviewer requested interactive permission"
					a.finishReviewLocked(current)
				}
				go run.write(map[string]any{"type": "control_response", "response": map[string]any{"subtype": "error", "request_id": textField(value, "request_id"), "error": "interactive question unavailable for this lifecycle"}})
				break
			}

			if textField(request, "subtype") == "can_use_tool" {
				tool := textField(request, "tool_name")
				input := mapField(request, "input")
				body, _ := json.MarshalIndent(input, "", "  ")
				q := question{ID: textField(value, "request_id"), Kind: "claude/permission", Title: "Claude requests " + tool, Prompt: string(body), Choices: []string{"allow", "deny"}, ExpiresAt: time.Now().Add(15 * time.Minute).UTC().Format(time.RFC3339), params: request}
				if tool == "AskUserQuestion" {
					q.Questions, _ = input["questions"].([]any)
					for i, raw := range q.Questions {
						if item, ok := raw.(map[string]any); ok {
							item["id"] = fmt.Sprintf("question-%d", i)
						}
					}
					q.Choices = nil
				}
				a.bindQuestionLocked(current, &q, current.ProviderID, current.turnID)
				current.PendingQuestions = append(current.PendingQuestions, q)
				current.Status = "waiting"
			} else {
				_ = run.write(map[string]any{"type": "control_response", "response": map[string]any{"subtype": "error", "request_id": textField(value, "request_id"), "error": "This console does not support this control request"}})
				current.Error = "Claude requested an unsupported control operation"
			}
		}
		if current.reviewParent != "" {
			a.syncReviewAgentLocked(current)
		}
		a.changedLocked()
		a.mu.Unlock()
	}
	if err := scanner.Err(); err != nil {
		a.failSession(current, fmt.Errorf("Claude output stream exceeded its bound or failed"))
		run.cancel()
	}
}
