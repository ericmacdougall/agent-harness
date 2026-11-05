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
	command     *exec.Cmd
	tree        *processTree
	input       io.WriteCloser
	writeOnce   sync.Once
	writer      *inputWriter
	done        chan struct{}
	cancelOnce  sync.Once
	cwd         string
	runtimeHash string
	// Survives settings revisions, unlike runtimeHash; see conversationIdentity.
	conversationIdentity string
	policy               resolvedPolicy
	taskID               string
	inputRevision        uint64
	requestID            string // Immutable after the sole user-frame admission.
	authAdmit            inputAdmission
}

func (r *claudeRun) cancel() {
	r.cancelOnce.Do(func() {
		r.writeOnce.Do(func() { r.writer = newInputWriter(r.input) })
		r.writer.close()
		if r.tree != nil {
			// Callers hold the app lock. The polite signal goes out before cancel
			// returns, so shutdown cannot skip it; only the grace wait and the kill
			// run on their own goroutine. An explicit cancel overrides a leave
			// verdict that was not yet recorded, and stops the group.
			r.tree.Release(true)
			if r.tree.BeginStop() {
				go r.tree.FinishStop(100 * time.Millisecond)
			}
		} else {
			terminateProcess(r.command)
		}
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
	err = r.writer.writeAdmitted(ctx, append(data, '\n'), func() (func(), error) {
		var authRelease, release func()
		var admissionErr error
		if r.authAdmit != nil {
			authRelease, admissionErr = r.authAdmit()
			if admissionErr != nil {
				return authRelease, admissionErr
			}
		}
		if admit != nil {
			release, admissionErr = admit()
			if admissionErr != nil {
				if authRelease != nil {
					authRelease()
				}
				return release, admissionErr
			}
		}
		return func() {
			if release != nil {
				release()
			}
			if authRelease != nil {
				authRelease()
			}
		}, nil
	})
	if err != nil && !isDispatchRefused(err) {
		r.cancel()
	}
	return err
}

var errRuntimeChanged = errors.New("credentials or tools changed; start a new context session")

// claudeRuntimeChanged reports whether resuming would carry this conversation
// into a different credential or tool runtime. A stored API key change does not
// pass through an auth transition, so this is what stops --resume, including
// unattended continuations, from crossing into another account.
func claudeRuntimeChanged(current *session, identity string) bool {
	return current.Provider == "claude" && current.conversationRuntimeHash != "" && current.conversationRuntimeHash != identity
}

func (a *app) sendClaude(current *session, requestID, prompt, cwd, profile string) error {
	a.mu.Lock()
	run := current.claude
	usedRun := run != nil && run.requestID != ""
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
	binary, env, fingerprint, authGeneration, runtimeErr := a.resolveRuntimeCaptured(policy)
	if runtimeErr != nil {
		a.rejectedSend(current, requestID, runtimeErr)
		return runtimeErr
	}
	identity := conversationIdentity(binary, env, policy)
	a.mu.Lock()
	runtimeChanged := claudeRuntimeChanged(current, identity)
	a.mu.Unlock()
	if runtimeChanged {
		a.rejectedSend(current, requestID, errRuntimeChanged)
		return errRuntimeChanged
	}
	if run != nil && (usedRun || (run.taskID != taskID || run.inputRevision != revision) || run.runtimeHash != fingerprint || run.policy.Model != policy.Model || run.policy.Effort != policy.Effort || run.policy.Permissions != policy.Permissions || run.policy.HarnessInstructions != policy.HarnessInstructions || run.cwd != cwd) {
		// Stream-json results do not identify the input request. A process may
		// admit only one user turn; retire it before resuming the conversation.
		// Keep the pointer until exit is confirmed, so a timeout cannot allow
		// a later send to bypass the still-live process boundary.
		// EOF lets the CLI flush conversation history before the resumed process
		// opens it. A process that cannot drain is not safe to replace.
		run.writeOnce.Do(func() { run.writer = newInputWriter(run.input) })
		run.writer.close()
		select {
		case <-run.done:
		case <-time.After(5 * time.Second):
			err := errors.New("prior Claude process did not stop; no replacement was started")
			a.rejectedSend(current, requestID, err)
			return err
		}
		a.mu.Lock()
		if current.claude == run {
			current.claude = nil
		}
		a.mu.Unlock()
		run = nil
	}
	startedRun := false
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
		command.Stderr = &cappedBuffer{limit: 32768}
		tree, err := startProcessTree(command, nil)
		if err != nil {
			a.unknownSend(current, requestID, err)
			return err
		}
		output := tree.Stdout()
		run = &claudeRun{command: command, tree: tree, input: input, done: make(chan struct{}), cwd: cwd, runtimeHash: fingerprint, conversationIdentity: identity, policy: policy, authAdmit: a.authAdmission("claude", profile, authGeneration)}
		if err = a.attachStartedClaudeRun(current, run, profile, authGeneration, taskID, revision); err != nil {
			// Start succeeded, so every later failure must reap the child even when
			// the generation fence refused publication before the session saw it.
			run.cancel()
			<-tree.Done()
			close(run.done)
			a.unknownSend(current, requestID, err)
			return err
		}
		startedRun = true
		go func() {
			a.readClaude(current, run, output)
			// Without a final, nothing supervises this tree any more. After a final,
			// its background work is the tool's own and retirement must not kill it.
			a.mu.Lock()
			final := current.requests[run.requestID] == "final"
			a.mu.Unlock()
			if !final {
				tree.Release(true)
				tree.Terminate(100 * time.Millisecond)
			} else {
				tree.Release(false)
			}
			<-tree.Done()
			err := tree.Err()
			run.writeOnce.Do(func() { run.writer = newInputWriter(run.input) })
			run.writer.close()
			close(run.done)
			a.mu.Lock()
			defer a.mu.Unlock()
			if current.claude != run {
				return
			}
			reason := "Claude ended before a final result. No request was replayed."
			if err != nil {
				reason = "Claude exited before a final result. Check authentication and process availability. No request was replayed."
			}
			a.claudeUnfinishedLocked(current, run, reason)
			current.claude = nil
			a.changedLocked()
		}()
	}
	frame := map[string]any{"type": "user", "message": map[string]any{"role": "user", "content": prompt}, "parent_tool_use_id": nil, "session_id": providerID}
	admit := a.turnAdmission(current, current.dispatchEpoch, requestID)
	bindRequest := func() (func(), error) {
		release, err := admit()
		if err != nil {
			return nil, err
		}
		a.mu.Lock()
		if current.claude != run || current.lastRequest != requestID || current.requests[requestID] != "intent" || run.requestID != "" {
			a.mu.Unlock()
			release()
			return nil, refused("Claude request binding changed before dispatch")
		}
		run.requestID = requestID
		a.mu.Unlock()
		return release, nil
	}
	if err := run.writeAdmitted(context.Background(), frame, bindRequest); err != nil {
		if startedRun {
			a.detachStartedClaudeRun(current, run)
		}
		a.unknownSend(current, requestID, err)
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if current.requests[requestID] != "intent" {
		return nil
	}
	current.context = ""
	a.transitionRequestLocked(current, requestID, "accepted")
	a.inputOutcomeLocked(current, requestID, "retained", "Provider accepted; attachment consumers may still be active")
	if current.requests[requestID] == "unknown" {
		a.changedLocked()
		return nil
	}
	if err := a.record(current, requestID, "accepted"); err != nil {
		a.transitionRequestLocked(current, requestID, "unknown")
		a.revokeQuestionsLocked(current, "")
		current.providerFinal = false
		current.Status = "unknown"
		current.Error = "Claude input was accepted but its receipt could not be saved"
		current.Supervision.State = "paused"
		current.Supervision.Reason = current.Error
		a.inputOutcomeLocked(current, requestID, "unknown", "Accepted receipt durability is unknown; no replay")
	}
	a.changedLocked()
	return nil
}

func (a *app) detachStartedClaudeRun(current *session, run *claudeRun) {
	a.mu.Lock()
	if current.claude == run && run.requestID == "" {
		current.claude = nil
	}
	a.mu.Unlock()
	run.cancel()
}

// attachStartedClaudeRun binds a newly started process to the session while
// holding the same generation admission used by serialized frame writes. A
// transition therefore either sees and cancels the attached run or prevents
// publication and cancels the otherwise invisible process here.
//
// Lock order is generation admission, then a.mu, matching admitted writers. A
// pending writer on the generation lock blocks new readers, so waiting for it
// while holding a.mu would deadlock against a writer that needs a.mu to finish.
func (a *app) attachStartedClaudeRun(current *session, run *claudeRun, profile string, generation uint64, taskID string, revision uint64) error {
	release, err := a.authAdmission("claude", profile, generation)()
	a.mu.Lock()
	if err == nil && (current.claude != nil || current.Restored) {
		err = refused("Claude session binding changed before process publication")
	}
	if err == nil {
		run.taskID = taskID
		run.inputRevision = revision
		current.claude = run
		current.conversationRuntimeHash = run.conversationIdentity
	}
	a.mu.Unlock()
	if release != nil {
		release()
	}
	if err != nil {
		run.cancel()
	}
	return err
}

// UI pause/stop is not a provider outcome. Only the exact unfinished request
// loses authority here; a durable final or an already unknown request is sticky.
func (a *app) claudeUnfinishedLocked(current *session, run *claudeRun, reason string) {
	requestID := run.requestID
	if current.claude != run || requestID == "" || current.lastRequest != requestID || !oneOf(current.requests[requestID], "intent", "accepted") {
		return
	}
	a.transitionRequestLocked(current, requestID, "unknown")
	current.providerFinal = false
	current.Status = "unknown"
	current.Error = reason
	current.Supervision.State = "paused"
	current.Supervision.Reason = reason
	a.revokeQuestionsLocked(current, "")
	a.inputOutcomeLocked(current, requestID, "unknown", "Claude ended without a durable final outcome; retain inputs and reconcile without replay")
	_ = a.record(current, requestID, "unknown")
}

func (a *app) readClaude(current *session, run *claudeRun, reader io.Reader) {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 65536), 2<<20)
	partialID := ""
	for scanner.Scan() {
		value := object(scanner.Bytes())
		kind := textField(value, "type")
		a.mu.Lock()
		if current.claude != run || run.requestID != "" && run.requestID != current.lastRequest {
			a.mu.Unlock()
			return
		}
		if requestTerminal(current.requests[run.requestID]) {
			a.mu.Unlock()
			if kind == "control_request" {
				// Drain terminal output without reopening waiting state. A denial
				// releases a CLI still waiting for its permission response.
				go run.write(map[string]any{"type": "control_response", "response": map[string]any{"subtype": "error", "request_id": textField(value, "request_id"), "error": "request is no longer active"}})
			}
			continue
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
			requestID := run.requestID
			requestState := current.requests[requestID]
			if requestTerminal(requestState) {
				break
			}
			if requestID == "" || requestID != current.lastRequest || !oneOf(requestState, "intent", "accepted") {
				current.Status = "unknown"
				a.revokeQuestionsLocked(current, "")
				current.Error = "Claude returned a result without an exact active request binding. No request was replayed."
				current.Supervision.State = "paused"
				current.Supervision.Reason = current.Error
				if active := current.lastRequest; oneOf(current.requests[active], "intent", "accepted") {
					current.providerFinal = false
					a.transitionRequestLocked(current, active, "unknown")
					a.inputOutcomeLocked(current, active, "unknown", "Provider result has no exact request binding; no replay")
					_ = a.record(current, active, "unknown")
				}
				break
			}
			current.claudeStarted = true
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
			// Persist before publishing: a final that was never saved is unknown, and
			// unknown cannot later become final.
			if err := a.record(current, requestID, "final"); err != nil {
				current.providerFinal = false
				a.transitionRequestLocked(current, requestID, "unknown")
				current.Status = "unknown"
				current.Error = "Claude completed but the final receipt could not be persisted. No request was replayed."
				current.Supervision.State = "paused"
				current.Supervision.Reason = current.Error
				a.inputOutcomeLocked(current, requestID, "unknown", "Provider completed but final receipt durability is unknown; no replay")
				break
			}
			a.transitionRequestLocked(current, requestID, "final")
			current.providerFinal = true
			a.inputOutcomeLocked(current, requestID, "retained", "Main turn final; files retained for possible owner/tool readers until explicit discard")
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
			if inputLifecycleBlocked(current) || current.reviewParent != "" {
				if current.reviewParent != "" {
					a.blockReviewerLocked(current, "Independent reviewer requested interactive permission")
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
				// Never write while holding a.mu: the write waits on auth admission.
				go run.write(map[string]any{"type": "control_response", "response": map[string]any{"subtype": "error", "request_id": textField(value, "request_id"), "error": "This console does not support this control request"}})
				current.Error = "Claude requested an unsupported control operation"
			}
		}
		if current.reviewParent != "" {
			a.syncReviewAgentLocked(current)
		}
		a.changedLocked()
		a.mu.Unlock()
	}
	// errStreamDrainBound means the leader is gone and a descendant merely holds
	// the pipe: the caller's goroutine decides the tree's fate after the final
	// check, so it is not a stream failure and must not cancel the run here.
	if err := scanner.Err(); err != nil && !errors.Is(err, errStreamDrainBound) {
		a.mu.Lock()
		a.claudeUnfinishedLocked(current, run, "Claude output stream exceeded its bound or failed before a final result. No request was replayed.")
		a.changedLocked()
		a.mu.Unlock()
		run.cancel()
	}
}
