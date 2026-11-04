# Console frontend and launcher contract

> **Unreleased baseline.** This plan describes the console kept on `main` as the base for the event-log rebuild. That console is not released, packaged or installed; see `console/README.md`.

## Launch

Use `[BINARY, --reference-file, FILE, --reference-sha256, HEX, --cwd, DIR, --data-dir, NEW_DIR]`; the unreleased baseline requires `--data-dir` and refuses the default console directory. The executable accepts optional `--session ID`, `--provider codex|claude`, `--no-open` and loopback-only `--listen`. The Go executable embeds `console/web/index.html`, `app.js`, `style.css`; no runtime Go/Node install is required. A supplied foreign session is imported as context for a labeled new interactive session.

## Authentication

A per-launch random token reaches the browser through the URL fragment. Store it in sessionStorage and remove the fragment from history. Every API call includes `Authorization: Bearer TOKEN`. Mutations use same-origin JSON POST. Every route enforces exact Host, rejects foreign Origin, and mutations require expected Origin. API responses never include the token. All returned text is rendered through textContent. CSP allows only embedded local assets.

## State and events

`GET /api/state` returns `{revision,sessions,activeSession,reference,providers,shortcuts}`. Sessions contain `{id,provider,providerId,title,cwd,status,model,effort,messages,agents,attachments,usage,error,pendingQuestions,supervision}`. A message has `{id,role,text,timestamp,streaming,agentId}`. An agent has `{id,parentId,name,role,task,model,provider,status,lastSeen,lastWrite,canPause,canResume,canStop}`. Unknown telemetry is null. A pending question has `{id,kind,title,prompt,choices,expiresAt}`. Supervision has `{state,nextCheckpoint,remainingBursts,reason}`.

`GET /api/events?after=N` is an authenticated fetch SSE stream with `{id,type,sessionId,data}` records. State records send a fresh snapshot. A cursor outside the bounded ring produces `gap`, causing an explicit fresh state read. Keepalives assert transport connectivity only. Browser reconnect retains its cursor. Server restart restores durable provider IDs but marks unresolved requests unknown, and never resends them automatically.

## User operations

- `POST /api/sessions` with `{provider,cwd}` creates a provider-backed session. Import through `/api/sessions/import` with `{provider,id}` reads an explicit supplied history and creates a new interactive context session for a foreign conversation.
- `POST /api/sessions/{id}/send` with `{requestId,text,attachments}` deduplicates bounded request IDs and records intent before dispatch. Accepted user input appears once. Unknown outcomes require reconciliation.
- `POST /api/sessions/{id}/control` with `{action,agentId}` pauses, resumes or stops the actual selected turn/owned process tree. It never kills the shared daemon. Resume is a deliberate continuation request. Unsupported provider actions remain disabled with reasons.
- `POST /api/sessions/{id}/answer` with `{questionId,answer}` resolves one live pending approval/question through its matching protocol response. Expired, unknown or already answered IDs are refused. No default approval is inferred.
- `POST /api/sessions/{id}/cwd` with `{path}` validates a directory and refuses active turns. Actual later provider cwd must match the displayed path. Claude rebind requires stopped-process resume.
- `GET /api/files?path=ABS` returns `{path,parent,entries:[{name,path,directory,size}]}`. The integrated picker explicitly selects paths. `POST /api/sessions/{id}/attachments` with `{paths}` validates regular files and records their paths for the next send. Credential files are excluded from automatic discovery and copying.
- `GET /api/git?sessionId=ID` returns `{root,branch,head,dirty,branches,worktrees}` with actual tracking/ahead/behind and selected cwd flags. `POST /api/git/refresh` explicitly fetches. `POST /api/git/sync` accepts `{sessionId,path,expectedHead}` and uses guarded fetch/fast-forward/push semantics. `POST /api/git/remove` accepts `{sessionId,path,expectedHead,confirmPath}` and refuses current, dirty, unpushed, locked or protected worktrees.
- `POST /api/launch` with `{sessionId,provider}` opens the trusted installed CLI at selected cwd through fixed platform argv. Its result distinguishes launch requested from readiness.
- `POST /api/shutdown` stops this app and its owned work. Other clients and shared daemons are outside its lifecycle.

Errors use `{error:{code,message}}`. API request sizes, stream records, pending maps and UI history are bounded. A private fsynced metadata journal preserves IDs, request intent/results and unresolved states across app restarts. It contains no token, environment or full prompt/transcript.

## Keyboard and selection

Ctrl/Cmd+Enter sends multiline input. Alt/Option+Shift+N opens new-session choice. Alt/Option+Shift+[ or ] cycles sessions. Tab navigates composer, tree and repository panel. Tree arrows navigate/expand/collapse; Enter opens a transcript. Alt/Option+Shift+O opens files. Alt/Option+Shift+W opens cwd. Alt/Option+Shift+K and Alt/Option+Shift+L launch Codex and Claude at cwd. Escape closes dialogs. Visible help documents conflicts.

Main chat is selectable. Sidebar, tabs, controls and borders use user-select:none. Cross-pane selection/copy must contain only chat text. Agent transcript display has its own content selection container.

### Recovery and dispatch repair contract

Sessions expose `restored: true` when the previous provider writer cannot be proven exclusive. Such histories refuse send/resume. `POST /api/sessions/{id}/continue-as-new` with `{}` returns `{id}` for a newly created provider session using the same provider/profile/cwd and available read-only context. It does not resume or replay the prior native writer. Journal recovery retains task/generation/subject/review identities and unknown reviewer outcomes; restored passes are not automatically reused.

Checkpoint inputs accept optional `subjectRoot`: current cwd or a registered worktree of the same pinned Git common directory. Subject root/common-directory identity and file/evidence digests bind the review; reviewer cwd is that root. A main session may stay in its original checkout while an owner feature branch is reviewed. Foreign repositories and unregistered roots are refused.

Pause/stop increments a control epoch. Checkpoint capture/policy resolution rechecks it before commit. Automatic continuation binds the original task and epoch through provider-input admission. Questions bind their connection, turn, request, generation and epoch; pause, stop, completion and disconnect revoke them. Provider input has a bounded single-writer queue and a five-second maximum write deadline, including time waiting behind backpressure. Uncertain writes close the owned connection rather than execute queued work later.

Only a correctly bound structured BLOCK verdict activates automatic repair. Transport failure, timeout, malformed output, cancellation or source drift pauses the gate with an explicit unknown/invalidated reason. Owned reviewer identities persist, and timeout/user stop requests cancellation of the exact owned turn without claiming an unconfirmed final result.

CLI launch uses an expiring, single-use metadata-only ticket. The new terminal runs the console's local helper, which resolves the selected account and vault-backed environment itself. Keys never enter launch arguments, ticket files or command scripts. OS acceptance remains distinct from interactive CLI readiness.

### Fresh-session cascade and native MCP preservation

A new session tries the default runtime, then the explicitly configured cascade order, before sending provider input. Only a typed local executable-unavailable result permits advancement. Profile refusal, vault/auth/quota errors, invalid policy, timeouts and uncertain/provider execution do not. Selected stage/model/effort, policy revision, admission ID, request ID and reason appear as session `cascade` metadata and durable receipts. A selected fallback stays with its provider/account; changing its configured stage requires a new context. Restart restores the selection as quarantined history and never replays it.

Console MCP helpers use opaque application namespaces. Before injection, Codex's native metadata command resolves configuration under the actual environment/cwd, and Claude's bounded native on-disk scopes are inspected without connecting foreign servers. Exact collisions, invalid/unreadable metadata and exclusive managed MCP refuse helper injection. Other native tools stay configured; no blanket strict/bare mode is added. The GoodQA allowlist applies to the console-added helper; existing native servers retain their own policies. Dynamic enterprise policy remains native-provider authority; namespacing is not a same-UID isolation boundary. Claude managed launches explicitly disable system-prompt snapshots so updated task metadata and resolved instructions apply on continuation.

Sources: [Codex configuration precedence](https://learn.chatgpt.com/docs/config-file/config-basic), [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli), [Claude MCP scope precedence](https://code.claude.com/docs/en/mcp), [Claude managed MCP](https://code.claude.com/docs/en/managed-mcp), plus installed CLI help/schema contracts. The metadata probes use no model turns.
