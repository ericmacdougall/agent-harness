# Interactive agent console

> **Unreleased baseline.** This plan describes the console kept on `main` as the base for the event-log rebuild. That console is not released, packaged or installed; see `console/README.md`.

## Outcome and location

Build a real desktop-oriented chat console in the public repository as `console/`, an independent Go 1.22 module using the standard library plus `golang.org/x/sys`. A single `harness-console` executable embeds its HTML/CSS/JavaScript, opens a browser window, and uses locally installed Codex and Claude Code. The existing private operator and reference reader remain separate compatibility paths. Supplied references are visible context, never automatically submitted model instructions.

The user explicitly requested the session/chat/agent/worktree layout, then authorized building and deep verification. Main recorded that authorization. Independent plan review remains required before product code.

## Decisions and observed contracts

- A browser GUI supports independent text selection, keyboard focus, file dialogs and expandable trees. Electron adds a runtime and packaging surface. A standard-library Go server with embedded assets retains one executable and cross-compiles for macOS, Windows and Linux.
- Bind only `127.0.0.1:0`. A cryptographic per-launch bearer token reaches the browser in the URL fragment. JavaScript removes the fragment from history and retains it in session storage. Every API request requires the token and exact Host. Foreign Origin is rejected, and POST requires the expected Origin. Assets are local with CSP and no third-party resources. The event stream uses authenticated fetch.
- Installed Codex `app-server --stdio` accepts newline JSON-RPC. A bounded no-model probe initialized and read metadata for the exact supplied current chat ID. It returned `notLoaded`, which must be shown honestly. Generated installed schemas expose thread start/resume/read, paginated turns/items, descendants, turn start/steer/interrupt and model/status data. An initial proxy probe timed out and is retained as unknown.
- A server-owned Codex stdio connection multiplexes actual sessions and subagent events. Exact-ID foreign history is imported into a new interactive session by default, labeled with its source. Returning notLoaded does not establish a free writer. Never auto-resume a foreign desktop thread. Own sessions can resume through the normal provider busy checks. New sessions use GPT-6.1 Sol, High effort, standard service and existing permission defaults.
- Claude Code uses a separate process adapter with installed `--print --input-format stream-json --output-format stream-json --include-partial-messages --forward-subagent-text` support. Provider events supply IDs and completion. Unsupported actions are disabled with the returned reason. Authentication stays inside the installed CLI.

## Launch contract

The executable accepts `--reference-file FILE --reference-sha256 HEX --cwd DIR` and optional `--session ID --provider codex|claude --no-open --listen 127.0.0.1:0`. Normal launch needs no argument. `--help` declares all flags. The public launcher invokes this direct contract without `tui` or `--reference-only`. Retain legacy reader compatibility separately.

Validate references using public schema-v1 and exact digest. If the supplied current Codex ID can be hydrated, show its actual available history as imported context in a clearly labeled new interactive session. Preserve supplied summary when hydration is unavailable. Never invent full history or imply continuation of a live foreign writer.

## User interface

1. Session tabs show provider, activity and unread output, plus a button and shortcuts for a new Codex or Claude session.
2. Main chat renders streamed user, assistant, tool and context records as text. Its selection container is independent of the sidebar. Multiple chat lines cannot select adjacent sidebar text.
3. The agent sidebar is a hierarchy from actual Codex descendant metadata/events and Claude parent-tool events. Nodes show task, provider/model/harness role, state, last observed activity and last file-write event when available. Missing telemetry reads unknown. Selecting a node opens its transcript. Tab and arrows navigate. Pause interrupts an actual turn, Resume continues explicitly, and Stop cancels selected running work without terminating the shared daemon.
4. Below the tree, toggle worktrees/branches. Rows show ahead/behind, dirty state, tracking and the directory selected by this session. Explicit Refresh fetches remote state. Sync uses fetch and fast-forward/push checks. Local worktree removal requires confirmation and refuses dirty, unpushed, current, locked or protected work. Refusals show precise reasons.
5. A multiline composer has an integrated file browser, send/stop and queued-input state. Reference files only after user selection. The cwd chooser validates a directory and updates only the selected session.
6. Bottom bar shows transport, session/tool/token metrics when supplied, cwd and shortcuts. Shortcuts open real Codex or Claude CLI at the selected cwd in a new terminal window using fixed argv and trusted local executables.

## Supervision and recovery

Observe events and work state continuously without paid polling prompts. Native harness guidance and the installed checkpoint govern owner reuse, branches, review, tests and delivery. Substantive sends automatically arm tracked-work supervision and maintain a visible next checkpoint. Progress uses structured tool completion, checkpoint state and revision/event digests, rather than searching reply prose. A finite burst budget is debited before each automatic continuation and cannot refill through state toggles. Advancement stops on user pause, provider auth/quota error, unavailable tool, no progress or a resolved outcome. The UI explains the waiting/stopped state and allows a deliberate new user instruction to continue. A detached process alone never establishes a handoff. Reconnect restores event cursors/provider IDs and reports gaps after bounded-buffer expiry.

Server-initiated RPC approvals, requestUserInput and elicitation become explicit pending UI questions with the actual choices, request ID and deadline. Only deliberate user action sends the matching answer. Unsupported request types return a visible capability error, never silently approve. Claude permission questions use the same lifecycle when supported; an unrecognized prompt stops with a recoverable error.

RPC calls use IDs, deadlines and bounded pending maps. Output streams have line/message caps and bounded retention. Serialize per-session state and child lifecycles. Keep stderr private and bounded. Process exit alone is not model completion. Uncertain requests do not automatically replay actions. Cancel/reconnect races retain explicit unknown outcomes. A private fsynced journal records provider/session IDs, request intent, actual outcomes and cursors. Browser reconnect restores the live stream. App/server restart reconstructs durable identities and marks unresolved actions unknown until provider evidence reconciles them. It never replays an uncertain send. Request bodies and private credentials are excluded from metadata journaling. Session cwd changes are refused during a turn. Codex binds the new cwd on its next actual turn; Claude changes cwd by a deliberate stopped-process resume and verifies the actual provider init cwd.

Provider discovery works under the public launcher's restricted PATH. Validate configured absolute executables or trusted standard installation paths, including the ChatGPT app bundle, Homebrew and Windows user installations. A missing provider opens setup with an executable picker and a bounded version preflight. No reliance on the developer shell PATH or credential inheritance. Test the compiled console through the actual launcher with its minimal environment and a quoted cwd.

## Slices and ownership

Implementation adjustment: the initial version uses validated PATH and known
installation discovery. A custom executable picker is deferred; setup help must
describe actual installation/discovery behavior rather than refer to a missing
Settings control. The normal restricted-PATH launcher remains an acceptance case.

Console owner owns `console/**` and console docs. Main coordinates public launcher and installer/tests against the accepted contract. Private operator, unrelated branches, credentials and global permissions are outside this build.

Implement protocol/state, embedded GUI, file/repository/terminal actions, then packaging and handoff. Commit recoverable slices. Independent code inspection precedes one frozen full validation. Browser tests drive the compiled executable's normal launch and API routes.

## Acceptance and adversarial proofs

Pre-register an ordinary eight-step chain and deep thirty-step chain. Retain baseline failures against the reference-only viewer. Exercise multi-session chat, partial chunks, long output, descendant tree, selected transcript, stop/resume, file selection, cwd changes, branch/worktree status, sync/removal refusals, external CLI launch, selection, reconnect, provider crash and auth/quota failure. Authored cases are regression evidence and do not establish field reliability.

Negative controls include missing/wrong token, foreign Origin/Host, oversized body, malformed stream, wrong RPC ID, lost final event, stale cursor, duplicate send, double cancellation, unavailable CLI, unsupported action, dirty/unpushed worktree removal, path/symlink races and quoted filenames/cwd. Use observable failing controls or broken variants.

Use protocol subprocess doubles for chaos, then bounded real Codex and Claude turns for integration. Actual browser automation drives tabs, streaming, tree navigation, composer, file modal, cwd, repository controls, shortcuts and isolated chat selection. Freeze source/fixtures/docs before Go tests, race checks, three-platform compile checks and fresh exact-head evidence review. Main verifies publication, delivered checkout and installed launch. Ship prebuilt platform archives requiring no Go or Node compiler. Native launch and real browser smoke run on each available macOS/Windows/Linux host. A cross-compile alone is explicitly labeled build-only and cannot establish easy installation or launch.
