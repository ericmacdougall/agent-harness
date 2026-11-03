# Agent Harness Console (development)

A local Go application with an embedded browser interface and real Codex and Claude Code CLI sessions. It is being built and verified on this feature branch; release packaging and final independent acceptance are pending.

## Run from source

Install Go 1.22 or newer and at least one authenticated provider CLI, then run:

```sh
cd console
go run . --cwd /absolute/path/to/project
```

The app binds a random port on `127.0.0.1`, opens the local interface and authenticates it with a per-launch capability. Normal use requires no pasted JSON or token. For local automation, `--no-open` prints the bootstrap URL; treat that URL as private. `--data-dir` selects private console metadata. One live process owns a data directory at a time.

```sh
go test ./...
go build -o harness-console .
./harness-console --help
```

The Settings panel selects profiles, policy and supported integrations. Native provider authentication remains in the provider's supported account flow. API keys are stored through the operating-system credential store, and unavailable vaults fail closed. Displayed usage is the actual provider response or an explicit unavailable state.

## Workflow and history

Session tabs have separate provider identities and working directories. A supplied conversation reference appears as context in a new interactive session. Importing an existing desktop thread does not take over its writer. The interface labels imported context rather than claiming an attached desktop session.

The composer submits real provider requests. Native streaming events update messages and owned-agent status; the sidebar keeps separate selectable transcripts. Provider-native subagents expose the controls their protocol supports. In particular, an embedded Claude subagent does not have an independent host control channel; controlling its parent stops that process tree. Application-managed independent reviewers have their own provider sessions and transcripts.

While one tracked objective is active, the composer queues follow-ups instead of replacing that objective. The private queue is FIFO and bounded to eight pending inputs, 128 KiB per message, 256 KiB of retained text and a 256 KiB expanded objective, and 16 MiB or 16 retained attachment snapshots. Up to 256 queue receipts may remain while delivered or discarded entries await cleanup. Acceptance preserves the current task and review authority. Immediately before a queued input is admitted to the provider writer, the console advances `inputRevision`, extends the objective and invalidates every pass for the earlier revision—even when the artifact digest is unchanged. A held or unknown FIFO head is never bypassed.

For substantive work, a scoped checkpoint can request plan, code and final review. The console dispatches the ordered independent review ladder, verifies structured verdict identity and compares the source/evidence snapshot before accepting a pass. Empty custom ladders resolve to the documented independent Codex Sol/high/normal default. There are finite continuation and repair limits; errors, unknown outcomes, changed subjects and user pause stop automatic advancement with a reason. Casual chat works outside Git and does not require code-review admission.

A code gate requires the actual committed head and clean worktree. Plan/document gates can use bounded artifact files. Evidence stays inside the selected cwd or an admitted owner worktree of the same Git repository, rejects redirected/credential paths and has byte limits. Review is a workflow safeguard; processes running as the same OS user are not isolated from one another.

The console journals metadata and send outcomes, not full prompts or credentials. Queued follow-up text and immutable attachment snapshots are the exception: they remain in the private data directory while they have a possible consumer. An ordinary send transfers its snapshots out of the composer until the provider reports a native final outcome, then releases them automatically; an unknown or restarted writer retains them for explicit reconciliation. Queued follow-up entries remain read-only recovery data until explicit local discard, which does not stop provider work or change its delivery outcome. Provider CLIs may retain their normal history. Browser reconnect reloads current state. App restart preserves provider/task/reviewer identities and quarantines prior writers. Queued and held entries restart as held; dispatching, unknown, interrupted, or conflicting durable candidates restart as unknown. Recovery may merge the two private metadata slots to preserve payload and snapshot ownership, but it never treats readability as proof of delivery and never replays an input automatically. Continue in new session creates a new writer with available context; it does not claim the old writer is exclusive.

## Files, Git and controls

The file picker snapshots selected bytes into private files. Sending verifies those snapshots, so later edits to the original do not silently change an attachment. Known credential files and configured secrets are refused. Files remain subject to the provider's normal access permissions after submission.

Automatic attachment cleanup uses descriptor-relative, no-follow deletion on macOS and Linux. Windows builds fail closed and retain `cleanup_pending` ownership because this release does not provide an equivalent confined deletion primitive there; attachment cleanup and native Windows qualification remain release limits.

Repository controls show the selected cwd, worktrees, branches and local tracking state. Sync uses guarded fetch/fast-forward/push. Remote failure preserves local work and reports failure. Removing a worktree requires exact-path confirmation and refuses dirty, locked, current-session or unpushed work. These controls do not run destructive force/reset/clean commands.

Codex/Claude launch buttons ask the OS for a new terminal at the selected cwd. An accepted OS launch is reported separately from CLI readiness. Native launch, browser controls and installation must be tested on each supported OS; cross-compilation alone is not that proof.

The local server uses exact Host/Origin checks, authenticated API calls, bounded event replay and escaped text rendering. GoodQA tools are opt-in and limited to the admitted discovered allowlist through a separate helper; the disabled Codex bridge and old Hive automation are not activated by this application.

## Verification status

Implementation plans and scenario registrations live in `../plans/CONSOLE-*.md`. Focused tests include malformed and stale checkpoints, authority separation, subject/evidence drift, queued-input admission and crash recovery, attachment mutation, provider framing and split-secret redaction. CI runs the Go suite, race detector, vet, native builds and the focused browser composer tests. These controls do not prove a real provider accepted or rejected an uncertain send, that a native credential vault works in the current desktop session, or that a cross-compiled UI works on that platform. Private native test receipts distinguish actual CLI delivery from simulated protocol tests. Full frozen validation, independent source review, real browser acceptance, and native platform installation evidence must be reported before a release is called ready.
