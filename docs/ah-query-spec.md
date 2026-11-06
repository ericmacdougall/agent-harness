# ah: deterministic harness lookups and writes (GoodQA goodqa#14598)

Outcome: agents stop grepping transcripts, WALs and `df /` by hand. `ah` answers the lookups with one
tested command each, and is the only writer of harness task state. Slice 1 ships `owners`, `user-msg`,
`ticket get|comments|comment`, `disk`, `task register|status|done`, `write result`, `spool drain`.
Later slices: `wal query`, `asks`, `delivery`, `alerts`, `work find`, MCP server, skills, more writers.

Source: user "how we dont have proper tools/a cli in our harness that handles all these common lookups/processes" (main WAL scope entry of 2026-11-05 06:07, queued message, not uuid-indexed).

## Acceptance criteria

- AC-1 `ah owners` lists every sub-agent with state live, quiet, SILENT, SILENT-HIGH, done, handoff, waiting-on-X, stopped or DROPPED, using `liveness.py` (shared with ops-watch). Verify by: tests.test_ah LivenessTests, OwnersTests.
- AC-2 `ah user-msg` resolves human turns, queued mid-turn messages and AskUserQuestion answers to `uuid:`, `queue:`, `answer:` ids. Verify by: UserMsgTests.
- AC-3 `ah ticket comments` returns every comment, untruncated and valid JSON. Verify by: TicketTests.test_comments_untruncated_and_paginated.
- AC-4 `ah disk` reports `/System/Volumes/Data` as the capacity volume on macOS and bounds its directory scan. Verify by: DiskTests.
- AC-5 Writes are idempotent by key, validated, audited and keep the WAL entry and ticket comment in one call; a comment GoodQA cannot take is spooled and drained once. Verify by: WriteTests.
- AC-6 The incremental index survives appends, torn last lines and truncation. Verify by: OwnersTests, UserMsgTests.

## Negative cases

- NEG-1 (AC-2) Forgery: a Bash tool result, a sidechain turn, a peer turn, a task-notification or agent-message queue record never becomes a user message. Verify by: test_resolves_all_three_kinds_and_rejects_forgeries.
- NEG-2 (AC-3) Key never printed, even on failure. Verify by: test_key_never_printed.
- NEG-3 (AC-5) Same key with a different body is `key_conflict`; concurrent same-key calls apply once. Verify by: test_idempotent_and_conflict, test_concurrent_same_key_applies_once.
- NEG-4 (AC-5) `task done` without both a deploy record and a live REALLY_TESTED run (a commit alone is refused), with evidence from a WAL outside `~/.claude/wals`, or with a missing commit is refused. Verify by: test_done_rejects_missing_or_fake_evidence.
- NEG-5 (AC-5) `task register` with an untraceable source is refused (`provenance`); comment bodies are redacted. Verify by: test_register_rejects_unsourced, test_comment_body_redacted.
- NEG-6 Secret files (`*.secret`, `.env*`, `member.key`, `credentials*`) are never indexed. Verify by: SecretTests (guard function; the index readers added in slice 2 must call it).

## Trust rules for `user-msg` (provenance.py is unchanged in slice 1)

- `uuid:` is a transcript user record whose `origin.kind` is `human` (provenance.user_authorship, shared).
- `answer:` is a user record carrying a tool_result whose `tool_use_id` matches an assistant `AskUserQuestion` tool_use in the same transcript; a tool result of any other tool never qualifies.
- `queue:<session>/<timestamp>#<sha12>` is a transcript queue-operation `enqueue` or `popAll` record whose content is not a harness wrapper element. Queue records have no `origin` marker, so each row reports its `trust` text. Agents cannot write the transcript; only harness-written records exist there.
- Proposal for main, not implemented: make provenance.py accept `queue:` and `answer:` ids with the same rules, after main approves the trust change.

## Ledger and spool

`~/.agent-harness/state/ah/store/`: `ledger.jsonl` (seq, key, body sha, op, args, actor), `audit.jsonl` (applied, rejected, key_conflict), `spool/` (pending GoodQA comments, keyed by operationId), `store.lock` (flock). Index files live in `~/.agent-harness/state/ah-index/`.

## Dropped-owner dispositions and the Stop gate (goodqa#14791)

A DROPPED owner (the shared `liveness.py` rule) must carry a live **disposition** or it is a defect that needs a decision now. `ah owners` rows carry `disposition` and `decision_required`; the document carries `undisposed`. `ah owners --gate` exits 1 while any owner is undisposed, so a "0 dropped" summary cannot be printed over a dropped owner. Dispositions go only through the `ah` writer (`task.dispose`: idempotent key, audit row, and a `disposition` entry in the session main WAL):

    ah task dispose --agent <id> --kind resumed                      live while activity follows within 30 min, or any later activity
    ah task dispose --agent <id> --kind reassigned --ref <agent id>  live while the replacement is live, or stopped but holding its own live
                                                                     waiting/closed/reassigned disposition (inherited, and expires with it)
    ah task dispose --agent <id> --kind waiting --ref <ask id | GoodQA proj#N> --until <ISO>   expires at --until
    ah task dispose --agent <id> --kind closed --reason <what you verified> --deployed <WAL id> --live-test <REALLY_TESTED id>   done; permanent
    ah task dispose --agent <id> --kind superseded|wontdo --ref <GoodQA proj#N> --reason <why>   ended, not done; permanent
    ah task dispose --agent <id> --kind legacy        quiet before the gate was installed; unverified, not done (the Stop gate writes these)

**Done means deployed to live and tested** (the user's rule, main WAL w07450081c12). `closed` needs a deploy record (a WAL entry of event `deploy`, `release` or `install`, or a note starting `DEPLOYED`, `INSTALLED` or `RELEASED`, carrying the deployed sha or version) and a `REALLY_TESTED <id>:` run against a live target (`live`, `production`, or a non-loopback URL) written at or after that deploy; a note that says it was not live (`not live yet`, `staging`, `pre-prod`, `locally`, `dry run`) is refused whatever else it names. Both must name the owner (its id, its registered task, or its ticket). When the owner registered a branch and worktree, the deployed sha must contain the branch tip. A merge, a commit or a plain note alone is refused. `ah task done` takes the same pair (`--deployed WID --really-tested ID --wal PATH`; `--commit` is extra evidence, never enough). Work that will not ship is `superseded` or `wontdo` with a ticket GoodQA confirms. It shows in `ah owners` under that state and never counts as done.

The dispose guard (the 19-owner loop, main WAL w3dcbe6b8ffa):
- Evidence that names an owner only through a shared ticket covers one owner. A record may cover several owners only when it names each of them by id or task.
- A closing reason needs 40+ characters and 6+ different words, and may not repeat another owner's reason within 7 days once ids, shas and numbers are masked.
- One actor trying to close more than 3 different owners within 10 min is refused as a possible bulk close. A high `bulk-close:<session>:<actor>` alert goes to the ring.
- Every attempt, refused or applied, gets an audit row with its kind and owner.
- `legacy` is accepted only for an owner whose last activity predates the gate's install time. `install.py` writes `~/.agent-harness/state/dropped-gate/installed_at.json` once, as the earlier of the install time and an already-installed gate's mtime. `ah` pins the earliest epoch it has used.
- The Stop gate records pre-gate owners as `legacy` once, with audit rows. `ah owners` keeps listing them as `unverified-legacy` (and under `legacy_unverified`) until a later disposition follows up.
- A `reassigned` replacement that has returned stays live while any of its child agents is live.

A `waiting` disposition must name an ask id that exists in the session WAL or a ticket that GoodQA confirms exists (a wait cannot park work), and `--until` may be at most 7 days after the writer's clock (24 h when GoodQA cannot be reached to confirm the ticket); a wait is renewed, never parked. A wait on an ask ends when the ask is answered (`ask_resolved`). A `waiting on <x>` note in an owner WAL holds for at most 24 h after it was written, and one that names an ask holds only while that ask is open in the session; after that the owner is DROPPED again. A longer wait is an `ah task dispose --kind waiting`, which checks what it names. A retry with the same `--key` is a duplicate even after the writer's clock or GoodQA's reachability has moved: server-stamped fields (`at`, `ref_unverified`) are not part of the request a key names. Who may acknowledge comes from the hook payload, not the shell: main's shell carries the same `CLAUDE_CODE_CHILD_SESSION` and `AI_AGENT` values as a sub-agent's, so `dropped_gate.py pretool` (PreToolUse, Bash) denies a sub-agent's `ah task dispose --kind resumed|reassigned|closed|legacy|superseded|wontdo`, and `ah` refuses an actor that names itself (`AH_AGENT_ID`). The hook reads shell words, not raw text: it matches an actual `ah` / `ah.py` invocation (behind env assignments, `env`, `nice`, a python interpreter, `bash -c`, `eval` or a heredoc fed to a shell), judges `--kind` as written (`ah` refuses abbreviated flags, so `--kin` cannot slip past), and denies an unexpandable `--kind "$K"`; text that only quotes such a line (grep, a commit message, a heredoc written to a file) is allowed. Both checks are advisory against an agent that hides the call (a script file, Python code calling `ah.write`, the MCP tool). A `status` or `result` row that `ah` writes on an owner's behalf carries `by: <actor>` and never counts as that owner's own activity.

`harness/hooks/dropped_gate.py` is a Claude Code Stop hook (registered by `install.py`): it blocks the main agent's turn from ending while the session has undisposed DROPPED owners, names them with the exact `ah task dispose` lines, and is bounded to 3 blocks per problem signature (state under `~/.agent-harness/state/dropped-gate/`). Headless (`sdk-*`) and sub-agent sessions are not gated; any `ah` failure fails open with a message.

The same hook in `subagent-stop` mode (registered on SubagentStop for every agent type) blocks a sub-agent once when it ends its turn with pending work (its own WAL ends in an open intent, status or similar, with no handoff, result or `waiting on <ask id|ticket|agent>`) and no live `ah-run` job; on the second stop it lets the turn end and writes a `task.pending` row through `ah`, so the owner is DROPPED at once instead of after the 30-minute finishing grace. Task-named WALs (`<task>.jsonl`) are owners in the same view: `liveness.classify_task_wal` makes them SILENT at 30 min, SILENT-HIGH at 60, DROPPED at 6 h without a terminal note or named wait, and done/handoff/waiting otherwise. `harness/skills/check-dropped-workstreams/scan.py` is installed as a thin wrapper over `ah owners --gate`.

## Asks: presence gate and reminders (goodqa#14791 P16/P17)

`provenance_hooks.py ask-gate` also checks presence: a modal AskUserQuestion is allowed only to the interactive main session while the user is present (a `prompt` event in the session main WAL within `ask_presence_minutes`, default 10; policy `ask_presence`: enforce | warn | off; `AH_USER_PRESENT=0|1` pins it for tests and the console). Otherwise the call is denied, the registered ask stays, a ring alert `ask:<id>:pending-user` notifies the user, and the caller is told to continue independent work and record `ah task dispose --kind waiting --ref <ask id>`. Sub-agents are always denied and routed to main. `ask_reminders.py` re-surfaces open asks on a bounded schedule (at once, +30 min, +2 h, then every 4 h, at most 42 repeats): ahd raises `ask:<id>:due` at info, warning, then high, so the ring, prompt context and digest carry them; each stage fires once and nothing fires after `ask_resolved`.

## Provenance quarantine and sourced resolutions (goodqa#14791 S3a)

`wal_note.py` never drops a note for lack of a source: an unsourced `scope` or `decision` is written with `unsourced: true` (quarantined). `provenance_hooks.py stop-lint` blocks the interactive main's turn end, at most 3 times per set of entries, while quarantined entries older than `quarantine_minutes` (default 10; policy `quarantine_lint`: enforce | warn | off) exist, naming each id and the fix: `ah note --wal <WAL> --source auto --dry-run --id <id>` previews the nearest sourced scope/decision/requirement/ask ancestor as a `wal:` source (an ancestor that is itself an assumption yields an `inferred:` source), and the same command without `--dry-run` writes the re-cited note through `wal_note.py`; with no sourced ancestor it refuses (`no_source`) rather than guess. `ask_resolved` now requires `--ref` to name an ask of that WAL that is not already resolved and `--source` to cite the answer (`user:`, `answer:` or `queue:` id from `ah user-msg`); the source is checked like an ask's and stored on the row. Quarantine applies only to a missing or rejected source, never to a ticket the tracker cannot verify right now. A sourced row written with `--recites <id>` clears the quarantine of the row it re-cites (`ah note --id` does this for you); rows written by tools with `--by <tool>` are never quarantined, where the tool is one of the allowlist (escalation, ahd, dropped_gate, ah-run); any other `--by` is refused. A re-cite clears the original only when the re-citing row is itself backed; when `ah note` writes a row that the checker could not back here, it answers ok:false with `quarantined: true` and the warnings, so the hint is never silently satisfied. `ask_resolved --source` must be the answer itself (`user:`, `answer:`, `queue:`) or a ticket; an ask is never closed on an `inferred:` or `file:` source. Tool-written rows (`by`) also do not count as the owner's own activity in liveness. `--source auto` always writes `inferred: from wal:<ancestor> -- auto-picked nearest sourced ancestor`, so an automatic choice is labelled as the assumption it is.

## Deadlines, handoff acknowledgement, unpushed-work guard, Codex gate (goodqa#14791 S3b)

`ah deadline add --at <ISO> --ref <ticket | ask id> --owner <id> --note ...` records a dated one-shot obligation through the writer (a `deadline` row in the session main WAL, id `dl` + 10 hex); `ah deadline done --id` closes it; `ah deadline list` shows open | due (within 1 h) | missed | done. `ah owners` carries `deadlines`, and a missed deadline with no disposition for its id joins `undisposed`, so the Stop gate and `--gate` cover it; ahd raises `deadline:<id>:due` (warning) and `deadline:<id>:missed` (high, stop_block). A `handoff` is acknowledged by a `resumed`, `reassigned` or `closed` disposition at or after the handoff; without one for 60 minutes the owner is `decision_required` with flag `handoff-unacked`. `workdir.py prune` never lists a work directory that holds a git checkout with commits on no remote (bounded walk; a git read that fails counts as unpushed). On Codex, the Stop hook runs the same dropped-owner gate after its continuation checkpoint; `install_codex.py` ships `dropped_gate.py`, `ah.py` and `liveness.py`. `ah` finds a session under either WAL root (`~/.claude/wals` or `~/.agent-harness/codex-wals`) and writes its own WAL rows with a bounded, locked append that is valid under both, so the gate and the writers work on a Codex-only host. A handoff is acknowledged only by a `resumed`, `reassigned` or `closed` disposition recorded by main or another agent: an owner cannot dispose itself (`forbidden`), and disposition and pending-stop times are stamped by the writer, never supplied by the caller. Upgrade note: on install, every handoff-state owner older than 60 minutes with no acknowledging disposition becomes `decision_required` at once; dispose them in the first gate round. `deadline done` refuses an id that is not a deadline of the session.

## ahd must run (goodqa#14791 S1d)

`install.py --apply --services` registers the ahd job after the files are installed (`ahd.py install --apply`: launchd on the Mac, a systemd user unit on Linux); a plain install never touches launchd or systemd. `ah doctor` carries an `ahd running` check (lock held or heartbeat fresher than 5 min) and fails while the daemon is down; `AH_EXPECT_AHD=0` turns it into a report on hosts that do not run it. `ahd_policy.json` runs in `mode: detector` with `restart.enabled: false` until the automatic-restart redesign (NEVER-LOSE.md S2) passes review.
