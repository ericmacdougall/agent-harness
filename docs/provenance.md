# Provenance

Provenance records where a requirement, ask, decision, scope, blocker or acceptance criterion came from. It never blocks work: no source form is refused, nothing is quarantined, and no hook blocks the end of a turn or a tool call over a source. What it does is label: a record whose source traces to the owner's words, a ticket or a file says so; one that does not is labelled `UNSOURCED` and stays usable.

Threat model: a careless or hurried agent, not a hostile one. A traced quote proves the words exist in a real owner turn, not that they support the claim, so listings print the owner's sentence next to the claim.

## Sources

Write the source the way you would say it. All of these are accepted:

| Given as | What happens |
| --- | --- |
| `user:<session>/<uuid> "words"` (also `uuid:`, `answer:`, `queue:` as `ah user-msg` prints them) | checked against the transcript: the turn must be the owner's own typed text and contain the words |
| `pasted:<session>/<uuid> "words"` | checked the same way against text the owner pasted; proves they supplied it, not that it is true (an unverified citation) |
| `user said "..."`, `user: "..."`, `the user, 2026-11-24: ...`, a bare `"quoted sentence"` | the quoted words are looked up in the session's owner messages (the `ah user-msg` index, then the transcript); when found the source is normalised to `user:<session>/<uuid> "words"` |
| `ticket:GoodQA <project>#<n>`, or `goodqa#123`, `GoodQA #123`, `#123` | normalised to `ticket:GoodQA <project>#<n>` (default project `goodqa`) and looked up; an unconfirmed ticket is an unverified citation |
| `wal:<path>#<id>`, `file:<path>:<line>@<sha> ["words"]`, `inferred: from <src> ; <src> -- <why>` | as before: followed, read from git, or labelled ASSUMPTION |
| a URL, a file path | kept as given and labelled `LINK` or `FILE` (unverified: not fetched or read) |
| anything else, or a quote that is not found | kept as given and labelled `UNSOURCED` |

The session for a quote lookup is the one given (`--session`, the WAL's folder) or `CLAUDE_CODE_SESSION_ID`. Excerpt matching folds smart quotes, dashes and whitespace, not case. An untraced result's first problem code is `unsourced`; the cause (`excerpt-not-found`, `transcript-missing`, ...) follows it.

## Recording

`wal_note.py --event requirement|ask|decision|scope|blocker --source '<anything>'` always writes the row. When the source does not trace, the row carries `"unsourced": true` and a one-line warning names the cause. Rows that older versions flagged `unsourced` (the former quarantine) simply read as `UNSOURCED`; nothing blocks on them and there is no grace timer. `ask_resolved` still needs the owner's answer (`user:`, `answer:`, `queue:`, `mc:` or `ticket:`) because it closes an ask.

Every mode in `provenance_policy.json` is `off` or `warn`. An old policy file or `HARNESS_PROVENANCE_POLICY` that says `enforce` for `spec`, `plan_packet`, `ask_user_question`, `stop_lint`, `status_lint` or a `wal` event is read as `warn`. `ticket_lookup` only decides whether a ticket the tracker reports missing counts as traced. `ask_presence` is about presence, not provenance (below).

## Later words govern

When a recorded scope, approval or decision (for example "Mac only" or "Living Context only") is narrower than a LATER owner message on the same subject, the later message wins. The tooling never holds work on the earlier, narrower record: no hook compares scopes, and `provenance.py decisions` lists records newest first and marks an earlier record `superseded by <id>` when a later record names it (`supersedes` or `recites`) or has the same event kind and the same `goal` or `ticket`. A record that is not marked is not thereby in force over a later owner message the tooling cannot see as related: read the owner's newest words (`ah user-msg --recent N`) first.

## Hooks

- `stop-lint` (Stop): at most one short advisory line per turn, and only for an explicit needed-from-you sentence ("Needed from you: ...", "What I need from you:" with bullets, "I need you to ...", "waiting on you", "waiting for you to", "blocked on you") that names no registered `[ask:<id>]` (or inline `[src: ...]`). Offers, optional suggestions, questions in passing ("Should I also...?", "If you want I can...", "Tell me if you want...") and status notes raise nothing; a negation before the phrase ("Nothing is needed from you") cancels it. The same sentence is flagged once per session (state in `~/.agent-harness/state/provenance-lint/<session>.json`). The line goes to the owner as a system message and to the agent on its next prompt. It never blocks.
- `ask-gate` (PreToolUse on AskUserQuestion): a question with no registered `[ask:<id>]` gets one advisory line; a registered ask's note is shown so a reused id is visible. It denies only for presence: a modal question while the owner is away (no human turn within `ask_presence_minutes`) or from a sub-agent, which is routed to main instead.
- `prompt` (UserPromptSubmit): delivers the pending advisory line once.
- `answer` (PostToolUse on AskUserQuestion) and the central-decisions sweep: unchanged (see [central-decisions.md](central-decisions.md#withdrawal-and-the-local-path)).
- `status_truth.py stop` prints nothing; the status-question and post-compaction goal injections remain.

Every hook fails open on its own errors (stderr note, exit 0) and runs under the watchdog (512 MiB, 8 s). Input handling follows `safe_input.py` (regular files only, bounded reads); `tests/test_input_lint.py` keeps new unbounded reads out.

## Commands

```
python3 ~/.claude/hooks/ah.py user-msg --recent N         # the owner's recent messages, each with a ready --source
python3 provenance.py check --source '<anything>'          # resolve one source (exit 2 when unsourced)
python3 provenance.py trace <ask-id> --session <id>        # chain back to the origin; or --source '<src>' / AC-1 --spec <f>
python3 provenance.py asks --session <id> [--json [--items]]   # open asks, newest first, unsourced ones labelled
python3 provenance.py decisions --session <id> [--json]    # requirements, scopes, decisions, asks, blockers, newest first
python3 provenance.py check-spec <spec.md>                 # report each AC/NEG source (exit 2 when any is unsourced)
python3 provenance.py find-user --session <id> --text '<words>'
python3 provenance.py cache-ticket --ref 'GoodQA <project>#<n>' --title '<title>' --checked-by main
```

`asks` and `decisions` are listings and exit 0. `asks --json --items` keeps its shape for Mission Control: unsourced asks are listed under `blocked` (now also counted as `unsourced`), each with its cause.

## Known gaps

- The stop lint sees only the literal phrases above; other phrasings pass.
- Supersession is found only through `supersedes`, `recites`, `goal` and `ticket`; two records about the same subject without those fields are not linked.
- A hostile agent can edit the transcript, the WAL, the hooks or the policy file.
