# Requirement provenance

Goal: the harness cannot carry or present a requirement, ask, blocker, acceptance criterion or decision whose origin cannot be traced. What is enforced: nothing enters a spec, a requirement or the asks ledger without a verifiable Source, lists are rendered from the ledger, and the Stop and AskUserQuestion hooks check that chat asks cite it. Trigger: a status list told the user to supply a key nobody could trace to a user request (GoodQA #14398).

Threat model: a careless or hallucinating agent, not a hostile one. An agent that edits transcripts, `provenance_policy.json` or the hooks can defeat this, as with the other gates. Provenance proves a quote exists in a real user turn; it does not prove the quote supports the claim, so every ask list prints the quoted words next to the claim for a human to judge.

## Source grammar

| Source | Resolves when | Label |
| --- | --- | --- |
| `user:<session-uuid>/<message-uuid> "excerpt"` | the transcript `~/.claude/projects/*/<session>.jsonl` has a record whose `uuid` matches, that is human-authored, and whose typed text contains the excerpt | USER |
| `answer:<session-uuid>/<message-uuid> "excerpt"` | the user's answer to an AskUserQuestion: a transcript user record whose single tool_result answers an assistant `AskUserQuestion` tool_use of the same transcript and contains the excerpt. Another tool's result never qualifies. The citation shows `trust [answer]` | USER |
| `queue:<session-uuid>/<timestamp>#<sha12> "excerpt"` | a queued mid-turn user message: a transcript `queue-operation` enqueue or popAll record at that timestamp whose content hashes (sha256, 12 hex) to the id, is not a harness wrapper element and contains the excerpt. Queue records carry no origin marker, so the trust is the accidental-damage threat model; the citation shows `trust [queue]`. `ah user-msg` prints both ids | USER |
| `ticket:GoodQA <project>#<n> [comment <id>]` | syntax is valid and the ticket exists. A hit in `~/.agent-harness/provenance/tickets.json` is trusted; otherwise one GoodQA lookup runs through the harness ticket adapter (4 s deadline, one attempt, proxy environment ignored) and a found ticket is cached. A ticket the tracker reports missing is refused (`ticket-missing`) when `ticket_lookup` is `enforce`. A cite that cannot be confirmed (transport outage, server or 4xx error, unusable credentials, project not visible, lookup off, or the lookup skipped for 60 s after a transport failure) is `unverified`: accepted in specs with a warning, but refused for `requirement` and `ask` events whose only cite it is, outage or not, because `user:` and `wal:` sources can be checked locally. It only warns when a verified `user:`, `wal:` or `file:` input stands behind the claim. Only a genuine transport failure (connection, DNS, timeout, deadline) starts the 60-second skip window, and the window only skips the network call: it never changes a verdict. `ticket_lookup` `warn` never refuses a missing ticket in specs and `off` skips the lookup. `provenance.py cache-ticket` records a ticket main checked by hand. `HARNESS_PROVENANCE_OFFLINE=1` forces every uncached cite to `unverified` without any network call (tests set it) | TICKET |
| `wal:<path>#<id>` or `#L<line>` | the WAL entry exists under `~/.claude/wals`, and its own `source` resolves (cycles and depth over 8 are rejected) | label of the end of the chain |
| `file:<path>:<line>[-<end>]@<sha> ["excerpt"]` | `git cat-file blob <sha>:<path>` has those lines (and the excerpt) | FILE |
| `inferred: from <src> ; <src> -- <rationale>` | at least one input is a grounded non-inferred source, every input resolves, and the rationale has 10+ characters | ASSUMPTION |

Unverified citations (a ticket that cannot be confirmed, a `file:` line with no excerpt) are accepted in specs with a warning, are refused for `requirement` and `ask` events unless a verified source stands behind them, never count as the grounded input of an `inferred:` source, and are listed apart in the asks ledger.

Quote excerpts with `"` (escape inner `"` as `\"`) or smart quotes. `...` joins up to 3 ordered segments of 8+ characters each.

### What counts as a user turn

Default-deny: `type=user`, `origin.kind=human`, not sidechain, not `isMeta`, not a compaction summary, no `toolUseResult`, text blocks only. In list-form turns a text block that is one wrapper element (`<ide_opened_file>`, `<browser_instruction>` and the like) is dropped. Before matching, `<agent-message>`, `<task-notification>`, `<system-reminder>`, `<pasted_content>`, command and local-command blocks are removed (an unclosed opener removes the rest). An excerpt cannot contain the removed-block marker, and `...` segments cannot straddle a removed block.

### Excerpt matching

NFC normalisation, smart quotes, dashes and the ellipsis character folded to ASCII, whitespace runs collapsed. Case, zero-width characters, homoglyphs and compatibility forms (NFKC) are not folded, so near-miss forgeries do not match. Each segment needs 12 to 300 characters. Ask lists print the user's surrounding sentence from the transcript, not just the agent's quoted fragment, so a clipped quote cannot silently flip a meaning.

## Enforcement points

| Surface | Rule | Start mode | Move to enforce when |
| --- | --- | --- | --- |
| spec_flow lint (`lint`, `packet`, `attach`) | every AC-n and NEG-n has a resolvable `Source:`; `Provenance: grandfathered (reason)` is accepted only in the header with `Sign-off: human`. The `## Reviews` section never exempts a spec (`attach` rewrites it before linting), so an in-flight spec without Sources must gain them (its reviews go stale) or be grandfathered | enforce | already |
| `wal_note.py --event requirement` / `ask` | `--source` required; ask also needs `--reason` | enforce (new events, nothing to break) | already |
| `wal_note.py --event blocker` / `scope` / `decision` | `--source` expected | warn (existing flows) | after one release with under 5 percent of warnings in `provenance: missing` entries (`provenance.py asks`, WAL grep) |
| `peer_review.py plan` packets | AC/NEG/REQ/ASK/DEC lines need `Source:` | warn | after the owners' packets carry sources routinely |

Rollback is `"off"` in `provenance_policy.json`; there is no data migration. New WAL fields (`id`, `source`, `reason`, `ref`, `provenance`, `assumption`) are additive, and readers ignore unknown events and fields.

## Asks ledger

Asks are WAL events, so they use the existing locked append and per-agent files. `provenance.py asks --session <id>` merges the main and agent WALs and prints four groups: traceable asks, unverified citations (offline ticket or repo-file origin), assumptions to confirm, and BLOCKED untraceable items that must not be shown to the user. A status or ask list for the user is built from that output, never from memory. No Stop-hook that parses the chat was added: free text cannot be matched to ledger entries without false positives and negatives, and a fragile hook that blocks or nags erodes trust. The enforceable edge is the ledger plus the rule that lists are rendered from it.

## Chat and AskUserQuestion hooks

`provenance_hooks.py` closes the original incident path, a plain-chat "needed from you" list.

- `ask-gate` (PreToolUse on `AskUserQuestion`): every question must contain `[ask:<id>]` naming an ask in this session's WALs (main and agents) whose Source still resolves and is not an unverified citation. Otherwise the call is denied with the fix. Policy key `ask_user_question`, default `enforce`.
- `stop-lint` (Stop): finds user-directed ask items in the final assistant message and requires `[ask:<id>]` or an inline `[src: <source>]` that resolves on each. Policy key `stop_lint`, default `warn`: the user sees a system message and the agent gets the reminder on its next prompt via `prompt` (UserPromptSubmit). In `enforce` it blocks the stop once with the uncited items listed (`stop_hook_active` prevents a loop).
- `prompt` (UserPromptSubmit): delivers a pending warn-mode reminder once.
- Every hook fails open on its own errors (stderr note, exit 0). One-line disable: set the policy key to `"off"` in the installed `provenance_policy.json`, or delete the hook entry.
- Environment variables can only tighten modes, never loosen them: `HARNESS_PROVENANCE_POLICY=<json>` and `HARNESS_PROVENANCE_TICKET_LOOKUP=<mode>` apply only where stricter than the installed policy, so an agent setting one inline cannot downgrade an enforce gate. Loosening comes from the installed `provenance_policy.json` alone. Tests loosen modes with a private copy of the hook scripts that carries its own policy file. Variables that choose where evidence lives (`HOME`, `CLAUDE_CONFIG_DIR`, `HARNESS_PROVENANCE_REPO`) are trusted as the harness set them; they are not modes and a hostile agent could point them at forged evidence (outside the threat model). The ticket cache write has no lock, so two concurrent writers can drop an entry; a dropped entry only costs one more lookup.

Detector (conservative): a heading or label such as "What I need from you", "Your call", "Decisions needed", "Waiting on you", "Blocked on you", "Questions for you", "Open questions" makes the bullets under it ask items; a sentence such as "I need you to", "please provide|confirm|send|approve", "can you provide", "waiting on your answer", "tell me if you want", "say if you want", "which one do you want", "wait until you tell me" is an ask item by itself. A negation in the same sentence ("nothing is waiting on you", "I don't need anything from you") cancels it, and fenced code is ignored.

### Calibration (this session, baab765b, last 200 assistant text messages, 2026-11-04)

Labels were assigned by the owner agent (not a second human), after tuning the patterns on the same messages, so treat the numbers as an upper bound. Positive means the message asks something of the user or makes progress depend on the user's reply.

| Set | Messages | Positives | Detector flagged | True positive | False positive | Missed |
| --- | --- | --- | --- | --- | --- | --- |
| all 200 | 200 | 19 | 18 | 18 | 0 | 1 |
| random 50 (seed 20261104) | 50 | 6 | 5 | 5 | 0 | 1 |
| held out: 10 other sessions | 108 | not labelled | 7 | 6 judged real asks | 1 (a rule statement, pattern since narrowed) | unknown |

False positive rate on the 181 non-ask messages: 0 of 181 (the rule of three gives an upper bound near 2 percent at 95 percent confidence); the held-out set adds one false positive in 108 messages before the pattern fix. Recall on asks phrased as this agent usually phrases them is about 95 percent; asks phrased in other ways are not detected. The earlier version flagged two "nothing is waiting on you" status lines (4 percent of the 50-message sample) until negation handling was added, which is why that handling exists.

Independent check: a separate agent that had not seen these labels hand-labelled the 50-message sample. It agreed with the owner labels on 48 of 50 messages (96 percent, Cohen's kappa 0.81; each found 6 positives). Against the independent labels the detector had 5 true positives, 0 false positives, 1 miss and 44 true negatives. Fifty messages from one session is a small sample.

Recommendation: `stop_lint` ships and stays `warn`. Enforcement needs a calibration on more sessions than one before it is switched on; the red-team also showed that the pre-fix detector nagged on status text, so the enforce-mode false positive rate is not yet established. The Stop block fires once per message when enforced.

### settings.json entries (registered by install.py)

```json
"PreToolUse": [ { "matcher": "AskUserQuestion", "hooks": [ { "type": "command", "command": "python3",
    "args": ["/Users/eric/.claude/hooks/provenance_hooks.py", "ask-gate"], "timeout": 10 } ] } ],
"Stop": [ { "hooks": [ { "type": "command", "command": "python3",
    "args": ["/Users/eric/.claude/hooks/provenance_hooks.py", "stop-lint"], "timeout": 10 } ] } ],
"UserPromptSubmit": [ { "hooks": [ { "type": "command", "command": "python3",
    "args": ["/Users/eric/.claude/hooks/provenance_hooks.py", "prompt"], "timeout": 10 } ] } ]
```

`install.py` registers these three entries on every install (replacing an earlier registration of the same script, so a re-install neither drops nor duplicates them). `python3 install.py --apply --no-provenance-hooks` unregisters them and leaves the files installed; the next plain install registers them again. Modes still come from `provenance_policy.json`. Typical cost on a 75 MB transcript: `stop-lint` about 30 ms, `ask-gate` about 60 ms (interpreter start is about 24 ms of each).

## Known gaps

- The Stop lint only sees asks phrased in the patterns above; other phrasings pass.
- Provenance proves a quote exists in a user turn, not that it supports the claim.
- A hostile agent can edit the transcript, the WAL, the hooks or the policy file.

## Input validation standard (`safe_input.py`)

Every hook treats paths, stdin and JSON text it did not write as hostile. `harness/hooks/safe_input.py` is the one implementation: `open_regular_file` (regular files only, optional allowed roots, re-checked after open, no blocking on FIFOs), `read_bounded`, `read_tail`, `read_stdin_bounded`, `safe_json_loads(text, max_depth=100, max_bytes)` (size, nesting and number-length limits, ValueError otherwise) and `iter_jsonl_lines` (per-line cap, optional byte and time budget). `tests/test_input_lint.py` fails on new unbounded `read()`, `readlines()`, `read_text()`, `json.load(f)` and `sys.stdin.read()` in `harness/hooks` (annotate a justified exception with `# input-ok: <reason>`; hooks that predate the module are held to a baseline that can only shrink, GoodQA #14414). `tests/hostile_inputs.py` is the reusable fixture (devices, FIFO, 5 GiB sparse file, symlinks to devices, deep JSON, invalid UTF-8, NUL bytes, a 9 MiB line); run it against a hook with `run_capped`, which puts the child in its own process group and kills the group on timeout. The Stop, AskUserQuestion and prompt hooks also run a watchdog that exits 0 when peak RSS passes 512 MiB or the run passes 8 s of wall time, with RLIMIT_CPU at 6 s as the last resort: RLIMIT_AS and RLIMIT_DATA are not enforced on macOS. The watchdog is a Python thread, so a single long C-level call can delay it; long lines are therefore cut to 2000 characters before any pattern runs.

## Fail-safe behaviour

Malformed, oversized (over 8 MiB) or deeply nested (over 200 levels, checked by a linear scan) lines are skipped and counted, never parsed unguarded; one claim resolves at most 40 sources; because very deep JSON can abort or exhaust the interpreter. Missing transcripts or WALs are rejection statuses (`transcript-missing`, `wal-missing`), not tracebacks; in enforce mode an unverifiable `user:` source is refused. On a host without the transcript, cite the main agent's sourced WAL entry or a ticket. Error text carries at most 60 characters of an excerpt, and `wal_note.py` applies its credential filter to `--source` and `--reason`. `trace` prints the exact user message on purpose; it is local terminal output.

## Commands

```
provenance.py check --source '<src>'
provenance.py check-spec <spec.md>
provenance.py check-packet <packet.md>
provenance.py find-user --session <id> --text '<words>'
provenance.py trace <ask-id> --session <id>      # or: trace --source '<src>' / trace AC-1 --spec <spec.md>
provenance.py asks --session <id>
provenance.py cache-ticket --ref 'GoodQA <project>#<n>' --title '<title>' --checked-by main
```

## Performance

The transcript lookup reads 8 MiB chunks with `bytes.find` for the record's own `"uuid":"<id>"` field, then parses only the enclosing line. See the PR for measured numbers on a 75 MB transcript.
