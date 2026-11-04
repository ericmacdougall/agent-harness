# Requirement provenance

Goal: the harness cannot carry or present a requirement, ask, blocker, acceptance criterion or decision whose origin cannot be traced. What is enforced is the ledger edge: nothing enters a spec, a requirement or the asks ledger without a verifiable Source, and lists are rendered from the ledger. Free text an agent types into chat is not intercepted (see Known gaps). Trigger: a status list told the user to supply a key nobody could trace to a user request (GoodQA #14398).

Threat model: a careless or hallucinating agent, not a hostile one. An agent that edits transcripts, `provenance_policy.json` or the hooks can defeat this, as with the other gates. Provenance proves a quote exists in a real user turn; it does not prove the quote supports the claim, so every ask list prints the quoted words next to the claim for a human to judge.

## Source grammar

| Source | Resolves when | Label |
| --- | --- | --- |
| `user:<session-uuid>/<message-uuid> "excerpt"` | the transcript `~/.claude/projects/*/<session>.jsonl` has a record whose `uuid` matches, that is human-authored, and whose typed text contains the excerpt | USER |
| `ticket:GoodQA <project>#<n> [comment <id>]` | syntax is valid. No network call: it is `deferred` (an unverified citation) unless `~/.agent-harness/provenance/tickets.json` lists it, which main does with `provenance.py cache-ticket` after checking the tracker | TICKET |
| `wal:<path>#<id>` or `#L<line>` | the WAL entry exists under `~/.claude/wals`, and its own `source` resolves (cycles and depth over 8 are rejected) | label of the end of the chain |
| `file:<path>:<line>[-<end>]@<sha> ["excerpt"]` | `git cat-file blob <sha>:<path>` has those lines (and the excerpt) | FILE |
| `inferred: from <src> ; <src> -- <rationale>` | at least one input is a grounded non-inferred source, every input resolves, and the rationale has 10+ characters | ASSUMPTION |

Unverified citations (a deferred ticket, a `file:` line with no excerpt) are accepted in specs with a warning, are refused for `requirement` and `ask` events, never count as the grounded input of an `inferred:` source, and are listed apart in the asks ledger.

Quote excerpts with `"` (escape inner `"` as `\"`) or smart quotes. `...` joins up to 3 ordered segments of 8+ characters each.

### What counts as a user turn

Default-deny: `type=user`, `origin.kind=human`, not sidechain, not `isMeta`, not a compaction summary, no `toolUseResult`, text blocks only. In list-form turns a text block that is one wrapper element (`<ide_opened_file>`, `<browser_instruction>` and the like) is dropped. Before matching, `<agent-message>`, `<task-notification>`, `<system-reminder>`, `<pasted_content>`, command and local-command blocks are removed (an unclosed opener removes the rest). An excerpt cannot contain the removed-block marker, and `...` segments cannot straddle a removed block.

### Excerpt matching

NFC normalisation, smart quotes, dashes and the ellipsis character folded to ASCII, whitespace runs collapsed. Case, zero-width characters, homoglyphs and compatibility forms (NFKC) are not folded, so near-miss forgeries do not match. Each segment needs 12 to 300 characters. Ask lists print the user's surrounding sentence from the transcript, not just the agent's quoted fragment, so a clipped quote cannot silently flip a meaning.

## Enforcement points

| Surface | Rule | Start mode | Move to enforce when |
| --- | --- | --- | --- |
| spec_flow lint (`new`, `lint`, `packet`, `review`, `attach`) | every AC-n and NEG-n has a resolvable `Source:`; `Provenance: grandfathered (reason)` is accepted only in the header with `Sign-off: human` | enforce (new specs only; a spec that already carries a `## Reviews` section is only warned about, until it is edited) | already |
| `wal_note.py --event requirement` / `ask` | `--source` required; ask also needs `--reason` | enforce (new events, nothing to break) | already |
| `wal_note.py --event blocker` / `scope` / `decision` | `--source` expected | warn (existing flows) | after one release with under 5 percent of warnings in `provenance: missing` entries (`provenance.py asks`, WAL grep) |
| `peer_review.py plan` packets | AC/NEG/REQ/ASK/DEC lines need `Source:` | warn | after the owners' packets carry sources routinely |

Rollback is `"off"` in `provenance_policy.json`; there is no data migration. New WAL fields (`id`, `source`, `reason`, `ref`, `provenance`, `assumption`) are additive, and readers ignore unknown events and fields.

## Asks ledger

Asks are WAL events, so they use the existing locked append and per-agent files. `provenance.py asks --session <id>` merges the main and agent WALs and prints four groups: traceable asks, unverified citations (offline ticket or repo-file origin), assumptions to confirm, and BLOCKED untraceable items that must not be shown to the user. A status or ask list for the user is built from that output, never from memory. No Stop-hook that parses the chat was added: free text cannot be matched to ledger entries without false positives and negatives, and a fragile hook that blocks or nags erodes trust. The enforceable edge is the ledger plus the rule that lists are rendered from it.

## Known gaps

- An agent can still type an unsourced request into chat. A deterministic edge would be a PreToolUse hook on `AskUserQuestion` that requires an `[ask:<id>]` naming a traceable ledger entry; it is not included because it needs settings.json wiring that the owner of the installed hooks should approve.
- Provenance proves a quote exists in a user turn, not that it supports the claim.
- A hostile agent can edit the transcript, the WAL or the policy file.

## Fail-safe behaviour

Malformed, oversized (over 8 MiB) or deeply nested (over 200 levels, checked by a linear scan) lines are skipped and counted, never parsed unguarded; one claim resolves at most 40 sources; because Python 3.9 can abort the interpreter on very deep JSON. Missing transcripts or WALs are rejection statuses (`transcript-missing`, `wal-missing`), not tracebacks; in enforce mode an unverifiable `user:` source is refused. On a host without the transcript, cite the main agent's sourced WAL entry or a ticket. Error text carries at most 60 characters of an excerpt, and `wal_note.py` applies its credential filter to `--source` and `--reason`. `trace` prints the exact user message on purpose; it is local terminal output.

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
