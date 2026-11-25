# Central top-rung decisions

GoodQA goodqa#16651. A top-rung (Fable or Astra) permission that `ah approve-top` recorded for one task on the Mac can be published once to a GoodQA ledger ticket. The Mac and its worker hosts then accept it for exactly that task until it expires or is revoked. The user does not have to repeat the request in a local session on each host.

## Trust model

The root of trust stays the user's own words in the Mac transcript. `ah decision publish --task K` signs a record only after re-running these checks:
- The task's local escalation record has a permission, and its WAL ask pair still verifies (`verify_ask_pair`).
- The cited turn is a human `user:` turn. Central publication refuses `answer:` and `queue:` sources.
- The cited turn holds an assenting sentence, the cited excerpt is inside that sentence, and the turn is less than 12 hours old (`verify_top_source`).
- No later human turn, queued message or answer in that session names the top rung, retracts or starts with a withdrawal. Publish scans the transcript before it signs and again after it posts. If a later turn arrived during the publish, it withdraws the new decision at once.
- No revocation made after the user's words covers the task, the session or a decision from the same turn.
- The turn backs no more than 3 task keys on the ledger.

The record is signed with an Ed25519 key at `~/.agent-harness/private/decisions/signing-ed25519.key`. The key file is mode 0600 inside a 0700 directory, and the command guard treats `*.key` paths as credential material. The key never enters argv, environment, logs, WALs or GoodQA.

Each host accepts only signatures that verify against the public key the user pinned (`~/.agent-harness/decisions/trusted-keys.json`).

What the signature protects against:
- accidental damage;
- forged, edited, replayed or reordered GoodQA comments, from anyone with GoodQA access, including agents that hold the user token or the member key;
- tampering in transit;
- a record for one task reused for another.

What it does not protect against:
- a malicious local agent on the Mac that reads the key file or edits the hooks;
- an agent that replaces the pinned public key on a host. This is the same class of risk as editing the escalation state today.

GoodQA comment authorship is never trusted as a grant, because agents act with the user's token.

## Record format

A decision is a comment whose whole body is one line:

```
agent-harness-decision v1 <base64url(payload)>.<base64url(signature)>
```

The signature covers the bytes `"agent-harness-central-decision-v1\0" + <ledger issue id> + "\0" + payload`.

The ledger issue id comes from the host's config, never from the record. The payload must:
- be JSON with no duplicate keys;
- have exactly the schema's key set;
- equal its canonical re-serialisation (sorted keys, no spaces, ASCII).

The payload binds:
- the decision id and the task key (an exact `SAFE_KEY` match: no wildcards, no case folding);
- the families named in the sentence (`fable` and/or `astra`);
- the source, session and turn uuid;
- the sentence and its sha256;
- the assent, issue and expiry times;
- the key id, the issuing host and the ask id.

Verification checks these time rules:
- `assent_at <= issued_at <= now + 120 s`;
- `expires_at <= assent_at + 12 h`;
- `now < expires_at`.

A host whose clock is more than 120 s behind the GoodQA server denies. Server time is the newer of the latest ledger comment and the HTTP `Date` header of the read itself, so a quiet ledger does not hide a slow clock; a response without a usable `Date` denies.

## Revocation

Revocation never needs a signature, because it can only deny. A comment whose whole body is one of these lines revokes, whoever posts it, archived or not:

```
agent-harness-revoke all
agent-harness-revoke task <task-key>
agent-harness-revoke session <session-uuid>
agent-harness-revoke decision <decision-id>
```

Scope rules:
- A `decision` revoke covers that id at any time.
- `task`, `session` and `all` revokes cover every decision whose user words came before the revoke. A re-publish of the same words therefore stays revoked, and new words after a revoke are a new decision.
- Closing the ledger ticket revokes everything.

Hosts keep a sticky local copy of every revoke they have seen (`tombstones.jsonl`). Tombstones only deny. A revoke without a server time is kept as newer than every grant, so a scope revoke of that kind blocks later decisions in its scope on that host. To recover after removing such a comment from the ledger, the user moves `~/.agent-harness/decisions/tombstones.jsonl` aside on that host; the next read rebuilds it from the ledger.

In the originating session, a later user turn that names the top rung or withdraws (typed, answered to an AskUserQuestion prompt, or queued mid-turn; see "Withdrawal and the local path") makes the provenance hooks revoke that session's published decisions by id. They write a row in `pending-revocations.jsonl`, then a local tombstone, then post the queue; a row leaves the queue only after its post succeeded, so a failed post or a hook stopped after the row was written leaves it queued for every later hook verb to retry. Until the queued post lands, other hosts still accept the decision (at most until its expiry). Publish refuses, before posting, when it cannot write the `published.jsonl` index that this hook relies on.

A retraction typed in a different session does not revoke automatically; use `ah decision withdraw` there.

`ah decision withdraw --task K | --session S | --decision ID | --all` does the same on demand.

## Consumers

Local approvals live in one store, `~/.agent-harness/approvals.jsonl` ([approvals.md](approvals.md)). A central
decision is the signed cross-host copy of one top-rung permission; it is not a second local store. `tier_gate.py`
reads the ledger permission, then a `top-rung` approval in that store, then a central decision.

- `tier_gate.py` treats a verified central decision as the task's recorded permission. It applies only where the local permission is read for launches: the Agent spawn (family fable) and the Bash launch and climbed-rung checks (fable or astra by model). Reviewers are excluded, because `peer_review.py` honours only local permissions. The rung ceiling is unchanged, and nothing is written into the escalation state. All ledger reads of one hook run share one 6 s budget inside the hook's 10 s timeout, and the hook blocks on failure.
- An external consumer on a worker host (a batch runner that launches top-rung work) may call
  `central_decisions.verify(..., max_age_seconds=N)` when the task has no local escalation record; a decision whose
  user words are older than N is refused. Its own later-withdrawal check must be `withdrawal_signal` narrowed, never
  wider.

## Withdrawal and the local path

A local grant is withdrawn when a later human turn in the same session names the top rung, retracts, or opens with a withdrawal word (no, stop, cancel, revoke, do not, don't) for that task or for all work. The local path finds this by scanning the transcript, and it reads three kinds of turn there: a typed prompt, an answer to an AskUserQuestion prompt (`toolUseResult.answers`), and a message queued while the agent was working (`queue-operation`).

A worker host has no transcript, so a central decision there is withdrawn only by a revoke on the ledger. Every channel the local path reads therefore produces a ledger revoke from the Mac's hooks in the originating session. All of them use one predicate, `central_decisions.withdrawal_signal`, which a consumer may narrow but never widen:

| Channel | Hook (provenance_hooks.py verb) | When it revokes |
|---|---|---|
| Typed prompt | UserPromptSubmit (`prompt`) | at submission, on the prompt text |
| AskUserQuestion answer | PostToolUse on AskUserQuestion (`answer`) | when the answer returns, on `tool_response.answers` (read by `provenance.ask_answers_text`, the extractor the local path uses); an answer that cannot be read revokes |
| Queued mid-turn message, or anything the two above missed | Stop (`stop-lint`), and also `prompt` and `answer` | at the end of the turn: a transcript sweep (`later_mentions`, the same record reader as publish) after each live decision's cited turn; a transcript that cannot be read revokes |
| On demand | `ah decision withdraw --decision/--task/--session/--all` | at once |
| Anyone | a revoke line posted on the ledger ticket | at once |

Each hook revokes only decisions published from its own session. For each it writes a queue row and then the local tombstone (the Mac denies at once), with no network yet; the row comes first because a tombstone hides the decision from later hooks, so a hook stopped between the two writes must leave the row, not a lone tombstone; then it posts the whole queue with one client inside one 6 s budget per hook run (the hook's watchdog is 8 s). A row leaves the queue only after its post succeeded, under a file lock so a concurrent hook in another session cannot drop it, and every hook verb retries the queue. A decision this host already tombstoned is not revoked again. `stop-lint` prints its own result before the central work, so a slow sweep cannot cost the quarantine or lint outcome. The sweep reads a transcript in well under a second (31 to 44 MB transcripts: 0.18 to 0.35 s for a full read on the Mac).

Guarantee, as tested (`EveryWithdrawalChannelRevokes`): for every channel above, once the revoke line is on the ledger, the central path denies on a worker host without the transcript wherever the local path denies on the Mac. Limits:
- **Post not landed.** Between the withdrawal and a successful post, worker hosts still accept the decision. Causes: GoodQA unreachable, the budget spent, the hook killed during the post, or the hook not running at all (crashed before it wrote the queue row, or not installed). In the first three cases the line stays queued and the next hook in any session on the Mac posts it; a hook that finished says "NOT posted" in the agent's context. In the last case nothing is queued. `ah decision withdraw --all` closes the gap at once.
- **Latency.** Typed prompts and answers revoke when the hook runs. Queued messages revoke at the next Stop, prompt or answer hook.
- **Another session.** A withdrawal typed in a different session is not seen by either path; the local path also scans only the originating session.

On a worker host the originating transcript is absent, and the ledger is what applies.

## Replay binding (accepted risk)

A central decision is keyed by task and family only: the task is the sha256 of project, run and work item. It is not bound to a `request_id`, a `packet_sha256` or a worker host. Within its freshness window, the same decision authorizes any request for that task on any host that pins the key and reads the ledger. A local grant has the same binding, but only on its own host; the central path makes it reachable from every worker. This is recorded as an accepted risk (ASSUMPTION, inferred by the implementer: the user has not been asked). Binding to `issuer_host` would not narrow which worker accepts it, and binding to a target worker would need a new field at publish time and a product decision on which hosts may run a task. Bounds that apply: the 12 h cap and the caller's shorter cap, the exact-task match, revocation, and the 3-key per-turn cap.

## Why the hooks directory is trusted

`central_decisions.py` runs from `~/.claude/hooks`, the same directory as `escalation.py` and `provenance.py`. A
consumer that imports it should first check that the directory and the file are owned by root or the runtime user and
are not writable by group or others. The threat model does not cover a process running as the same user that
rewrites those files.

## Limits of the ledger read

- A revoke comment without a usable server time still denies (it counts as newer than every grant); a grant without one is not valid. Publish refuses when the Mac clock is more than 120 s from the server's.
- Every read fetches the whole ledger: archived comments included, at most 10 pages of 200. Running out of pages, an unreachable tracker, a missing or closed ticket, a missing pinned key or a missing `cryptography` package all deny.

## Commands

```sh
python3 ~/.claude/hooks/ah.py decision verify --task KEY --family fable     # exit 0 only when valid now
python3 ~/.claude/hooks/ah.py decision publish --task KEY                   # Mac, after ah approve-top
python3 ~/.claude/hooks/ah.py decision withdraw --all                       # deny everywhere
```

Setup, by the user: install the merged harness on each host; on the Mac run `ah decision keygen` and
`ah decision pubkey`; on every host run `ah decision pin --pubkey-file F` and `ah decision enable --project P --number N`
(the ledger ticket).

Rollback, in order of speed:
1. `ah decision withdraw --all` (or the line `agent-harness-revoke all` on the ledger ticket) denies on every host at once.
2. Remove `~/.agent-harness/decisions/config.json` on a host to turn the feature off there.
3. Reinstall the previous hooks on the host.

## Limits

- The residual race is the gap between a passing check and the launch that check gates.
- Expiry uses each host's clock, with the 120 s check against the GoodQA server time.
- The user's sentence need not name the task keys; `ah decision publish` is bounded by the 3-key cap, the exact-key match and the 12 h expiry.
- About 2,000 junk comments on the ledger make every central check deny. This is an availability attack that the threat model accepts.
