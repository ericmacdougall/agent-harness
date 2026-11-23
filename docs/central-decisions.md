# Central top-rung decisions

GoodQA goodqa#16651. A top-rung (Fable or Astra) permission that `ah approve-top` recorded for one task on the Mac can be published once to a GoodQA ledger ticket. The Mac and its worker host (t2-dev) then accept it for exactly that task until it expires or is revoked. The user does not have to repeat the request in a local session on each host.

## Trust model

The root of trust stays the user's own words in the Mac transcript. `ah decision publish --task K` signs a record only after re-running these checks:
- The task's local escalation record has a permission, and its WAL ask pair still verifies (`verify_ask_pair`).
- The cited turn is a human `user:` turn. Central publication refuses `answer:` and `queue:` sources.
- The cited turn holds an assenting sentence, the cited excerpt is inside that sentence, and the turn is less than 12 hours old (`verify_top_source`).
- No later human turn, queued message or answer in that session names the top rung, retracts or starts with a withdrawal. Publish scans the transcript before it signs and again after it posts. If a later turn arrived during the publish, it withdraws the new decision at once.
- No revocation made after the user's words covers the task, the session or a decision from the same turn.
- The turn backs no more than 3 task keys on the ledger.

The record is signed with an Ed25519 key at `~/.agent-harness/private/decisions/signing-ed25519.key`. The key file is mode 0600 inside a 0700 directory, and the command guard treats `*.key` paths as credential material. The key never enters argv, environment, logs, WALs or GoodQA.

Each host accepts only signatures that verify against the public key the user pinned with the installer (`~/.agent-harness/decisions/trusted-keys.json`).

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

In the originating session, a later user turn that names the top rung or withdraws makes the provenance prompt hook revoke that session's published decisions by id. It writes a local tombstone first, then posts the revoke. A failed post is queued in `pending-revocations.jsonl`, retried on later prompts and reported in the agent's context. Until the queued post lands, other hosts still accept the decision (at most until its expiry). Publish refuses, before posting, when it cannot write the `published.jsonl` index that this hook relies on.

A retraction typed in a different session does not revoke automatically; use `ah decision withdraw` there.

`ah decision withdraw --task K | --session S | --decision ID | --all` does the same on demand.

## Consumers

- `tier_gate.py` treats a verified central decision as the task's recorded permission. It applies only where the local permission is read for launches: the Agent spawn (family fable) and the Bash launch and climbed-rung checks (fable or astra by model). Reviewers are excluded, because `peer_review.py` honours only local permissions. The rung ceiling is unchanged, and nothing is written into the escalation state. All ledger reads of one hook run share one 6 s budget inside the hook's 10 s timeout, and the hook blocks on failure.
- The T2Scan Claude adapter (`cli/adapters/claude-assessment.py`) uses the central path only when the approval task has no local escalation record. Both paths pass one check, `enforce_assent`:
  - the caller's freshness cap (for example the launcher's `top_assent_max_age_seconds`);
  - the family named in the record's family list and in the sentence;
  - the direct-assent words for `-astra-direct` tasks;
  - withdrawal.

  The adapter passes its cap to `verify(..., max_age_seconds=N)`, and a decision whose user words are older than N is refused.

## Withdrawal and the local path

A local grant is withdrawn when a later human turn in the same session names the top rung, retracts, or opens with a withdrawal word (no, stop, cancel, revoke, do not, don't) for that task or for all work. The adapter finds this by scanning the transcript.

A central decision is withdrawn by a revoke on the ledger. Revokes come from three places:
- **The prompt hook in the originating session.** It revokes every published decision of that session on any of those words. Its trigger is a superset of the adapter's, and a test pins that.
- **`ah decision withdraw`**, run on demand.
- **A revoke line posted on the ledger ticket.**

When the originating transcript is on the host running the adapter (the Mac), the adapter also runs its own transcript scan on the central decision's source. On a worker host the transcript is absent, so the ledger revocation is what applies there.

Known gaps, both covered by `ah decision withdraw --all`:
- A withdrawal given as an answer to an AskUserQuestion prompt is not a typed prompt, so the hook does not see it.
- The same applies to a withdrawal typed in another session.

## Why the hooks directory is trusted

`central_decisions.py` runs from `~/.claude/hooks`, the same directory as `escalation.py`, `provenance.py` and `usage_guard.py`, which the adapter already trusts for local grants. `repair-harness` installs it, and the installer compares its blob with the merged commit on both hosts.

Before importing it, the adapter checks that the directory and the file are owned by root or the runtime user and are not writable by group or others, as `binary_identity` does for the Claude binary. The threat model does not cover a process running as the same user that rewrites those files.
- A revoke comment without a usable server time still denies (it counts as newer than every grant); a grant without one is not valid. Publish refuses when the Mac clock is more than 120 s from the server's.
- Every read fetches the whole ledger: archived comments included, at most 10 pages of 200. Running out of pages, an unreachable tracker, a missing or closed ticket, a missing pinned key or a missing `cryptography` package all deny.

## Commands

```sh
python3 ~/.claude/hooks/ah.py decision verify --task KEY --family fable     # exit 0 only when valid now
python3 ~/.claude/hooks/ah.py decision publish --task KEY                   # Mac, after ah approve-top
python3 ~/.claude/hooks/ah.py decision withdraw --all                       # deny everywhere
```

The user-run installer `scripts/trust-central-decisions.sh` does the following, in order:
1. Checks the exact-HEAD `peer_review.py pr` receipt for each PR.
2. Merges each PR with `gh pr merge --match-head-commit`, then checks that the merge commit's second parent is the reviewed head.
3. Installs the merged harness on both hosts with `repair-harness`.
4. Creates the Mac key and pins it on both hosts.
5. Runs `approve-top` and `publish` for each T2Scan item.
6. Reinstalls the worker's T2Scan adapter from the merged trusted checkout.
7. Checks that `decision verify` and the adapter's `authorize` pass on the worker.

It never pushes to main itself.

Rollback, in order of speed:
1. `ah decision withdraw --all` (or the line `agent-harness-revoke all` on the ledger ticket) denies on every host at once.
2. Remove `~/.agent-harness/decisions/config.json` on a host to turn the feature off there.
3. `repair-harness --ref <previous main> --host t2-dev --apply` restores the previous hooks.
4. On the worker, check out the previous trusted T2Scan commit in `~/t2scan-runtime/t2scan` and reinstall the adapter (mode 0700).

## Limits

- The residual race is the gap between a passing check and the launch that check gates.
- Expiry uses each host's clock, with the 120 s check against the GoodQA server time.
- The user's sentence need not name the task keys. With the installer, the keys come from the items the user types on its command line; `ah decision publish` itself is bounded by the 3-key cap, the exact-key match and the 12 h expiry.
- The installer's receipt check parses the receipt file the user names; it does not prove the file came from `peer_review.py`.
- About 2,000 junk comments on the ledger make every central check deny. This is an availability attack that the threat model accepts.
