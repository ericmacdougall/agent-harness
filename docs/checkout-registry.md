# Checkout registry

`harness/hooks/checkout_registry.py` (goodqa#16947) records who created each git checkout an agent makes. Stream B's owner
removal uses these rows to decide what an agent may delete as its own work, and the janitor reads them too. The rule is
simple: a missing row is safe, but a wrong row deletes someone's work. So a row is written only when a hook watched the
checkout being born during that agent's own tool call.

## What gets a row

- **Clones and worktrees.** A `git clone URL DIR` or `git [-C REPO] worktree add PATH` that a Claude agent runs through Bash
  on this machine. This covers the Mac, and t2-dev's own sessions on t2-dev.
- **Isolation worktrees.** Each isolation worktree Claude Code makes for a subagent, `REPO/.claude/worktrees/agent-<agent_id>`.

Each row goes in `~/.agent-harness/state/checkouts/local.jsonl`:

```
{"v":1,"event":"created","kind":"clone","host":"local","path":"/Users/me/x","dev":16777234,"ino":123,
 "btime_ns":1795496019112242768,"common_dir":"/Users/me/x/.git","session":"<session id>","agent":"<agent id or null>",
 "task":null,"created_at":"2026-11-24T05:00:00Z","tool_use_id":"toolu_...","mac":"<hmac-sha256>"}
```

- **Identity.** A checkout is identified by host, dev, ino and btime_ns. The path is not part of the identity, because ext4
  reuses an inode number as soon as it is freed (40 of 40 times on t2-dev). The birth time tells a new checkout from an old
  one. Where the birth time cannot be read, no row is written. On macOS it comes from `st_birthtime`; on Linux from
  `/usr/bin/stat -c %.9W`.
- **`removed` rows.** These end ownership. Stream B's route writes one after it removes a checkout, through
  `append_removed(identity, by, route)`. A hook that sees the path gone writes one with route `observed-absent`.
- **Signing.** `mac(row)` and `verify(row)` are the only signing functions. The key is
  `state/checkouts/registry.key`: 32 random bytes, mode 0600, created once.
- **Ownership check.** `held(identity)` is the only one. It reads the host's own file and returns None when two created
  rows name one identity.
- **Kill switch.** Replacing the key voids every row.

## How a Bash row is proven

The command text only proposes a path. The row needs all of the following, as observed state:

1. PreToolUse sees the path absent (ENOENT). It pins the nearest existing folder above the path by realpath, dev and inode.
   It takes a clock mark (the birth time of a fresh file) and claims the path under a lock.
2. Any second claim on the same path marks it contested, and neither call gets a row.
3. PostToolUse or PostToolUseFailure carries the same tool_use_id, session, agent and command hash as the signed pending
   record. The payload's transcript must be the session's own, and it must hold that Bash tool_use.
4. The path is now a git checkout top. It is not a symlink and it is under the home folder. It sits at the pinned folder,
   which still has the same dev and inode, and it was born at or after the clock mark. That rules out a checkout moved in
   with `mv`.
5. For a clone, `remote.origin.url` is the command's URL. For a worktree, it is linked and has the named repo's common dir.

## How an isolation row is proven

- The path is named after the payload's agent id.
- It is a linked worktree listed by the repo that contains it.
- The subagent transcript `~/.claude/projects/*/<session>/subagents/agent-<id>.jsonl` exists.
- The worktree was born within 300 s of that transcript.

The row is written at SubagentStart, or at the agent's first tool call from inside the worktree.

## Why no row was written

Every refusal appends one reason code to `state/checkouts/decisions.jsonl`. The codes are:

| Stage | Codes |
|---|---|
| PreToolUse | `existed-at-pre`, `unreadable-at-pre`, `repo-unknown`, `contested`, `unsure` |
| PostToolUse | `pending-missing`, `pending-bad-mac`, `pending-foreign`, `pending-expired`, `transcript-unbound`, `not-made`, `link`, `not-a-checkout`, `outside-home`, `realpath-moved`, `anchor-changed`, `no-btime`, `born-before-pre`, `not-linked`, `repo-mismatch`, `origin-mismatch`, `second-owner`, `already-held` |
| Other | `background`, `permission-denied` |
| Isolation | `iso-not-checkout`, `iso-not-listed`, `iso-no-transcript`, `iso-window` |

A successful write is recorded as `written`.

```
python3 ~/.claude/hooks/checkout_registry.py list                 # verified rows, failures, how many are held
python3 ~/.claude/hooks/checkout_registry.py stat --path ~/x      # read-only facts about one path
tail -n 20 ~/.agent-harness/state/checkouts/decisions.jsonl       # why recent calls did or did not get a row
```

No command writes a row by hand. The `hook` verbs read a hook payload, and a made-up payload fails the transcript binding.

## When an agent stops

SubagentStop writes `~/.agent-harness/work/<session>/inbox/data-checkout-<agent>.md` for the parent session. owner_inbox
injects it under a header that says it is data, not instructions. For each checkout the agent still holds, the note lists:

- the changed, untracked and ignored counts;
- the branch and HEAD;
- commits on no remote ref;
- the repo's stash count;
- any checkouts nested under its path.

It also gives a verdict. "owner may remove" is given only to the agent's own isolation worktree when it is clean, has
nothing unpushed and has nothing nested. Everything else gets "keep: reasons".

The hook removes nothing. A resumed agent keeps its worktree. git runs hardened (no fsmonitor, no hooks, no optional
locks), within a 15 s budget.

## Not covered (disclosed)

- **Codex.** Codex has no PostToolUse hook, so Codex checkouts get no rows. The manifest row
  `checkout_registry:codex` records this gap.
- **Checkouts made over ssh.** `ssh t2-dev '... git clone ...'` gets no row yet; a later PR adds it with a remote stat
  before and after the call. Until then the hooks start no ssh, and a remote command naming clone or worktree proposes
  nothing.
- **Other ways a checkout appears:**
  - `gh repo clone`;
  - `cp -r`, `rsync -a` and `ditto` copies;
  - the EnterWorktree tool;
  - `--bare` and `--mirror` clones;
  - clones inside scripts and wrappers (kill_guard spawn, bg_job, testrun);
  - a `mkdir P` in one call followed by `git clone U P` in a later one.
- **Background clones.** A `run_in_background` clone gets no row, because PostToolUse fires at launch.
- **SubagentStop gaps.** SubagentStop does not fire for every agent, so the janitor is the backstop.
- **macOS device numbers.** st_dev can change across a reboot. Rows then stop matching: safe, but stranded.
- **Trust boundary.** It is the same as kill_guard's ledger: careless agents, not a hostile process with the same uid
  that reads the key.
- **Forgery protection.** command_guard's `state_files` list should protect `state/checkouts/` against direct writes.
  That is stream B's file, and the rule was handed over.
