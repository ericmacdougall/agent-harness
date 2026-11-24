# Checkout registry

`harness/hooks/checkout_registry.py` (goodqa#16947, spec v3.2) records who created each git checkout an agent makes.
Stream B's owner removal uses these rows to decide what an agent may delete as its own work, and the janitor reads them
too. The rule is simple: a missing row is safe, but a wrong row deletes someone's work. So a row is written only when a
hook watched the checkout being born during that agent's own tool call.

## Off until the user turns it on

The registry is opt-in. Until `~/.agent-harness/state/checkouts/enabled.json` holds `{"enabled": true}` (a private file
the user writes: mode 0600, in the 0700 state folder, not a link):

- `install.py` does not wire its hooks, and `doctor.py` reports their manifest rows (status `opt_in`) as `OFF`, not
  `MISSING`;
- `held()` returns None for every identity, so no removal route can treat a row as ownership;
- no verdict says "owner may remove"; every stop note says "keep: checkout registry opt-in is off".

Recording needs no opt-in: hooks wired by hand, or by the live kit's `--settings`, still write rows, because a row alone
lets nothing be removed. Turn it on only after the live check `ac7-bash-clone-live` has passed at the installed commit
and is recorded as REALLY_TESTED:

```
mkdir -p -m 700 ~/.agent-harness/state/checkouts
printf '{"enabled": true}\n' > ~/.agent-harness/state/checkouts/enabled.json
chmod 600 ~/.agent-harness/state/checkouts/enabled.json
python3 install.py --apply          # wires the hooks
```

To turn it off again, remove that file and run `install.py --apply`.

## What gets a row

- **Clones and worktrees.** A `git clone URL DIR` or `git [-C REPO] worktree add PATH` that a Claude agent runs through Bash
  on this machine. This covers the Mac, and t2-dev's own sessions on t2-dev.
- **Isolation worktrees.** Each isolation worktree Claude Code makes for a subagent, `REPO/.claude/worktrees/agent-<agent_id>`.

Each row goes in `~/.agent-harness/state/checkouts/local.jsonl`:

```
{"v":1,"event":"created","kind":"clone","host":"local","path":"/Users/me/x","dev":16777234,"ino":123,
 "btime_ns":1795496019112242768,"gen":null,"common_dir":"/Users/me/x/.git","session":"<session id>",
 "agent":"<agent id or null>","task":null,"created_at":"2026-11-24T05:00:00Z","tool_use_id":"toolu_...",
 "mac":"<hmac-sha256>"}
```

- **Identity.** A checkout is identified by host, dev, ino, btime_ns and gen. The path is not part of the identity.
  - ext4 reuses a freed inode number at once (40 of 40 times on t2-dev). The birth time tells a new checkout from an old
    one.
  - A folder removed and recreated inside one clock tick has an equal birth time too (249 of 300 in-process rounds on
    t2-dev). On Linux the inode generation (`FS_IOC_GETVERSION`, readable unprivileged) changes on reuse, so `gen`
    separates them.
  - APFS does not reuse inode numbers, so `gen` is null on macOS.
  - With no birth time, or no generation on Linux, no row is written.
- **`removed` rows.** These end ownership. Stream B's route writes one after it removes a checkout, through
  `append_removed(identity, by, route)`. A path seen gone is retired with route `observed-absent` (see Retirement).
- **Signing.** `mac(row)` and `verify(row)` are the only signing functions. The key is
  `state/checkouts/registry.key`: 32 random bytes, mode 0600, created once.
- **Ownership check.** `held(identity)` is the only one. Every read of ownership (held, the writer's duplicate check,
  retirement, the stop note and `list`) goes through one function, `current()`. `held()` returns None for each clause of
  contract 4, listed in `CONTRACT_4` and each covered by a test and a mutant:
  - the opt-in is off;
  - the host is unknown;
  - the state folder is not on a local filesystem;
  - there is no safe key;
  - the file is over 64 MB, checked on the open file and again while reading, so it is never judged from a part;
  - two or more created rows name the identity, whoever wrote them;
  - a removed row, or a retirement, came after the created row.
- **Kill switch.** Replacing the key voids every row.

## How a Bash row is proven

The command text only proposes a path. The row needs all of the following, as observed state:

1. PreToolUse takes a clock mark (the birth time and st_dev of a fresh file in `state/checkouts/marks/`). It then sees
   the path absent (ENOENT) and pins the nearest existing folder above it by realpath, dev and inode.
2. It claims the path under the lock. The claim key is the expected path, NFC-normalized and casefolded, so case and
   Unicode variants of one path, and calls that pinned different parent folders, share one claim. A second claim marks the
   path contested, and neither call gets a row. A claim file that cannot be read counts as someone else's claim.
3. PostToolUse or PostToolUseFailure carries the same tool_use_id, session, agent and command hash as the signed pending
   record. The payload's transcript must be the session's own. For an agent, only its own file
   `projects/<p>/<session>/subagents/agent-<id>.jsonl` is searched, never the main transcript. It must hold that Bash
   tool_use.
4. Post takes a second clock mark. The path is now a git checkout top. It is not a symlink, and it is under the home
   folder. Its realpath equals the expected path byte for byte. The pinned folder still has the same dev and inode, and
   the checkout is on the same st_dev as the marker.
5. The checkout top, its `.git` and, for a worktree, its admin folder were all born between the two marks. That rules
   out a checkout or a `.git` moved in with `mv`, and an object dated in the future.
6. For a clone, `remote.origin.url` is the command's URL. For a worktree, it is linked and has the named repo's common
   dir.
7. The call's own output shows its git creating that path: `Cloning into 'DIR'...` naming the same folder for a clone,
   `Preparing worktree` for a worktree, and no git `already exists` error for that path. This is a fact only this call's
   git could have produced: if another process made a checkout at the path during the call, this call's git failed with
   `already exists` and there is no row (`git-failed-here`). Output that was hidden (`-q`, `--quiet`, `>/dev/null 2>&1`)
   gives no row either (`no-own-output`). `2>&1 | tail -3` and `>/dev/null` keep git's messages, which go to stderr.

The lock is `state/checkouts/registry.lock`. Waits stop after 2 s with `lock-timeout`, and a state folder that is not on
a local filesystem gets no rows.

## How an isolation row is proven

- The path is named after the payload's agent id.
- It is a linked worktree listed by the repo that contains it.
- The subagent transcript `~/.claude/projects/*/<session>/subagents/agent-<id>.jsonl` exists. A missing transcript is
  checked again on the next call; other failures are retried after a minute.
- The transcript was born 0 to 120 s after the worktree (the worktree comes first).

The row is written at SubagentStart, or at the agent's first tool call from inside the worktree.

## Retirement

A row is retired as `observed-absent` only when two lstat calls under the lock both give ENOENT for its exact path, and
the nearest existing folder is on the row's own st_dev, so an unmounted volume never retires a row. Retirement happens
when a later call proposes the same path, when SubagentStop finds the checkout gone, or through
`checkout_registry.py retire --path P`.

Retirement only ends ownership. A removed or retired row is never permission to delete anything.

## Why no row was written

Every refusal appends one reason code to `state/checkouts/decisions.jsonl` (rotated to `decisions.1.jsonl` at 4 MB).
The codes are:

| Stage | Codes |
|---|---|
| PreToolUse | `existed-at-pre`, `unreadable-at-pre`, `repo-unknown`, `contested`, `lock-timeout`, `no-mark`, `unsure` |
| PostToolUse | `pending-missing`, `pending-bad-mac`, `pending-foreign`, `pending-expired`, `transcript-unbound`, `no-mark`, `git-failed-here`, `no-own-output`, `not-made`, `link`, `not-a-checkout`, `outside-home`, `realpath-moved`, `anchor-changed`, `other-fs`, `not-linked`, `repo-mismatch`, `no-btime`, `born-outside-call`, `origin-mismatch`, `state-not-local`, `no-key`, `no-generation`, `lock-timeout`, `ledger-too-large`, `second-owner`, `already-held`, `contested-identity` |
| Other | `background`, `permission-denied`, `observed-absent`, `hook-error` |
| Isolation | `iso-not-checkout`, `iso-not-listed`, `iso-no-transcript`, `iso-window` |

A successful write is recorded as `written`.

```
python3 ~/.claude/hooks/checkout_registry.py list                 # verified rows, failures, how many are held
python3 ~/.claude/hooks/checkout_registry.py stat --path ~/x      # read-only facts about one path
python3 ~/.claude/hooks/checkout_registry.py retire --path ~/x    # end ownership of a checkout that is gone
tail -n 20 ~/.agent-harness/state/checkouts/decisions.jsonl       # why recent calls did or did not get a row
```

No command writes a created row by hand. The `hook` verbs read a hook payload, and a made-up payload fails the
transcript binding.

## When an agent stops

SubagentStop writes `~/.agent-harness/work/<session>/inbox/data-checkout-<agent>.md` for the parent session. owner_inbox
injects it under a header that says it is data, not instructions. Data notes never block Stop or crowd out a decision
note. For each checkout the agent still holds, the note lists:

- the changed, untracked and ignored counts;
- the branch and HEAD;
- commits on no remote ref;
- the repo's stash count;
- any checkouts nested under its path.

It also gives a verdict. One function, `may_remove(evidence)`, produces it, and the default is keep. "owner may remove"
is given only when every item of `REMOVE_EVIDENCE` was observed as true; an item that is false, unknown or missing keeps
the checkout and is named in "keep: reasons". The items:

- the opt-in is on;
- it is the agent's own isolation worktree (a clone or a Bash worktree is never a removal candidate);
- the repo configures no program;
- no index entry is skip-worktree or assume-unchanged (`ls-files -v`), since `diff-files` does not see edits to those;
- nothing is changed, staged or untracked;
- its ignored content is all regenerable: `node_modules` beside a `package.json`, a virtualenv (a folder with
  `pyvenv.cfg`), `__pycache__` and `*.pyc`;
- nothing is unpushed or stashed;
- nothing is nested, and the nested scan finished;
- the verdict finished within its time budget.

Ignored files such as `.env.local`, data or build output may be someone's only copy, so they always mean keep.

The hook removes nothing, and a resumed agent keeps its worktree.

## How the hooks run git

No hook runs `git status`, `git log`, `git diff`, `git show` or `git stash list`, because those can start a program that
the repo's config names (filter drivers, textconv, gpg.program). `_git` refuses them.

The verdict uses plumbing that reads no file content through filters: `diff-files`, `diff-index --cached`, `ls-files`
and `rev-list`. Every call is hardened:

- no fsmonitor, no hooks and no optional locks;
- `log.showSignature=false` and `protocol.allow=never`;
- `GIT_NO_LAZY_FETCH=1`, no `GIT_*` from the caller, and `GIT_CONFIG_NOSYSTEM=1`;
- bounded by the hook's whole deadline (8 s, 15 s for SubagentStart, 18 s for SubagentStop).

If the repo's own config, or a file it includes, sets `filter.*`, `diff.*.textconv`, `diff.external`, `core.fsmonitor`,
`core.hooksPath` or `gpg.*program`, the verdict is "keep: repo config runs programs" and no content-reading command runs.
The user's global config is trusted.

## Live check

`bash tests/live/checkout_registry_live.sh RECEIPT_DIR` runs three short `claude -p` sessions (main, subagent,
isolation) with these hooks added through `--settings`, in a `mktemp -d ~/streamd-live.XXXXXX` folder it removes
afterwards; it then retires the rows it made and checks that none is held. Exit 0 PASS, 1 FAIL, 2 BLOCKED (a session
did not run, or the user's own guards refused a clone before it ran). It writes `live-receipt.json` and redacted
payloads to RECEIPT_DIR. `tests/fixtures/checkout_registry_live_payloads.json` is a trimmed copy of those payloads,
and `LivePayloads` in the unit tests replays it.

What the live run showed (Claude Code 2.1.330, 2026-11-24):

- A subagent's Bash PreToolUse and PostToolUse payloads carry `agent_id`, but `transcript_path` names the session's
  main transcript; the agent's calls are in `projects/P/SESSION/subagents/agent-ID.jsonl`, which SubagentStop names
  as `agent_transcript_path`. The binding follows that path.
- An isolation subagent's SubagentStart `cwd` is the worktree itself.
- A Bash call that another PreToolUse hook refuses gets neither PostToolUse nor PostToolUseFailure, so it gets no row.
- In that run, a `cd` to the parent folder in one Bash call did not carry into the next call's `cwd` or `pwd`.
- Not yet observed live: a Bash clone that completes. The Mac run's clones were refused by copy_hygiene's free-disk
  floor (18.1 GB free, floor 20 GB), and the t2-dev run could not start because the account's weekly limit was reached.

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
  - The writer is an importable module, so until command_guard refuses imports of it and writes under `state/checkouts/`,
    such a process could append a signed row.
  - macOS lets an owner set a birth time, so a hostile agent could forward-date a moved-in checkout.
- **Same-URL race.** An unhooked creator that clones the same URL into the same path during the call is attributed to
  the call.
- **Forgery protection.** command_guard's `state_files` list should protect `state/checkouts/` against direct writes.
  That is stream B's file, and the rule was handed over.
