# ahc coordinator daemon

GoodQA goodqa#16034. Gate 1 is receipt-only: `ahc` lints the queued packet, runs one exact-head
`peer_review.py pr` receipt, and writes the result back to the ticket, the owner inbox and the digest. It never
merges. Code: `harness/hooks/ahc_core.py`, `ahc_fs.py`, `ahc_packet.py`, `ahc_clone.py`, `ahc_runner.py`.

## State root

The coordinator root is `~/.agent-harness/ahc` (`ahc_core.Paths.root`). It was `~/.agent-harness/coordinator`
until goodqa#16049 slice 1. That directory belongs to another program, coordd, which keeps its own ledger, clones
and token there. No ahc install existed when the root moved.

ahc owns its root only by the marker file `.ahc-root`. The marker is written to a temp file, fsynced, then
hard-linked into place, so it is never torn. On every start, before reading anything, ahc claims the root:
- If the root is absent or empty, ahc creates the marker.
- It refuses, naming the conflict and changing nothing, when:
  - the root has no marker and is not empty;
  - a marked root holds a top-level entry ahc does not write (`ROOT_NAMES` and `ROOT_PATTERNS` in `ahc_core`);
  - the root or the marker is a symlink;
  - the root, existing or new, or any ahc directory below it is not a real directory owned by this uid at mode
    exactly 0700, or a file at an ahc name is owned by another uid (PR 258 v3 F2);
  - an ancestor of the root is owned by a uid other than this one or root, or is group- or other-writable without
    the sticky bit (`ahc_fs.ancestor_problems`). ahc never chmods an ancestor or an existing root; it refuses.
- Every subcommand turns a refusal into exit 3, which is in the units' `RestartPreventExitStatus`, so a foreign
  root stops the unit instead of looping.

A name alone proves nothing (PR 258 v1 BLOCK). The checks run in two tiers:
- Top level: every entry is checked with lstat for the type ahc gives it. A symlink, or a file where ahc keeps a
  directory, refuses the start.
- `items/` and `clones/` (`STRICT_TREES`): only ahc writes these. They are walked without following links, and a
  link or special file anywhere in them refuses the start. Under `clones/`, only each clone directory and its `.git`
  must be real, because a clone's work tree may hold symlinks committed in the repository.
- `queue/`, `inbox/`, `staging/`, `reports/` and `rejected/` (`SHARED_DIRS`): other processes write into these by
  design. A link inside them never stops ahc, since anyone who can submit could then halt it. Instead, every open
  of an entry there uses `O_NOFOLLOW` and requires a regular file.

The ledger, its pre-migration backups and the reopen after a restore all go through
`ahc_runner.connect_nofollow`:
- the sidecars must not be links;
- the file is opened or created by an `O_NOFOLLOW` descriptor and gets its mode by `fchmod`;
- the path's device and inode are compared with that descriptor right after sqlite opens it, before any statement
  runs.

### One writer under the root (PR 258 v3 F1)

Every write under the root goes through `harness/hooks/ahc_fs.py`:
- the root is opened `O_DIRECTORY|O_NOFOLLOW`, and each directory below it is opened relative to its parent's
  descriptor and must be owned by this uid at 0700;
- a file is written to a temp name that cannot be predicted (`.<name>.<16 hex>.tmp`), created
  `O_CREAT|O_EXCL|O_NOFOLLOW`, written, `fchmod`ed and fsynced by descriptor, then renamed or hard-linked into
  place by directory descriptor, and the directory is fsynced;
- appends, opens, renames, unlinks, `make_dirs` and `make_fresh_dir` use the same descriptor walk.

`tests/test_ahc_fs.py` parses every ahc module and fails on any path-based write (`open` for writing,
`write_text`, `chmod`, `os.replace`, `os.link`, `mkdir` and similar) outside `ahc_fs`. Its allowlist names each
remaining site and why it is outside the root or pre-checked, and the test fails if an allowlisted site
disappears. A new writer must use `ahc_fs`, or justify an allowlist entry in review.

### Daemon clones (D4)

The clone in `clones/<repo>` is reused across reviews (D4 kept on PR 258 v3). Before every use, `ahc_clone`
walks its `.git` without following links, bounded at 200,000 entries and depth 12 (past either bound it fails
closed), against an allowlist: `HEAD`, `config`, `packed-refs`, `index`, `FETCH_HEAD`, `ORIG_HEAD`, and `objects/`
and `refs/` with their usual names. A link, special file, foreign owner, writable directory or any other name
(hooks, `info/`, `worktrees/`, `modules/`, `logs/`, alternates, `shallow`, `config.ahc-tmp`) moves the clone to
`rejected/clone-<name>.<ns>.<pid>` with a `.reason` file. It is never repaired in place, and a fresh clone is made
into a new directory that ahc creates exclusively. The local config is rewritten from scratch each time. git runs
with `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_GLOBAL=/dev/null`, `core.hooksPath=/dev/null`, `core.fsmonitor=false`,
https only (`protocol.allow=never`, `protocol.https.allow=always`), `--template=` and umask 077. The local file
transport is off by default. The config key `clone_file_transport: true` turns it on for local test remotes, and
it is refused, before git runs, for the production root under the real home directory.

### Review report directory

peer_review refuses an existing report path and writes the report itself (an `O_EXCL` temp plus a link through
its own directory descriptor), so ahc cannot pre-create the file. Instead it creates a fresh private directory
`reports/<item>-a<attempt>/` per attempt with `ahc_fs.make_fresh_dir` and records its device and inode. The child
writes `report.md` there. After the child exits, ahc opens that directory, compares its device and inode with the
recorded ones, and reads `report.md` through the directory descriptor with `O_NOFOLLOW`. It must be:
- the directory's only entry (peer_review unlinks its own temp file before it exits);
- a regular file owned by this uid;
- a file with exactly one link;
- within `REPORT_MAX_BYTES`.

Anything else concludes as INVALID, never PASS. The attempt directory is then moved, as a name, to
`rejected/report-<item>-a<attempt>` with a `.reason` file, and the next attempt gets a fresh directory. A crash
right after the directory is made leaves it empty, and the retry reuses it only if it is still empty, 0700, owned
by this uid and not a link.

### What remains (L10)

Every check above defends against other users. A process running as this same uid can still write inside the
0700 root. For example, it could:
- swap the ledger path to a link and back between sqlite's open and the inode comparison, because Python's sqlite3
  cannot pass `SQLITE_OPEN_NOFOLLOW`;
- plant into a clone while git runs;
- replace a report between the child's exit and ahc's read.

The defense is that no other uid can reach the root: `claim_root` enforces the 0700, uid-owned chain at every
start.

A change that adds a top-level file under the root must add its name to `ROOT_NAMES` in the same commit.

## Ledger and migrations

State lives in one SQLite database, `<coordinator root>/ledger.sqlite3`, in WAL mode. `meta.schema_version`
records the schema; a ledger newer than the code refuses to start (`SchemaError`).

Version 2 adds the D20 timing columns on `items`:

| Column | Meaning |
|---|---|
| `entered_at` | When the item entered its current state. A same-state settle (an hourly recheck) keeps it. |
| `esc_n` | The escalation number `<n>` in the critical alert key `ahc:<item>:<n>`. It is bumped once per escalation, in the same transaction as the escalation's notice, and never by a delivery retry. It survives restart and migration. |
| `esc_at` | When the last D20 escalation was raised. |
| `disposed_at` | When a disposition stopped D20 escalation. |

A migration runs only after a proven backup:

0. A ledger larger than `RESTORE_MAX_BYTES` (2 GiB, counting its `-wal` file) is never migrated: ahc refuses
   with a `SchemaError` before anything is copied or changed.
1. The SQLite online backup API copies the database to `ledger.sqlite3.pre-v<N>.<ns>.bak`. The copy includes
   committed rows that are still only in the `-wal` file.
2. The copy must pass `PRAGMA integrity_check` and have the same row count as the source in every table.
   Otherwise the migration does not start.
3. All steps run in one transaction.
4. If any step fails, the daemon restores the backup (PR 258 v4 F1). The steps, in order:
   - A durable restore intent is written first.
   - The backup is streamed through a directory descriptor, in 1 MiB chunks (`ahc_fs.copy_to_temp`), into a
     new temp file beside the ledger, and fsynced. Memory use does not grow with the ledger under the unit's
     `MemoryMax`.
   - Only after the copy succeeds are the live `.db`, `-wal` and `-shm` files moved aside together as
     `ledger.sqlite3.failed-<ns>[-wal|-shm]`. They are never deleted.
   - The copy is renamed into place and the intent is dropped.
   - The daemon then refuses to start with a `SchemaError` that names both files.

   If the copy fails while the live database is still in place, nothing has been moved. The intent is dropped,
   so the next start opens that unchanged database instead of repeating the restore. A restart after a crash
   removes any partial temp copy and completes the same restore.

## Admission and staged packets

`ahc submit` is the only way work enters the ledger. Each submit runs in one `BEGIN IMMEDIATE` transaction that
does three things in order:

1. A duplicate item id returns the existing item.
2. The submit is refused when 50 items are non-terminal, when the repo already had 6 submissions in the last
   hour, or when 3 packet revisions on this head already reached `reviewing` ("review budget exhausted for this
   head: push a new head or ask main").
3. Otherwise the item is inserted.

## Retry budget

The budget is counted per (lineage, head), where the lineage is (repo, PR). Every packet revision on the same head
shares it; only a new head starts a fresh one. Per head:

- at most 3 revisions reach `reviewing`;
- one provider-transient retry. A second transient goes to `needs-attention`;
- one declared invalid-output repeat. A second invalid output goes to `review-invalid`;
- one ticket-freshness re-run (D24). A second STALE goes to `needs-attention`.

Each class is first-come and used at most once. Quota, auth and pool contention consume nothing. An auth block
opens the provider circuit and defers the item. The item re-checks the circuit every 30 min and never launches
while the circuit is open.

A crash during a side effect (ticket comment, alert, inbox write, note) marks only that effect row
`outcome-unknown`. The item keeps its state. The effect is read back before it is sent again: a ticket, alert
or clear is re-sent under the same idempotency key.

The head's 24 h deferred deadline starts at its first deferral. Later deferrals never restart it, so a flapping
quota ends in `review-error` 24 h after the first one.

The budget lives in `lineage.attempts["heads"][head]` and survives restarts and resubmits.

### Ticket-freshness STALE (D24)

peer_review refuses a PR review before any provider launch when commit_policy reports a referenced ticket as
STALE (rc 2, "PR review not started"). When that refusal is the only problem, the daemon:

1. posts one note per (ticket, head) on the STALE tickets. The note is labelled `coordinator bookkeeping (ahc)`
   and lists only the PR URL, the head, and each commit's SHA and subject from the daemon clone;
2. defers the item until every note is posted. The re-run never starts before that, so a ticket outage holds the
   re-run instead of wasting it;
3. re-runs the receipt once.

A second STALE on the same head goes to `needs-attention`.

A file placed in the queue directory admits nothing. It is quarantined unread and raises an alert.

`ahc submit --packet -` reads the packet from stdin and checks it against `--expect-sha` when that flag is given.
It then writes the packet once to `<coordinator root>/staging/<sha256>.md` (mode 0600, in a 0700 directory).

The core pass removes a staged packet 7 days after the last item that names it turned terminal. It never
removes a packet while any item that names it is non-terminal. A staged file that no item names (its submit was
refused) is removed 7 days after its mtime. Only regular `<sha256>.md` files in that directory are touched. The
ledger and the receipt keep the SHA-256 after the file is gone.

## Digest readback

The digest (`<coordinator root>/digest.md`) is a courtesy copy for main. Before re-appending an entry left at `intent`,
the runner checks whether its key is already present, but it reads only the last `DIGEST_TAIL_BYTES` (1 MB) of
the file. Reading only the tail bounds the cost and never blocks on a hostile file. The tradeoff: a key older than
the last 1 MB reads as missing and the entry is appended again. That duplicate is accepted, because delivery is
at-least-once and the digest is never the only channel. (Accepted by the spec owner, 2026-11-14.)

## Escalation past main (D20)

`STATE_TABLE` in `ahc_runner.py` is the only place an item state is declared. Each state that waits on a person has
one of two covers:

- **`ack`** (refused, lint-failed, review-error, stale-head): the owner notice needs
  `ahc_runner.py ack ITEM --owner OWNER`. If the deadline (`block_ack_seconds`, 4 h) passes without one, the notice
  escalates once.
- **`d20`** (routed-to-main, needs-attention, block-delivered, acknowledged, blocked, unsubmitted, outcome-unknown,
  cancel-requested): the item escalates 4 h after entering the state, then every 24 h. This runs from the ledger
  alone, so a GitHub outage cannot suppress it.

### A BLOCK verdict

1. The verdict puts the item in `block-delivered`. The owner notice needs an ack.
2. `ahc ack ITEM --owner OWNER` moves it to `acknowledged`. The ack only confirms receipt; it closes nothing.
3. The repair deadline runs from the ack: a D20 escalation 4 h after it, then every 24 h. An escalation raised
   before the ack does not push the first repair escalation out to 24 h, and `<n>` keeps counting up.
4. A second ack is a no-op and never resets the deadline. A restart never moves it.
5. The item leaves `acknowledged` only when:
   - the PR is submitted at a new head. The item closes as `superseded` with reason `superseded-by-head`, linked
     to the new item. A new packet on the same head is not a repair;
   - the PR moves to a new head and nothing is submitted for it. The daemon reads the PR's live head at most every
     10 minutes per item. When the head has moved and the PR is open, the item closes as `superseded`
     (`superseded-by-head`) linked to a new `unsubmitted` item for the new head. That item has its own owner
     notice and its own D20 clock, so the obligation never disappears. A submission at that head supersedes it
     with reason `resubmitted`. An unreadable PR changes nothing;
   - the PR merges or closes;
   - main records a disposition.

`blocked` is a different state: a guard or policy refusal, routed to the decision-maker. In P0 the guard is the
repo allowlist: a repo removed from `repos` after admission blocks its items. From `queued` or `deferred` the item
blocks before any review starts. A refusal noticed while the item is reviewing applies once the child settles: the
child is never killed, its result stays recorded on the effect row, and the item becomes `blocked` instead of
routing a verdict.

Every escalation does three things:

- posts a ticket comment;
- adds a digest line;
- raises a critical alert `ahc:<item>:<n>`. `<n>` is `items.esc_n`.

If the no-ack deadline passes while the item is under live D20, that escalation counts as the D20 one, so the two
clocks never raise two criticals for the same wait.

### What stops escalation

- **A disposition** (required reason text):
  `ahc_runner.py ack ITEM --owner OWNER --disposition "<reason>"`.
  - Every D20 state: main only. An owner can ack and repair, never dispose. Closing a BLOCK without a repair is
    main's call.
  - `--owner main` counts only when main's own `mission_gate.py pretool` hook stamped that exact command line.
    The stamp is a caller_identity stamp, bound to main's still-running tool call. A sub-agent is refused.
  - The stamp is local to the host. A main session on another host cannot dispose for main over SSH; its
    obligation keeps escalating until the PR merges or closes.
- **A newer submission for the same PR at a new head.** This also skips a pending no-ack escalation. A packet-only
  resubmit on the same head stops nothing.
- **The PR reads as merged or closed.** This also skips a pending no-ack escalation. An unreadable PR never counts
  as either.

### When criticals are cleared

The item's `ahc:<item>:*` criticals are cleared when:

- it leaves the covered state;
- a disposition is recorded;
- a stop condition fires;
- an owner ack leaves no live D20 obligation. An owner ack on a routed-to-main item clears nothing.

## Email route (D19)

The daemon never sends mail and holds no mail credentials. ops-watch mails only critical raises, through its
`sinks.deadman` command.

### Readiness

At the start of every tick the daemon asks ops-watch:

- `ops_watch.py capabilities` must list `forward-foreign-critical` and `deadman-delivered`;
- `ops_watch.py config` must have a non-empty `sinks.deadman`. Only its emptiness is checked; that output holds the
  mail argv and is never logged.

The ops-watch path comes from config key `ops_watch` (default `~/.claude/hooks/ops_watch.py`).

If either check fails, the route is `email route: unavailable` (`ahc_runner.py status` shows it with the reason):

- One outage episode raises one high alert `ahc:email-route:<episode>` and posts one comment on the ticket in
  config key `ops_ticket`. With no `ops_ticket`, only the alert is raised and a log line says so.
- While unavailable, an escalation's ticket comment says it was NOT handed to the mail command.
- When the route is ready again, the episode alert is cleared.

### Receipt

Each escalation that can be mailed gets a `mail` effect.

- It is done only when `ops_watch.py delivered --key ahc:<item>:<n> --json` returns a time at or after the raise.
  The raise time is recorded before the `ah alert raise` call. Done is reported as "handed to mail command", never
  "emailed". Mailbox arrival is separate live evidence.
- A failed, timed-out, malformed or mismatched answer counts as not delivered.
- With no receipt 30 minutes after the raise, the escalation fires `email-undelivered` once: a ticket comment and a
  high alert `ahc:email-undelivered:<item>:<n>`.
- A failed send stays in ops-watch's `pending_deadman`, and each ops-watch run retries at most 3 sends, oldest
  first. So a mail can land late, and the daemon keeps re-reading the receipt after `email-undelivered` fires.
  When the receipt arrives, the alert is cleared and the ticket gets one note saying the mail was handed over
  late. Checks stop after 7 days.
- Delivery is at-least-once. An ops-watch crash after the send but before its state save re-sends the mail once.

## Review, Grant and Operation contracts (M-1, goodqa#16049)

`harness/hooks/ahc_contracts.py` holds the design v3 transition contracts for three entities. A transition that is
not listed there does not exist. Every transition checks the expected version, a new event id and an allowed actor,
and is recorded in `transitions` in the same transaction.

- **Review** rows (spec ahc-m1 R1-R13) have the kinds `adversarial`, `spec` and `red-team`. Each is bound to
  (kind, repo, pr, head, packet or spec core SHA-256, policy revision). `passed` and `findings` need a receipt bound
  to that exact subject, with a matching verdict. For an attempt kind (`adversarial`, `red-team`), the result must
  arrive with a kernel peer uid equal to the uid that core bound to the row at `running` (the unit it started).
  Anything else is `unverified-producer` and authorizes nothing. A `spec` row passes only from `required`, on its
  attach record. A new head supersedes every open row, and a running row goes through `cancelling` first so its
  unit is stopped. A receipt that arrives later for a superseded row authorizes nothing. There is no waiver path.
- **Grant** rows (spec ahc-m1-v2e G1-G9) are issued only by the `ahc-policy` principal, straight to `validated`,
  for one candidate merge commit M: scope (repo, pr, H, B, M), one use, a 24 h expiry, the authority epoch and the
  kill epoch read at issue. A partial unique index allows at most one non-terminal grant per (kind, repo, pr, M).
  Issuing reserves a CAP1 slot (10 per repo per UTC day); retiring (G5) and expiry (G7) release it, consumption and
  revocation keep it, so the count never goes down. Every move is written first to an append-only, fsynced
  authority log, **local, not off-host** (a stated deviation from 3.9); if the write fails, nothing changes. A grant
  is reserved only for an intent with exactly its scope and policy revision, under the current epochs, and only
  after the mirror comment was read back. It is consumed when its operation is confirmed, or abandoned after a send
  whose outcome stayed unknown, and retired when the operation was abandoned with nothing sent or every send proven
  absent. Main revokes it (G8; the caller verifies main's stamp); the kill switch revokes it as `ahc-core` (G9). A
  grant reserved past its expiry has no transition until its operation settles.
- **Operation** rows (E1-E12) are merge-commit only, keyed by (repo, pr, M, policy revision, g). The generation g
  rises only after the previous operation for the same M was abandoned with every send proven absent; an
  operation with a send not proven absent never yields a new g. Dispatch re-reads every guard on an observation
  under 2 min old (tip at B, candidate ref at M, M's parents (B, H), PR open and not a draft at H, checks green,
  kill switch off at the grant's kill epoch), the lease and the mirror, and counts before the request leaves; at
  most 3 are allowed (B10). Confirmation is by ancestry: M reachable from the tip (identical or ahead) with parents
  (B, H), so a later advance does not hide a success. If the PR is not shown merged 10 min after the dispatch it is
  still confirmed and flagged (E12). Absence needs one of three proofs: p1 a typed server refusal, p2 an error to a
  completed request plus a fresh readback showing the tip left B and M unreachable, p3 a failure before any request
  byte was written. An error while the tip is still B is never absence: the operation stays unknown with its grant
  reserved. After a proof, a revoked grant or the third dispatch gives `held` (E11); p1 or p2, or a tip that left B,
  gives `abandoned` (E8); only p3 with the tip still at B retries the same key (E7). Twenty inconclusive readbacks
  give `held`; main settles a held row with evidence, and the reconcile confirms it when M is reachable or
  abandons it after the 24 h late-request horizon with M unreachable and the tip off B. For 30 days after an
  operation is abandoned, a readback that finds its M reachable raises an incident and turns the repo's merging
  off (`repo_flags`) until main turns it back on (late-apply watch, L5). A settled row becomes a tombstone 30 days
  after settlement, and its key is refused for good.

The runner does not use these rows yet, and automatic merging is off.

**Ledger schema v4.** The ledger carries these tables, plus `items.cause` (why an item is in its state: a
dependency or budget name). A same-state settle keeps the cause, and a state change without one clears it. A fresh
ledger and a v2 ledger migrated to v4 have the same tables and columns. A v3 ledger (either committed v3 layout)
keeps its grant and operation rows untouched in `grants_v3_legacy` and `operations_v3_legacy`; every unsettled
legacy row is reported by `Contracts.legacy_unsettled()` for main to reconcile. Migrations are forward-only: older
ahc code refuses a newer ledger, and rollback means restoring the `ledger.sqlite3.pre-v4.*.bak` copy made before
the step, which the previous release (21357968) reads.

**The daemon's review is bound and unstamped.** It runs `peer_review.py pr ... --github-repo OWNER/NAME --pr N
--no-main-stamp`, so the FINAL carries the PR binding that `merge_gate.pr_pass_evidence` checks. It never takes or
burns main's `review-auth` stamp, and it never passes `--author-harness`, because peer_review derives that from the
commit trailers. An argv without `--no-main-stamp`, or one that asserts an author or an approval, is refused before
launch. The configured `peer_review.py` must therefore support `--no-main-stamp`, which it does from commit e50c3619.
