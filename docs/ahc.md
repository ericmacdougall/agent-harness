# ahc coordinator daemon

GoodQA goodqa#16034. Gate 1 is receipt-only: `ahc` lints the queued packet, runs one exact-head
`peer_review.py pr` receipt, and writes the result back to the ticket, the owner inbox and the digest. It never
merges. Code: `harness/hooks/ahc_core.py`, `ahc_packet.py`, `ahc_clone.py`, `ahc_runner.py`.

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

1. The SQLite online backup API copies the database to `ledger.sqlite3.pre-v<N>.<ns>.bak`. The copy includes
   committed rows that are still only in the `-wal` file.
2. The copy must pass `PRAGMA integrity_check` and have the same row count as the source in every table.
   Otherwise the migration does not start.
3. All steps run in one transaction.
4. If any step fails, the daemon restores the backup. The live `.db`, `-wal` and `-shm` files are moved aside
   together as `ledger.sqlite3.failed-<ns>[-wal|-shm]`; they are never deleted. The daemon then refuses to start
   with a `SchemaError` that names both files.

## Digest readback

The digest (`<coordinator root>/digest.md`) is a courtesy copy for main. Before re-appending an entry left at `intent`,
the runner checks whether its key is already present, but it reads only the last `DIGEST_TAIL_BYTES` (1 MB) of
the file. Reading only the tail bounds the cost and never blocks on a hostile file. The tradeoff: a key older than
the last 1 MB reads as missing and the entry is appended again. That duplicate is accepted, because delivery is
at-least-once and the digest is never the only channel. (Accepted by the spec owner, 2026-11-14.)

## Escalation past main (D20)

`STATE_TABLE` in `ahc_runner.py` is the only place an item state is declared. Each state that waits on a person has
one of two covers:

- **`ack`** (refused, lint-failed, review-error, stale-head, blocked): the owner notice needs
  `ahc_runner.py ack ITEM --owner OWNER`. If the deadline (`block_ack_seconds`, 4 h) passes without one, the notice
  escalates once.
- **`d20`** (routed-to-main, needs-attention): the item escalates 4 h after entering the state, then every 24 h.
  This runs from the ledger alone, so a GitHub outage cannot suppress it.

Every escalation does three things:

- posts a ticket comment;
- adds a digest line;
- raises a critical alert `ahc:<item>:<n>`. `<n>` is `items.esc_n`.

If the no-ack deadline passes while the item is under live D20, that escalation counts as the D20 one, so the two
clocks never raise two criticals for the same wait.

### What stops escalation

- **A disposition** (required reason text):
  `ahc_runner.py ack ITEM --owner OWNER --disposition "<reason>"`.
  - needs-attention: the item's owner or main may record it.
  - routed-to-main: main only.
  - `--owner main` counts only when main's own `mission_gate.py pretool` hook stamped that exact command line.
    The stamp is a caller_identity stamp, bound to main's still-running tool call. A sub-agent is refused.
  - The stamp is local to the host. A main session on another host cannot dispose for main over SSH; its
    obligation keeps escalating until the PR merges or closes.
- **A newer submission** for the same PR. This also skips a pending no-ack escalation.
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
- That alert is cleared if the receipt arrives later. Checks stop after 7 days.
- Delivery is at-least-once. An ops-watch crash after the send but before its state save re-sends the mail once.
