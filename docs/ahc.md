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
