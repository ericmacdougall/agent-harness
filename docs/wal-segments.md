# WAL segments (50 MiB rotation)

Ticket: GoodQA #16751. Contract and review history: `docs/spec/wal-segments.md` (rev 3). Code: `harness/hooks/wal_segments.py`.

## What it is

A session WAL (`main.jsonl`, `agent-<id>.jsonl`, a task-named WAL; Claude root `~/.claude/wals/<session>/` and Codex root
`~/.agent-harness/codex-wals/<session>/`) rotates natively once the live file would pass 50 MiB:

```
main.0001.jsonl   oldest closed segment (never modified after the rename)
main.0002.jsonl
main.jsonl        the live file: always the newest segment; line 1 is its open marker
main.segments.json   derived index (advisory, rebuildable)
.main.seglock        lock file (never removed)
```

Rotation only renames (exclusively: never over an existing name) and creates. It never truncates, rewrites or deletes a
WAL. The only truncation is the pre-existing removal of an unterminated torn tail line of the live file.

## Names and reserved stems

- Live: `<stem>.jsonl`. Closed: `<stem>.NNNN.jsonl`, zero-padded to at least 4 digits, contiguous from 0001.
- `<x>.<4+ digits>` stems are reserved. `safe_id` escapes such ids (`z-...`) so a hostile or odd agent id can never
  look like a segment. Listers must use `wal_segments.list_wals`, which folds segments into their stem, so a segment is
  never shown as an agent or task.

## Linking: the open marker

The first line of every file created by a rotation (and so of every closed segment from 0002 on) is:

```json
{"at":"...","event":"wal_segment_open","by":"wal_segments","schema":1,"stem":"main","segment":3,
 "prev":"main.0002.jsonl","prev_bytes":52428800,"prev_lines":91234,"prev_sha256":"...","limit":52428800}
```

A marker is recognised only as line 1 of a segment with seq >= 2 or of the live file, with this exact schema and the
`by` field. Readers skip it by default, so line counts, `last_at` and activity are unaffected. The forward link is
derived (segment k is followed by k+1; the last closed segment by the live file) and is stored in the index.

## The rotation protocol (writers)

Every append takes, in this order: the seglock (`.stem.seglock`, flock with a 2 s deadline), the live file (O_CREAT only
under the seglock), the data flock, the target check. When `size + record > limit` (and the file is more than a marker
long), under all locks: repair a torn tail, hash the live file, exclusive-rename it to the next segment, fsync the
directory, create the new live file (O_EXCL), write the marker, rewrite the index, then append the record. Recovery rule:
a live file that is missing or empty next to closed segments is finished with a fresh marker by the next append, with the
enable file off too.

Stderr codes (hooks show nothing; the ops_watch alert on an oversize live file and on a persistent `live_missing` is part of the reader-migration PR, PENDING): `rotate_collision` (the target
name exists; rotation skipped), `rotate_unsupported` (no exclusive rename on this platform or filesystem),
`seq_implausible`, `seglock_timeout`, `seglock_unusable`, `rotate_create_failed` (rotation undone, record kept),
`rotate_failed_record_not_written` (rename could not be undone: the record is NOT written into a closed segment; the next
append repairs).

## Switch and rollout

Rotation is on only when `~/.agent-harness/state/wal-rotation.on` exists. Order: ship `wal_segments.py` and the readers,
restart daemons (ops_watch, Mission Control, ahd) and check the Codex install, then create the file. Rollback: delete the
file; readers keep reading chains and `wal_segments.py cat` yields the logical file. Rolling the code back below the
reader version is unsupported once segments exist. `HARNESS_WAL_SEGMENT_BYTES` and the fault-injection variables are
honoured only when `HARNESS_TEST=1` and HOME is under a temp root.

## Reading (one API)

```python
import wal_segments as ws
for segment, line_no, raw in ws.iter_lines(live_path, problems=problems): ...   # logical line numbers, markers skipped
tail = ws.read_tail(live_path, 4 << 20, problems=problems)                       # last bytes across segments
ws.exists(live_path)       # live or any closed segment (a crashed rotation still counts)
ws.list_wals(directory)    # {stem: Chain}; segments folded into their stem
```

The reader opens the live fd first, lists the directory, and reconciles by inode, so a concurrent rotation gives a
consistent prefix: no duplicate and no lost pre-snapshot line. Problem codes: `gap` (reported as a `[lo, hi]` range),
`not_regular` (symlink, FIFO or directory in a segment's place; never followed), `ambiguous`, `marker_mismatch`,
`marker_missing`, `truncated` (a read budget was reached), `unreadable`, `live_missing` (info), `schema_newer` (info).
`strict=True` raises `SegmentProblem` instead of reading past a problem. No reader may treat a chain with a problem as
complete.

## Finding, checking and recovering (local or a git backup copy)

```
python3 wal_segments.py map DIR                 # JSON: every logical WAL, segments, bytes, first/last time, problems
python3 wal_segments.py verify DIR [STEM] [--deep]   # exit 1 on any problem; --deep rehashes against the markers
python3 wal_segments.py cat DIR STEM [--allow-gaps]  # the whole logical WAL in order, markers dropped
python3 wal_segments.py reindex DIR STEM [--write]   # rebuild STEM.segments.json (dry run unless --write)
```

All four work on a copy of a WAL folder (a git backup checkout) using only the file names; they refuse a symlinked
directory argument and a stem with a path or a segment shape, and open only names found by scanning the directory, never
a name taken from a marker or the index. The index is advisory: the directory is authoritative.

## Transcripts

Claude Code and Codex transcript files are read-only sources owned by those tools and are not rotated by us. ASSUMPTION
(accepted by main, not the user's words): "transcripts rotate at 50 MiB" is met by the archive's chunking
(`docs/transcripts-archive.md`); carrying the segment links into the archive index (`wal_segment` fields) and adopting a rotated segment's archived chunks is PENDING (spec R2-15; blocked until PR #316's transcripts.py repairs land).

## Status of this document

Implemented in this PR: the module, the three writers, the CLI, the installer lists. PENDING (named in the spec, owned by the reader-migration streams): migration of every reader to the API, the reader inventory guard, the ops_watch alerts, and the transcripts adoption.
