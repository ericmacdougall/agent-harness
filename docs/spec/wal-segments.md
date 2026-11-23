# Spec: WAL and transcript 50 MB segment rotation (transcripts phase 2)

Ticket: GoodQA (main files it; stream owner: wal-rotation-owner)
Author: wal-rotation-owner (Claude Opus 5.5)
Click-test: required (a runnable instance: the real hooks run against a throwaway HOME on t2-dev)
Sign-off: main
Review-policy: data contract (two independent spec reviews, different models)

Source of every requirement below: the stream brief `wal-rotation-owner/brief.md`, which carries main's citation
`user:8d9ac187-f758-4aac-b3ea-8e54ebf74057 "change the harness so wals and transcript are auto link-chunked/rotate at 50mb but are clearly linked to each other so agents can read them... make a proper mapping system so its easy to find/recover/index/use them from git backups and local"`.
Details marked `inferred:` are design choices of the owner, labelled as assumptions.

## Outcome

A live WAL (`main.jsonl`, `agent-<id>.jsonl`, task-named WALs; Claude and Codex roots) rotates natively at 50 MiB
into linked segments `<stem>.0001.jsonl`, `<stem>.0002.jsonl` ... plus the live `<stem>.jsonl`, with prev links and a
derived segment index. One segment-aware reader API (`harness/hooks/wal_segments.py`) is used by every WAL reader, so
no reader silently sees only the live tail. The transcripts archive links source segments, and a `map`/`verify`/`cat`
CLI finds and reads a WAL chain locally or in a copy (a git backup checkout) with nothing but the file names.

## Design (the contract)

- **Names.** For a WAL stem `S` the live file is `S.jsonl` and is always the newest segment. A closed segment is
  `S.NNNN.jsonl` (NNNN: decimal, zero-padded to at least 4 digits, starting at 0001, contiguous). Names of the form
  `<x>.<digits>.jsonl` are RESERVED for segments; no writer may create a WAL with such a stem, no lister may treat one
  as an agent or task WAL. Live sequence number = (highest closed seq) + 1.
- **Limit.** `SEGMENT_BYTES = 50 * 1024 * 1024`. `HARNESS_WAL_SEGMENT_BYTES` may only LOWER it (floor 4096; used by
  tests). A WAL that never reaches the limit is byte-identical to today's: no markers, no sidecars except the lock.
- **Rotate.** Under the sidecar lock `.<stem>.seglock` (a regular 0600 file, O_NOFOLLOW, never removed) and the data-fd
  flock, when the live file is longer than 1024 bytes and `size + len(record) > limit`: (1) crash-tail repair as
  today; (2) hash the live file (sha256, bytes, lines); (3) `rename(S.jsonl, S.NNNN.jsonl)` (atomic, same directory,
  dir_fd); (4) create new `S.jsonl` with O_CREAT|O_EXCL|O_NOFOLLOW 0600; (5) write the open marker; (6) rewrite the
  index; (7) append the record to the new live file. Rotation only renames and creates; it never truncates, rewrites
  or deletes a WAL. The closed segment is not modified (no close marker): links live in the NEW file's open marker.
- **Open marker** (first line of every live file after a rotation):
  `{"at":ISO,"event":"wal_segment_open","schema":1,"stem":S,"segment":N,"prev":"S.NNNN.jsonl","prev_bytes":B,"prev_lines":L,"prev_sha256":H,"limit":LIMIT}`.
  A forward link is derived (segment k's next is k+1, the last closed segment's next is the live file) and stored in
  the index.
- **Index** `S.segments.json` (not `.jsonl`; derived, advisory, rebuildable): `{"schema":1,"stem":S,"updated":ISO,
  "segments":[{"seq","name","bytes","lines","sha256","first_at","last_at","prev","next"}...],"live":{"seq","name","bytes"}}`,
  written by tmp + fsync + rename. Readers never trust it over the directory; `verify` reports a stale index as a
  warning, `reindex` rewrites it from the directory.
- **Recovery rule.** Whenever a writer holds the lock and finds the live file missing, or empty while closed segments
  exist, it creates/finishes the live file with a freshly derived open marker. So every crash state converges.
- **Writers.** One implementation, `wal_segments.append_line(...)`, holds the open/validate/lock/crash-tail/rotate/
  write/fsync flow. `harness/hooks/wal.py`, `ah._wal_append` and `codex/hooks/wal.py` call it and keep their own
  directory-pinning and path validation. A stale writer that locked an inode that was renamed meanwhile re-opens the
  live name and retries (bounded 8 times) instead of failing.
- **Reader API** (`wal_segments`): `parse_name`, `chain(dir, stem)` -> segments + problems, `open_chain(path)`
  (snapshot: opens the live fd FIRST, then lists, then reconciles by inode, so a concurrent rotation yields neither
  a duplicate nor a lost pre-snapshot line), `iter_lines(path, ...)` (drop-in for `safe_input.iter_jsonl_lines`,
  yields `(segment_name, line_no, bytes|None)`), `read_tail(path, window)` (the last `window` bytes of the logical
  concatenation), `list_wals(dir)` (logical WALs, segments folded in), and `problems`. Problem codes: `gap`
  (missing middle or leading seq), `not_regular` (symlink, FIFO, directory in a segment's place; never followed),
  `ambiguous` (two names parse to one seq), `marker_mismatch` (an open marker's `prev` is not the predecessor),
  `live_missing` (info, crash window), `unreadable`. `strict=True` raises `SegmentProblem` instead of yielding past a
  problem; the default yields what is readable AND reports the problems, and every migrated reader surfaces them in
  its own unread/problem channel.
- **CLI** `wal_segments.py {map,verify,cat,reindex}` works on any directory (local or a backup checkout).

## Scope

- In: the writer, the reader API, migration of every WAL reader (wal_note, ah, provenance, ops_watch, goals/status
  helpers that open WALs, codex hooks) onto it, transcripts.py source-segment linking, the CLI, docs, contract and
  race/crash tests.
- Out: Claude Code's own transcript files (read-only sources; chunked only in the archive); log-backup files
  (`harness/bin/log-backup.sh`, `log_backup.py`; another owner); deleting, pruning or compressing local segments;
  changing the 4 MiB / 64 MiB reader budgets.

## Acceptance criteria

- AC-1: Appending a record that would take the live WAL past the limit renames the live file to the next
  `S.NNNN.jsonl`, starts a new live file whose first line is a valid open marker, and puts the record in the new live
  file; the concatenation of all segments in order equals the original bytes plus the records appended, with no record
  lost or duplicated. Verify by: `tests/test_wal_segments.py::RotationTests` (limit lowered by env; sha256 of the
  logical concatenation compared with the expected bytes) run on t2-dev via testrun. Source: brief "rotates natively at 50 MB into linked segments".
- AC-2: Each rotation writes `S.segments.json` atomically; it lists every segment with bytes, lines, sha256, first_at,
  last_at, prev and next; `reindex` rebuilds an identical index from the directory alone; a missing or stale index
  never changes what a reader returns. Verify by: `RotationTests.test_index_*`, `CliTests.test_reindex`. Source: brief "a segment index", "proper mapping system".
- AC-3: Two or more writer processes appending concurrently (many appends each, tiny limit, so many rotations) lose
  and duplicate nothing: every record appears exactly once across the chain, each writer's own order is preserved,
  segment numbers are contiguous, every open marker's `prev` is its predecessor. Verify by:
  `tests/test_wal_segments.py::ConcurrencyTests` (8 processes x 200 appends). Source: brief "no lost or duplicated lines under concurrent appends".
- AC-4: A crash injected at each rotation step (after hash, after rename, after live create, after marker, after
  index) leaves a state that the next append repairs without losing a record and without a gap; a reader at each
  crash state returns every record written before the crash exactly once. Verify by: `CrashTests` (the writer runs
  in a subprocess killed at an injected fault point via `HARNESS_WAL_FAULT=<step>`, test-only). Source: brief "a crash mid-rotation".
- AC-5: A reader running while writers rotate sees a consistent snapshot: no duplicated line, no line lost that
  existed when it started, lines in order. Verify by: `ReaderRaceTests` (reader loops against rotating writers; final
  re-read equals the full set). Source: brief "a reader during rotation".
- AC-6: A segment missing from the middle (or the start) is reported as a `gap` problem naming the missing seq; a
  symlink, FIFO or directory in a segment's place is never followed and is reported `not_regular` (and the chain is
  incomplete); `strict=True` raises; no reader returns an apparently complete chain over a gap. Verify by:
  `GapTests`, and the per-reader assertions in AC-8. Source: brief "reports the gap and never silently skips it".
- AC-7: A pre-existing unrotated WAL larger than the limit (80 MB) is renamed whole to `S.0001.jsonl` on the first
  append (bytes and sha256 unchanged, nothing rewritten), and the append lands in a fresh live file; the open marker's
  `prev_sha256` equals the pre-rotation sha256. Verify by: `LegacyTests.test_80mb_wal` (checks the segment sha256
  before and after; the test file is generated, no real data). Source: brief "a pre-existing unrotated 80 MB WAL".
- AC-8: Every WAL reader returns the same answer over a rotated fixture as over the same records in one file, and
  reports (not hides) a gap: wal_note (`ask_entry`, `open_ask_exists`, `sibling_ask_wal`), ah (`owners`, `status`,
  `user-msg` path, evidence/session entry scans, agent summaries with their offset caches), provenance (`wal_entry`,
  `ledger_read`, `session_wals_read`, `find`), ops_watch (wal_size, liveness, idle_guard, alert text), codex
  `hooks/wal.py` readers, goals_view/status_truth where they open a WAL. A guard test fails when a module that names
  a WAL file is neither migrated nor on a reviewed allowlist. Verify by: `tests/test_wal_readers_contract.py` (one
  parametrized registry over all readers, rotated fixture and gap fixture) plus the existing suites of each module. Source: brief "One segment-aware reader API is used by every WAL reader ... a contract test that runs every reader over a rotated fixture".
- AC-9: Segment files are never treated as WALs of their own: no agent/owner/task row, no ops_watch size or silence
  alert, no ledger entry is created from `S.NNNN.jsonl`; a writer refuses to create a WAL whose stem looks like a
  segment name. Verify by: `ReservedNameTests`, and the AC-8 registry (owner lists identical rotated vs unrotated). Source: inferred: from the brief's "linked to each other so agents can read them" -- a segment shown as its own agent would mislead status.
- AC-10: The three writers (claude `wal.py`, `ah` `_wal_append`, codex `wal.py`) pass the same rotation, race and
  crash scenarios and keep every existing refusal (hard link, symlink, redirected session directory, partial tail,
  bad path); `tests/test_wal.py` and the codex WAL tests pass unchanged. Verify by: `WriterContractTests` + the existing suites on t2-dev. Source: brief "the rotation writer" in scope; inferred: single implementation to avoid three divergent copies.
- AC-11: transcripts.py: when a live source rotates, the new segment source ADOPTS the live source's archived chunks
  (recorded as moved_from the live key; the bytes are not archived a second time), the new live source starts at gen 0
  offset 0 (not a "rewritten" generation), and index rows and manifests of segment and live sources carry
  `wal_segment: {stem, seq, kind: segment|live, prev}` linking them. A segment missing from the chain is listed by
  `transcripts.py` status as a gap. Verify by: `tests/test_transcripts_wal_segments.py` (fake archive config from
  `transcripts_testlib`, rotation between two runs, assert chunk counts and `moved_from`). Source: brief "transcripts.py chunk mapping links source segments".
- AC-12: `wal_segments.py map <dir>` prints, as JSON, every logical WAL in a directory (stem, segments with bytes,
  sha256, first_at, last_at, live, problems); `verify [--deep]` exits non-zero on any problem (`--deep` rehashes every
  segment against the markers and index); `cat <dir> <stem>` streams the full logical WAL in order; `reindex` rewrites
  indexes. All four work on a copy of the directory under another path (a git backup checkout) and never need
  `~/.claude`. Verify by: `CliTests` on a copied fixture directory. Source: brief "easy to find/recover/index/use them from git backups and local".
- AC-13: No code path deletes or truncates a WAL or segment except the pre-existing removal of an unterminated torn
  tail line of the live file; a static guard test asserts `wal_segments.py` contains no unlink/truncate/remove call
  outside that function and no open of a segment for writing other than the live file. Verify by: `NoDestructiveTests`. Source: brief "Never delete or truncate a WAL. Rotation only renames and opens a new file".
- AC-14: If rotation itself fails (permission, ENOSPC at create, injected fault) the record is still appended to the
  file that could be written (never lost), the failure is reported on stderr with a distinct code, and the next append
  retries the rotation. Verify by: `RotationFailureTests`. Source: inferred: from the WAL's job as the record of truth -- a rotation fault must not drop a record.
- AC-15: Docs: `docs/harness-reference.md`, `docs/operations.md`, `docs/transcripts-archive.md` (phase 2 out-of-scope
  note replaced) and a new `docs/wal-segments.md` describe names, markers, index, reader API, CLI, recovery from a
  backup, and the reserved-name rule; the installers ship `wal_segments.py`. Verify by:
  `tests/test_wal_segments_docs.py` (named sections present, installer lists contain the module) and review. Source: brief "and docs".

## Negative cases

- NEG-1 (AC-4): Crash between rename and live create (no `S.jsonl`), between create and marker (empty live), after
  marker before index (stale index). Each converges on the next append; readers meanwhile see all records once. Source: brief "a crash mid-rotation".
- NEG-2 (AC-3): Two writers both observe the limit crossed at once; one rotates, the other must not rotate again
  (no empty/marker-only segment) and must append into the new live file; two writers both find the live file missing
  and create it (O_EXCL loser re-opens). Source: brief "two writers racing".
- NEG-3 (AC-5): A reader that opened the live fd just before the rename; one that listed the directory between the
  rename and the new live create; neither duplicates or loses a line. Source: brief "a reader during rotation".
- NEG-4 (AC-7): The legacy WAL ends in a torn (unterminated) line; crash-tail repair runs before rotation, so the
  segment ends with a newline and the torn bytes are removed by the existing rule only. Source: inferred: existing crash-tail rule must not break the segment boundary.
- NEG-5 (AC-6): `S.0001.jsonl` is a symlink to another file (even a valid segment); `S.0002.jsonl` is a directory;
  neither is followed or read; a `not_regular` problem and a gap are reported. Source: brief "a symlink in place of a segment".
- NEG-6 (AC-6): Segments 1 and 3 exist, 2 missing (middle); segment 1 missing (leading); live missing with segments
  present (crash window, not a gap); duplicate seq via `S.0002.jsonl` and `S.00002.jsonl` (ambiguous). Source: brief "a segment missing from the middle".
- NEG-7 (AC-1): One record larger than the limit: it is written alone into a live file and never causes
  a rotation loop or a marker-only segment per append. Source: inferred: unbounded rotation would exhaust inodes.
- NEG-8 (AC-9): A task WAL id `foo.0001` (segment-shaped) is refused by the writer; an existing
  `agent-x.0001.jsonl` is never listed as agent `x.0001` by `ah owners`. Source: inferred: reserved names.
- NEG-9 (AC-10): A writer holding an fd on the pre-rotation inode (blocked on flock) wakes after the rename; it must
  not append to the closed segment, must re-open the live name and append there; a writer that is an OLD install
  (no rotation support) appending to a renamed inode lands in the closed segment, which readers still read (accepted
  residual: documented, not silent: `verify --deep` flags the segment as `marker_mismatch` on bytes). Source: inferred: mixed-version installs during rollout.
- NEG-10 (AC-8): A WAL line crossing no segment boundary is split by the reader; every segment ends with a newline
  after crash-tail repair, so a record never spans two segments; a reader window that starts mid-line in an earlier
  segment (`read_tail`) skips the partial first line exactly as today. Source: inferred: line-safety of the logical stream.
- NEG-11 (AC-12): `cat`/`map` pointed at a directory with a segment missing report the gap and exit non-zero (unless
  `--allow-gaps`, which still prints the gap on stderr). Source: brief "never silently skips it".
- NEG-12 (AC-13): A hard-linked live file or a symlinked live file is refused (as today) and nothing is renamed. Source: existing refusals in wal.py, kept by AC-10.
- NEG-13 (AC-3): The delayed-response scenario: a hook killed after write but before fsync returns; the retry of the
  same hook appends the record again (hooks are not idempotent today); rotation adds no new duplication class. Source: inferred: scope statement, nothing new introduced.
- NEG-14 (AC-12): No secret or PII in fixtures: generated records carry only synthetic event names and notes. Source: brief "no secrets or PII in fixtures".

## Resource budget

Host: t2-dev (via /home/eric/repos/harness/bin/testrun); nothing heavy on the Mac
Fan-out: agents=2 spec reviewers, jobs=1 test job at a time, processes=8 (concurrency test), browser_pages=0, test_workers=1
Peak memory: under 1 GB (method: 8 small Python writers; the 80 MB fixture is streamed, never loaded whole)
CPU: 2 cores (method: tests are IO-bound)
Disk: about 400 MB peak in a throwaway HOME (the 80 MB legacy fixture and its renamed copy; removed after) (method: fixture sizes)
Network: none
Wall time: 5 min per focused run
Cap and kill: testrun's own lease and timeout; the 80 MB test is the only large step
Checkpoint: the branch is pushed every 30 minutes; test receipts are saved under the work dir

## Risks

- A reader outside the registry still reads only the live tail: the guard test scans for modules that name WAL files and fails on an unreviewed one; every reader found is migrated or allowlisted with a reason.
- Incremental readers keyed by inode/offset (ah agent summaries, transcripts) treat the rotated live file as new: migrated readers rescan the chain; transcripts adopts by hash (AC-11).
- ops_watch `wal_size` threshold of 40 MiB would fire near the limit: re-based to alert when a live file exceeds the limit plus slack (rotation not working).
- Mixed installs (old writer, new writer) during rollout: the NEG-9 residual is documented and detectable by `verify --deep`.
- Hashing 50 MB under the lock stalls other writers about 0.2 s once per rotation: accepted; hooks have multi-second deadlines. UNMEASURED: measured on Mac and t2-dev before any claim (R2-18).

## Revision 2: review triage (two BLOCK reviews, opus and sonnet, both read the code)

Both reviewers returned BLOCK. Every item below is CRITICAL or USER_EXPERIENCE and binding; it overrides earlier text (including NEG-9, AC-13, AC-14 and the reserved-name rule, now `\.\d{4,}\.jsonl$` only, with `safe_id` escaping such ids into the `z-` namespace instead of raising).

- R2-1 Lock order (CRITICAL, both). Every append by every writer: seglock (blocking flock on the dir_fd-opened `.S.seglock`), then open the live file (O_CREAT only under the seglock), then the data flock, then the target check. A stale writer releases the data lock and retries from the top (bounded 8, then re-opens the CURRENT live name or fails loud; it never writes to a renamed inode). A bad seglock (directory, FIFO, symlink, nlink != 1) disables rotation for that append, the append proceeds under the data flock, stderr code `seglock_unusable`.
- R2-2 Rename never replaces (CRITICAL, both). Exclusive rename: `renameat2(RENAME_NOREPLACE)` on Linux, `renamex_np(RENAME_EXCL)` on macOS (ctypes). If unavailable or the target exists: skip rotation, append to the live file, stderr code `rotate_collision`. Next seq = max over ALL parsed names (including not_regular and ambiguous) and the live marker's segment minus 1, plus 1. AC-13's guard is AST-based (os.rename/replace, Path.rename/replace, shutil.move, unlink, truncate, remove), with a planted-violation negative control; the only allowed rename is the exclusive one in `rotate`.
- R2-3 Durability. fsync(dir_fd) after the rename, the live create and the index rename, before the append is acknowledged. AC-4 fault points: after_hash, after_rename, after_create, after_marker, after_index; one test each, asserting the child stopped AT that point and the on-disk state equals the expected intermediate before recovery.
- R2-4 Budgets (CRITICAL). `iter_lines` and `read_tail` budgets are over the LOGICAL stream; tail-bound readers (agent_gate, ask/evidence lookups, liveness) read newest-first. Budget exhaustion yields problem `truncated`, never a quiet stop. AC-8 "same answer" is scoped to chains inside the reader's budget; a separate case with a chain larger than the budget asserts `truncated` and that the newest records are still found.
- R2-5 Dedupe and last-line helpers (CRITICAL). `ah._wal_append` id-dedupe, `_last_line_is(pending_stop)` and every "last record" helper use `read_tail` on the chain and skip the open marker. Test: id in the previous segment, retry appends nothing. NEG-13 corrected: rotation must not weaken dedupe.
- R2-6 Markers (CRITICAL). A marker is recognised only as line 1 of a live file with the exact schema, and carries `"by":"wal_segments"`. `iter_lines` and `read_tail` skip markers by default (`include_markers=True` opts in), so line counts, last_at and activity are unaffected; a marker-shaped line elsewhere is an ordinary record. AC-1's byte equality is over records, markers excluded. New problem codes: `marker_missing` (closed predecessors but no marker on line 1, from an old or unlocked writer), `overlap` (a backup where bytes of the live file also sit in a closed segment, detected by `prev_sha256`), `truncated`, `schema_newer` (info), `seglock_unusable`, `rotate_collision`.
- R2-7 Existence (CRITICAL). `wal_segments.exists(path)` is true if the live file or any closed segment exists. Every `.exists()/.is_file()` check on a WAL path in migrated modules (wal.py subagent_stop, ah session_dir/deadline/pending_stop/owners, provenance session_wals_read, ops_watch idle/liveness) uses it. A crashed rotation (live missing) counts as the session existing. ops_watch and `reindex` finish a crashed rotation (create live and marker) without waiting for a new record.
- R2-8 Citations (CRITICAL). `wal:<path>#<id>` resolves over the chain; `#L<n>` is a LOGICAL line number across the chain, markers excluded; a citation naming a segment file directly resolves inside that segment. Tests: an id in a closed segment; `#L` across a boundary.
- R2-9 AC-14 corrected. If creating the live file fails after the rename (ENOSPC), rotation renames back exclusively; if that fails too, the record is NOT written into any closed segment: the writer fails loud (`rotate_failed_record_not_written`) and the recovery rule finishes the rotation on the next append. If rotation never started or collided, the record goes to the live file. Test ENOSPC at each step.
- R2-10 Mixed installs. NEG-9 restated per writer: old wal.py and old codex wal.py raise "target changed" after a rotation (record not written, hook errors); old `ah._wal_append` appends to the renamed inode (a closed segment), still read by readers and flagged by `verify --deep`. Rollout order: `wal_segments.py` first, then readers, then writers. Rotation is behind a switch: `~/.agent-harness/state/wal-rotation.on` must exist (written by the install step once readers and daemons are restarted); deleting it is the rollback (readers still read chains; `cat` yields the logical file). If importing `wal_segments` fails, writers fall back to the old plain append with a stderr note. hooks_manifest.json, doctor, install.py and install_codex.py list the module.
- R2-11 Reader inventory (CRITICAL). The AC-8 registry is per call site over: wal_note, ah (owners, session_dir, deadline, pending_stop, _session_entries, summarize_agent_wal, discover_agents), provenance (wal_entry, ledger_read, session_wals_read, `_lines_containing`, provenance_hooks quarantined entries), ops_watch (wal_size, liveness, idle_guard, deploys check with its 32 MiB per-file cap, alert text), agent_gate, ahd, ahd_peek, review_map, mission_coverage, spec_flow native-click reads, escalation, ah_export, ah_kill, wal_cadence, workdir, worktree_hygiene, kill_guard and command_guard codex regexes, mission_control WalTailer (a new segment is never replayed as a new agent), skills/check-dropped-workstreams/scan.py, dropped_gate, goals_view, codex hooks. Each is migrated or allowlisted with a reason in `tests/wal_reader_inventory.json`; the guard scans harness/, codex/, skills/, mission_control/ for open/glob/scandir/read_tail/read_bounded on WAL paths and WAL helper names, with a planted negative control.
- R2-12 Caches. ah owners/summaries key closed segments by (name, bytes, sha256 from marker/index) so only the live file is rescanned; a latency check on a 500 MB synthetic chain is reported with workload, hardware, baseline and result.
- R2-13 Index and CLI hardening. Index: 0600, tmp via O_EXCL|O_NOFOLLOW at dir_fd, fsync file and dir; the writer adds only its own entry, a full rebuild happens only in `reindex`. CLI: refuse a symlinked directory argument; validate the stem against the WAL-id regex; open only names from `scandir` matching the segment regex, never a name from a marker or index; `reindex` is `--dry-run` by default and writes only with `--write`; higher `schema` is best-effort with `schema_newer`. AC-12 adds forged-index cases (huge ints, wrong stem, `/` in names, FIFO or symlink index) and a backup-with-overlap fixture. AC-2 compares indexes excluding `updated`.
- R2-14 Env overrides. `HARNESS_WAL_SEGMENT_BYTES` and the fault-injection variable are honoured only when `HARNESS_TEST=1` and HOME is under a tmp root; production floor 1 MiB; `verify` warns when a marker's `limit` differs from the default; a test proves production mode ignores both.
- R2-15 Transcripts (AC-11). Adoption runs in a pre-pass before per-file processing, segments before live (both walk orders tested), keyed by the open marker's `prev_sha256` plus the prefix-chunk hash; the new live source starts a new epoch (gen continues, so chunk names cannot collide); `moved_from` records `{key, seq}`. Codex rollout files are Codex's own and are not rotated by us: they stay archive-chunked and the docs say so.
- R2-16 Target labels. ASSUMPTION: the user's "transcript ... rotate at 50mb" is met for WALs natively and for Claude/Codex transcripts by the archive's chunking (sources are read-only and not ours to rotate); "50mb" is read as 50 MiB. Both go to main for confirmation and are never presented as the user's choice.
- R2-17 Test adequacy. Failing-first: the AC-8 registry first runs the UNMIGRATED readers over a rotated fixture and that red run is saved as evidence (ImportError failures do not count). Concurrency tests use a start barrier and large records and assert rotation count >= 3 with >= 2 writers; the NEG-2 interleave is deterministic via a test-only pause hook. Reader-race tests pause the reader between "open live fd" and "list" during a rotation (NEG-3's two windows) and assert every intermediate snapshot is a duplicate-free, in-order prefix. Added negatives: mixed writers on one file, crash before fsync and during crash-tail repair, index as FIFO or symlink, stem `../`, orphan index tmp, ordering past 9999, target name already existing, a chain restored from backup with an overlap. AC-7 asserts the segment inode equals the pre-rotation inode (rename, not copy).
- R2-18 TICKET_LATER (main tickets them): log-backup carrying the whole chain and `verify` on a staged copy (another owner's files); rotation latency on cold or network homes (measured, not claimed).
