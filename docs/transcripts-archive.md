# Agent transcripts archive

GoodQA #16650, phase 1. Tool: `harness/hooks/transcripts.py` (wired as `ah transcripts`). Redaction gate:
`harness/hooks/transcript_redact.py`. Index contract: `docs/transcripts-index.schema.json` (schema 1).

The tool copies every Claude Code and Codex transcript (subagents included) and every harness WAL on a host. Each
record is redacted, the stream is split on record boundaries into chunks of at most 48 MiB raw, and each chunk is
compressed with zstd and pushed to private GitHub repos. A catalog repo maps sessions, projects, hosts, tickets and
PRs to chunks. The Dropbox log backup remains the unredacted never-lose copy, and this tool never touches it.

## Recovery truth

- **Recovery from git is byte-identical to the redacted archive, never to the source.**
- **Exact-source recovery comes from the local source file or the Dropbox log backup.**

## Accepted residual risk (read this before trusting the archive)

The archive is redacted plaintext. It is **not secret-free**. These gaps remain:

- Free-text passwords, and short secrets with no keyword or vendor prefix. Raw 64-hex keys are not redacted,
  because sha256 digests appear everywhere.
- Third-party personal data beyond email addresses and North American phone numbers. That includes ParentProof
  parents.
- Git history is permanent: a leaked value cannot be scrubbed without deleting the repo.
- GitHub secret scanning is not available on these repos.

The user was told about each of these gaps and chose redacted plaintext with no encryption. Source:
answer:8d9ac187-f758-4aac-b3ea-8e54ebf74057/fce7446f-9b52-42df-902f-2856da6dd1d8 "Scrub only, plaintext" (main WAL
w9cec461e7e7). The same statement is in the catalog README. No body encryption is implemented.

## For agents: when to run it

| Checkpoint | How it runs |
|---|---|
| Project start (`SessionStart` startup) | hook: `transcripts.py sync --checkpoint start --background` |
| Recovery (`SessionStart` resume/compact/clear) | hook: `sync --checkpoint recovery --background` |
| Takeover of another owner's stream | you: `ah transcripts sync --checkpoint takeover` |
| PR submit | `deliver.py prepare` runs `sync --checkpoint pr --budget-seconds 90`, then `check` |
| Deploy / release / live record | `wal_note.py --event deploy` starts a detached `sync --checkpoint deploy` |

A checkpoint without a fresh receipt is incomplete. If Codex hooks are untrusted, run the command by hand.

## Commands

```
transcripts.py sync --checkpoint {start,recovery,takeover,pr,deploy,manual} [--budget-seconds N] [--background] [--dry-run]
transcripts.py backfill [--budget-seconds 1800] [--max-load L]
transcripts.py check [--max-age-min 60] [--json]
transcripts.py status
transcripts.py find --session S | --ticket N | --project P | --since T | --host H
transcripts.py cat <session> [--local]
transcripts.py recover <session> --to DIR [--from git|local]
transcripts.py verify [--rehash] [--against-source] [--rescan --kind K]
transcripts.py reindex [--from-sidecars]
transcripts.py incident --kind K [--shard R]
transcripts.py ensure-repos --host H --months YYYY-MM[,YYYY-MM] [--parts N]
```

- **sync**: handles changed files newest first within the budget (90 s foreground, 600 s with `--background`). With
  `--background` it double-forks a detached child (setsid, stdio to `logs/sync.log`) and returns in under a second.
  If the lock is held it drops a request file and exits 0 with `skipped: locked`. `--dry-run` lists what would be
  archived and writes nothing.
- **backfill**: the same engine, resumable, at nice 10. It visits files **oldest mtime first**, so the transcripts
  closest to Claude Code's 30-day retention cleanup are archived first (goodqa#17119); a checkpoint `sync` stays
  newest first. It defers (exit 0, receipt status `deferred`) while the 1-minute load average exceeds
  `--max-load` (default: the core count). It never refreshes `last-ok.json` and never fails `check`.
- **check** exit codes, in precedence order 3, then 2, then 1:
  - `3` never-ok: there has never been an ok receipt, or the last run was `unconfigured` (no source root exists,
    or no transcript file was found under any root). An unconfigured host is never reported ok.
  - `2` failed: the last run failed, was refused (repo check), hit the omission cap or `disk-low`, or ran with the
    kill switch set. Also: a file is held, or there is backlog with no archived-byte progress in 24 h.
  - `1` stale: the last ok receipt is older than `--max-age-min`.
  - `0` ok.

  `--json` prints `{status, last_ok_at, age_min, reasons, exit, held, incidents}`, where `held` is
  `{count, by_reason}` from the last receipt. Any held file adds a `held=N (reason=n, ...)` reason and exit 2.
  `incidents` is `{oversize_records}`, the records omitted over the maximum in every archived chunk; it never
  changes the exit code, and the plain output appends `incident oversize_records=N` when it is not zero.
- **find** prints one JSON line per matching source file (host, source, relpath, session, parent, project, chunks,
  first/last ts, gens). `--session` also matches subagents whose parent is that session.
- **cat** streams the latest generation of a session from git, verifying every chunk before writing it.
  `--local` streams the source files.
- **recover** verifies everything into a staging dir under the state dir: zsha256, sha256, chain, sidecar prev
  pointers, seq contiguity, and the manifest's chunk count, chain and `whole_sha256`. Only then does it move files
  into `DIR/<host>/<source>/<relpath>`. On any mismatch it names the chunk and writes nothing to `DIR`. It never
  overwrites an existing file.
- **verify** checks that every pushed chunk and sidecar is present in its shard tip with the expected git blob id.
  A changed blob means changed bytes, and this costs no blob download. It also counts orphans. Other modes:
  - `--rehash` downloads generations whose `whole_sha256` is pending and fills it in. It is a prerequisite
    for the `whole_sha256` check on any file over 256 MiB: such a file is archived over more than one visit, so
    its `whole_sha256` stays pending (null) until `verify --rehash` runs. Run it before a live AC-4 recover of a
    large file.
  - `--against-source` (weekly, from the scheduler) fully hashes each archived prefix against the sidecars'
    `src_sha256`, and schedules a new generation on any mismatch.
  - `--rescan --kind K` is the incident rescan; see the runbook below.
- **reindex** rebuilds `index.sqlite` from the catalog (index JSONL and manifests). `--from-sidecars` rebuilds
  it from the shard repos alone: each sidecar, plus the commit that added it.

## How it works

Sources per host: `claude-projects` (`~/.claude/projects`, subagents included), `claude-wals` (`~/.claude/wals`),
`codex-sessions` (`~/.codex/sessions`), `codex-archived` (`~/.codex/archived_sessions`) and `codex-wals`
(`~/.agent-harness/codex-wals`). Files are opened read-only with `O_NOFOLLOW|O_NONBLOCK` and re-checked with
`fstat`. Symlinks, FIFOs, other non-regular files and empty files are skipped, and symlinked directories are never
walked.

### Incremental unit

Per source file the state keeps:

- the current generation's `archived_offset` (just after the last sealed record) and its line count;
- size, mtime_ns, ctime_ns and inode;
- a prefix fingerprint: sha256 over the first 64 KiB, the 64 KiB before the offset, and 16 sampled 4 KiB blocks.

An unchanged stat costs one `lstat`. A file is a rewrite, and gets a new generation `g<N+1>` from offset 0, when
any of these holds:

- it shrank below the offset;
- its inode changed (except a detected move);
- its fingerprint differs.

Old chunks are never touched. When in doubt, a duplicate generation is preferred over a skip.

**Stale-head bound.** A mid-file rewrite that keeps the size, mtime and inode, and that misses every
fingerprinted block, is not seen by the incremental scan. `verify --against-source` runs weekly from the
scheduler and fully re-hashes every archived prefix against the sidecars' `src_sha256`, so such a rewrite is
caught, and a new generation started, within 7 days.

**Moves** (Codex moves sessions into `archived_sessions/`). A new path continues the old entry only when all of
these hold:

- the old path is absent;
- the session id matches;
- re-hashing the new file range by range, each archived byte range matches the old chunk's `src_sha256`.

Otherwise the new path is archived as a new file.

**Small-chunk control.** A trailing delta is sealed only when one of these holds:

- it is 1 MiB or more;
- the file has been idle for 30 minutes or more;
- the checkpoint (or a served request) is `pr`, `deploy` or `takeover`.

Otherwise it waits, and `pending_since` is recorded; a delta pending over 2 h is reported as backlog. A partial
last line always waits. A single record over 48 MiB can never fit a chunk, so it is not a hold: it is archived
as the record-level omission `{"_archive":"omitted","reason":"oversize","line":N,"src_len":L}`, the chunk's
source hash still covers its bytes, and the receipt, `check` and `status` count it under
`incidents.oversize_records`. Oversize omissions do not count toward the omission cap. A record over the maximum
that has no newline yet waits like any partial line, without a hold.

A file's delta is capped at 256 MiB per visit. The redaction pass runs at roughly 1 to 2 s per MB, so the
checkpoint budget is enforced between records. When the budget runs out, the records gathered so far follow the
small-chunk rule.

### Redaction

Each record goes through `transcript_redact.redact_line` (pass 1 redaction, then the independent pass 2 verifier).
A record that still trips pass 2, or that raises, is replaced by an omitted marker. Its `{line, kind}` is listed in
the sidecar and counted in the receipt. The file keeps archiving.

No keyword rule runs on transformed text. A run of 1000 or more base64-alphabet characters is collapsed to
`[OMITTED:base64:<len>:<sha12>]` only after the raw keyword scan, the normalized keyword scan and a pass 2 check
have seen it intact, and a keyword span that ends inside such a run is extended to the run's end. Collapsing a
run therefore never removes the key word that ends it (`<1000-char name>_secret: V`), and a value cut at its
rule's length limit leaves no tail.

Mapping metadata (cwd, models, mentions, session ids) is taken from the redacted bytes only. Each sidecar is itself
run through the verifier before it is pushed: a field that trips it is dropped and `metadata_dropped` is set.

**Omission cap (AC-16).** The denominator is the records processed in the run. A run fails when:

- more than 0.5 % of all records in the run are omitted, or
- more than 5 % of a file's records are omitted, for a file of 100+ records.

Files over the per-file rule are held first. If the rest of the run still trips the run rule, files are held one
at a time, highest omission rate first, until the rest is under 0.5 %. A file whose own rate is at or under 0.5 %
is never held for the run rule, so one hostile file cannot take benign files down with it. The held files' staged
chunks from that run are discarded, so their gaps are never baked into immutable chunks before the rules are
tuned; every other file archives. The receipt status becomes `omission-cap`.

The run-level 0.5 % rule applies only when the run processed 1000 or more records. The per-file 5 % rule
applies only to files with 100 or more records in the run.

### Failures and holds

Holds are only for causes a retry can clear: a raised chunking error, a refusal, the omission cap (cleared by a
rules change or by the cause going away) and a collision (an integrity alarm that is re-checked when due). A
cause no retry can clear (a record over the maximum) is a recorded record-level omission instead.

One set of functions in `transcripts.py` (`hold`, `hold_due`, `begin_retry`, `release`) is the only writer of a
file's hold state; a guard test fails if anything else writes it. Every hold carries `since`, `attempts` and
`retry_at`:

- A held file is retried when `retry_at` passes, after 15 min, doubling per attempt up to 24 h; at once when
  `RULESET_VERSION` changes; and at once when the source file is rewritten.
- A retry that holds again keeps the first `since`; the same reason again counts as another attempt and backs
  off further. A collision is re-checked when due and, if still present, re-held and re-alerted.
- While any file is held the run is not ok: a run that would otherwise be ok gets status `held`, `last-ok.json`
  is not refreshed, `check` exits 2 with the counts, and `deliver.py prepare` refuses with the counts. A
  `--transcripts-waiver` still lets the PR through and is logged.

- A file that raises during chunking (a zstd failure, a sidecar whose metadata still trips the verifier, an
  unreadable range) is held with reason `refused:<why>` or `error:<Class>`, and an alert is raised. The rest of
  the run continues, and the file is retried by the hold rules above.
- Any other exception still writes a failed receipt naming only the exception class.
- Every child process (git, gh, zstd) gets a timeout capped at the run's hard stop (budget + 10 s). Publishing
  re-verifies and pushes one push group at a time, and stops starting new groups at the budget. What remains
  waits for the next run (receipt `notes`).
- Backlog is: visits cut short, unsealed deltas, and discovered files not yet visited. A file whose only
  unarchived bytes are a partial last line is not backlog. `no-progress-24h` counts from `last_progress_at`,
  or from the state's creation time.
- **Lost state guard.** Before the first catalog push from a state file, the tool reads the host's committed
  index. It refuses (status `failed`, "local state looks lost") if that index lists chunks the local state does
  not know, so a lost or replaced `state.json` can never shrink the host's catalog index.
- The host label comes from `TRANSCRIPTS_HOST`, else from the pinned `host` file in the state dir, which is
  written on first use from the short hostname. macOS hostnames drift; the label must not.
- The catalog README is pushed from `harness/hooks/transcripts_catalog_README.md`, installed beside
  `transcripts.py` in the hooks directory. The installer must ship it; when it is missing, the
  catalog push refuses visibly.

### Chunks and sidecars

`<stem>.<firstTS>_<lastTS>.g<gen>.p<seq:05d>.jsonl.zst` sits at `<host>/<source>/<relpath-dir>/` in a shard:

- The timestamps are the min and max of the records' top-level ISO-8601 `timestamp`, in UTC, formatted
  `YYYY-MM-DDTHH-MM-SSZ`. Without one, the file mtime is used and the sidecar says `ts_source: mtime`.
- Path components are sanitized to `[A-Za-z0-9._-]`, and paths stay at or under 200 characters by truncating the
  stem with an 8-hex sha256 suffix.
- Compression is `zstd -12 -T1`, round-trip verified before the chunk is staged.

Each chunk has an immutable `.meta.json` sidecar. It records:

- host, tool, source, relpath, session, parent, project and models;
- gen and seq, and `prev` {name, sha256};
- `src_range` and `src_sha256`; `sha256` of the raw bytes, `zsha256` of the compressed file, bytes and zbytes;
- records, `line_start` and the time range;
- `chain_sha256 = sha256(prev_chain_hex + sha256_hex)`;
- mentions: GoodQA tickets, PR URLs and 40-hex commits, at most 200 of each;
- redaction counts, omissions and `ruleset_version`.

There are no next pointers, because chunks are immutable. The next chunk is `seq+1`, also listed in the manifest
and the index.

### Shards and catalog

Shards are `ericmacdougall/agent-transcripts-<host>-<YYYY>-<MM>-p<N>`, using the UTC month the chunk was created.
A shard rolls to `p<N+1>` once its recorded compressed bytes would pass 1.5 GB. The catalog
`ericmacdougall/agent-transcripts` holds:

- `README.md`;
- `shards/<host>.json` (the ledger);
- `index/<host>.jsonl` (one row per pushed chunk);
- `manifests/<host>/<source>/<relpath>.json`.

Every catalog path is per host. Catalog files carry no run timestamps, so a no-op run makes no commit.

### Publisher

All git work happens in a temporary bare repo under `tmp/`, with a promisor remote. It uses:

- `ls-remote` to read the tip;
- a root commit for an empty repo;
- otherwise `fetch --depth=1 --filter=blob:none`;
- `read-tree`, `hash-object -w`, `update-index --index-info`, `write-tree --missing-ok` and `commit-tree`;
- `push <sha>:refs/heads/main`, with a 300 s cap, bounded by the run budget.

It never uses `--force` or a `+` refspec. A non-fast-forward rejection refetches and rebuilds, up to 5 tries.
After a timeout or error it re-reads the tip and treats the push as landed only if the tip is its commit or
contains every one of its paths with the same blobs.

**Collisions (NEG-17).** An existing shard path with a different blob is never overwritten. The chunk is refused,
the file is held and an alert is raised. This is decided from tree blob ids, without fetching any blob.

**Repo checks (AC-1).** Before every push run the tool checks every repo it will push (shards and catalog):

- visibility PRIVATE;
- not a fork;
- owner ericmacdougall;
- no collaborators besides the owner.

The result is cached for that run only. Any failure, or an unknown answer, refuses all pushes; the receipt status
becomes `refused` and an alert is raised.

**Re-verify before push (NEG-16).** Each staged chunk is re-read from the outbox before it is pushed:

- zsha256 must match;
- it must decompress, and the sha256 must match;
- `ruleset_version` must be current;
- pass 2 and gitleaks (the independent third gate, pinned at 8.30.1) must be clean over the chunk and,
  separately, its sidecar.

The rescan is file-atomic: every staged chunk of a file is rescanned before any chunk of that file is pushed. A
scanner hit holds the **whole file** (reason `scanner:<rules>`, with the source line when the hit is in the chunk);
none of its staged chunks leave, and the receipt counts it in `egress.scanner_held_files`. A record that pass 1 or
pass 2 caught while chunking is already an omitted marker; only a hit that survives redaction holds a file. On any
other failure (zsha256, sha256, ruleset, unreadable) the chunk and every later staged chunk of that file are dropped,
the generation is rewound and the range is re-chunked from source; a file that fails three times is held. A file
the budget cuts off during the rescan waits whole.

**Egress gate (click-test F1, class C11).** `publish_tree` is the only function that runs git write plumbing
(a guard test lists every site). Before it builds a tree it scans the repo name, the ref, the commit message, every
tree path and every blob: bytes blobs with pass 2 per item and gitleaks once per commit; an outbox chunk may leave
only if the rescan registered it and its sha256 is unchanged. Any hit refuses the whole commit. Producers filter
first (`egress_filter`): a chunk whose path or sidecar fails holds its file (`refused:egress`); a failing catalog
manifest is withheld, and a JSONL index blob loses only its failing lines (`egress.catalog_withheld`, run not ok).
A held file with nothing pushed gets no manifest. gitleaks is required: a missing binary refuses the run, and
`TRANSCRIPTS_GITLEAKS=off` is honoured only against a local test remote. Residual: repo names are created before
the gate from the pinned host label, not from source data.

### Hosts without gh (SSH push, e.g. t2-dev)

- **Remote URL style:** `TRANSCRIPTS_GIT_URL_STYLE={auto,https,ssh}`, default `auto`. Auto uses https, through
  the gh credential helper, when `gh auth status` succeeds, and `git@github.com:ericmacdougall/<repo>.git`
  otherwise.
- **Visibility check without gh:** an unauthenticated `GET https://api.github.com/repos/OWNER/REPO` (urllib, 10 s,
  generic User-Agent). HTTP 200 means the repo is public, so the push is refused. A 404 together with a working
  SSH `git ls-remote` means private. Any other status or error is a refusal.
- **Attestations:** fork, owner and collaborator checks need auth. On each of its push runs, a host with gh writes
  `repo-checks/<repo>.json` to the catalog (schema, repo, checked_at, checked_by, private, fork, owner,
  collaborators_count). It does this for the catalog, its own shards, every shard in any host's ledger, and every
  already-attested repo, refreshing records older than 6 h. A gh-less host refuses with `repo-attestation-stale`
  unless the record exists, is younger than 24 h, and shows private, not a fork, owner ericmacdougall and 0
  collaborators. A gh host must therefore push at least daily, or run `ensure-repos`, for gh-less hosts to keep
  pushing.
- **Repo creation:** a gh-less host cannot create repos. It refuses with `shard-repo-missing` (or
  `catalog-repo-missing`). On a gh host, run
  `transcripts.py ensure-repos --host t2-dev --months 2026-11,2026-12 [--parts N]` to create that host's private
  shards p1..pN for each month and attest them. Pre-create the next month, and higher parts before a shard
  reaches 1.5 GB.

### Crash safety (NEG-6, NEG-19)

The order of operations is:

1. Write the chunk, sidecar and a `.rec.json` to `outbox/` atomically (tmp, fsync, rename).
2. Advance the state.
3. Assign the shard and save.
4. Write journal `pending` rows (path and blob).
5. Push.
6. Write journal `pushed` rows.
7. Mark the state pushed and save.
8. Delete the outbox files.
9. Push the catalog.

On restart:

- outbox chunks the state missed are adopted when they continue the generation exactly, and deleted otherwise;
- unresolved journal rows are reconciled by path and blob against the shard tip, never by commit, before
  anything is re-chunked.

A chunk in a shard but missing from the catalog is repaired by the next run, because the catalog stays dirty
until it is pushed. The test suite injects a hard crash after each step.

### Lock, requests, receipts

- `lock`: `fcntl.flock`, non-blocking. The kernel frees it when its holder dies.
- `requests/<checkpoint>-<ns>-<pid>`: created with `O_EXCL|O_NOFOLLOW`; the checkpoint is validated against the
  six names. Requests older than 24 h, and invalid ones, are reaped. The lock holder serves requests between
  files: a served `pr`, `deploy` or `takeover` forces sealing, the changed files are rescanned first, and the
  receipt lists `served_checkpoints`.
- `receipts/last.json` is written by every run that took the lock; `last-ok.json` only when ok. Fields: host,
  checkpoint, served_checkpoints, started/finished, ok, status (`ok|held|failed|refused|omission-cap|disk-low|
  killswitch|deferred`), files scanned/changed, chunks staged/pushed, bytes, held (source label, path sha12,
  reason, line, since, attempts, retry_at), backlog, shard commits, catalog commit, omitted {total, by_kind, records_processed}, incidents {oversize_records}, collisions,
  last_progress_at, killswitch, notes and error. `sync` exits 0 when the receipt is ok and 2 otherwise.

  Receipts, alerts and logs never carry a source value: only kinds, counts, line numbers and path sha12.
- `alerts.jsonl`: one row per alert (repo check, collision, reverify, omission cap, file held, incident), for
  ops_watch.
- `waivers.jsonl`: `deliver.py --transcripts-waiver` appends one row per waiver; `status` counts them.

### Local footprint

`~/.agent-harness/transcripts/` (mode 0700) holds:

- `state.json`, `journal.jsonl`, `receipts/`, `requests/`, `logs/`;
- `outbox/` (cap 1.5 GB) and `meta/` (sidecars of pushed chunks, used to build the index);
- `tmp/` and `index.sqlite`.

The sync refuses new work while free disk space is under `min_free_gb`: 12 by default, overridable with
`TRANSCRIPTS_MIN_FREE_GB`. It still pushes what is already staged, and reports `disk-low free=X.XGB floor=12.0GB`.

### Environment overrides (tests)

- `TRANSCRIPTS_HOME`: the state dir.
- `TRANSCRIPTS_SOURCES`: a JSON label to root map.
- `TRANSCRIPTS_HOST`: the host label.
- `TRANSCRIPTS_REMOTE_BASE` with `TRANSCRIPTS_ALLOW_LOCAL_REMOTE=1`: shards and the catalog become local bare repos
  under that dir. The repo checks then read `<base>/repo-checks.json` instead of `gh api`. Map a repo name or `*`
  to fact overrides, or to `{"error": ...}`.
- `TRANSCRIPTS_GIT_URL_STYLE` (see above).
- Only with a local remote: `TRANSCRIPTS_TEST_NO_GH` (act as a gh-less host; the stub's `unauth_status` stands in
  for the unauthenticated API read), `TRANSCRIPTS_CHUNK_MAX_BYTES`, `TRANSCRIPTS_SHARD_CAP_BYTES`,
  `TRANSCRIPTS_SEAL_MIN_BYTES`, `TRANSCRIPTS_FILE_DELTA_CAP`, `TRANSCRIPTS_PUSH_TIMEOUT`, `TRANSCRIPTS_CRASH_AT`
  and `TRANSCRIPTS_IGNORE_LOAD`.

## Incident runbook (secret found after push, AC-15)

1. **Contain.** Run `ah transcripts incident --kind K [--shard R]` on any host. It sets the host-wide local kill
   switch, which stops every push on that host (shards and catalog), raises an alert and makes `check` exit 2.
   It also pushes `incident/K.json` (`cleared: false`) to the catalog. Every host's publisher reads the
   catalog's `incident/` files before it pushes, and refuses while any of them is not cleared (status
   `killswitch`). An incident raised on one host therefore stops all hosts. If the catalog push fails, the
   command exits 2 and the local kill switch still holds.
2. **Rotate the credential first.** Assume it is compromised the moment it was pushed.
3. **Patch the rules.** Fix `transcript_redact.py` so pass 2 detects kind K, then bump `RULESET_VERSION`. Staged
   chunks under the old ruleset are then re-redacted from source automatically.
4. **Rescan.** Run `ah transcripts verify --rescan --kind K` on every host. It scans every shard listed in the
   catalog's ledgers for every host, plus the local ledger. Findings name the repo, path, line and kind, never the
   value. Only a clean rescan for kind K clears the local kill switch and rewrites the catalog's
   `incident/K.json` with `cleared: true`, which lets every host push again.
5. **Remove the bad record (only with the user's sourced OK).** Deleting a repo is a permanent deletion and needs
   the user's explicit approval in chat. With that approval:
   - delete and recreate shard R from local state minus the bad record;
   - re-push it through the tool;
   - repair the catalog with `reindex --from-sidecars`.

   The ref is never rewritten and never force-pushed (rule 4).

## Index format

See `docs/transcripts-index.schema.json`. Index rows carry:

- schema, host, tool, source, relpath, session, parent, project and models;
- gen, seq and name;
- sha256, zsha256, bytes, zbytes and records;
- first_ts, last_ts and ts_source;
- mentions, chain_sha256, line_start, src_range and the omitted count;
- shard, path and commit (the commit that added the path).

Manifests carry each generation's ordered chunk list (shard, path, commit, sha256, zsha256, src_sha256, git blob,
seq, src_range), plus:

- `archived_offset`, `chain_sha256`, and `whole_sha256` (or `whole_sha256_pending`);
- `fully_archived`: archived_offset equals size, no pending delta and no held record;
- `held`, `missing`, `moved_from` and `omitted_chunks`.

A file that moved leaves a pointer manifest at its old path with `moved_to`. A field is never removed or renamed
without a schema bump, and `reindex` migrates.

## Out of scope (phase 1)

- Native WAL rotation (phase 2).
- Windows hosts: the tool refuses visibly.
- A full local chunk mirror.
- Harness operational logs.
- The Dropbox log backup script, its lock and its sync client: this tool never starts or touches them (AC-12).
