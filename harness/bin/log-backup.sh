#!/bin/bash
# Agent log backup to Dropbox (GoodQA #14471). COPY only: this script runs only `rclone copy`, `listremotes` and
# nothing that deletes, syncs, purges or moves on the remote, so a local deletion cannot propagate. Changed files
# are kept under versions/STAMP instead of overwritten.
#
# Environment (all optional; tests and operators use them, the scheduler uses none):
#   LOG_BACKUP_REMOTE       base path on the remote, NAME:path such as lessons-dropbox:Backups/agent-logs. NAME must
#                           be listed by `rclone listremotes`. Default: the first of lessons-dropbox, dropbox that is
#                           a dropbox or crypt remote. A crypt overlay is named here later; nothing else changes.
#   LOG_BACKUP_ALLOW_LOCAL  1 lets LOG_BACKUP_REMOTE be an absolute local directory (tests only)
#   LOG_BACKUP_RCLONE       rclone executable (default: rclone)
#   LOG_BACKUP_HOST         host label, letters digits . _ - only (default: hostname -s)
#   LOG_BACKUP_EXCLUDES     exclude file (default: log-backup.excludes next to this script)
#   LOG_BACKUP_RETRIES      extra attempts per source (default 2) and LOG_BACKUP_RETRY_SLEEP seconds between them (30)
#   LOG_BACKUP_STAGE        local snapshot directory for live sources (default ~/.agent-harness/backup-stage)
#   LOG_BACKUP_TPSLIMIT     rclone --tpslimit per host (default 1; the account's write budget is shared by all hosts) and
#   LOG_BACKUP_TRANSFERS    --transfers (default 2), both whole numbers 1-99
#   LOG_BACKUP_BULK_EVERY_SECONDS  minimum gap between bulk-tier attempts (default 3600); transcripts run every time
#   LOG_BACKUP_JITTER_SECONDS      random start delay up to this many seconds (default 0; the launchd plist sets 120)
#   LOG_BACKUP_BUDGET_SECONDS      wall time for copying after the start delay (default 780), never past the next run
#   LOG_BACKUP_PERIOD_SECONDS      the schedule interval (default 900); a run ends at least 30 s before it is over
#   LOG_BACKUP_SLICE_RESERVE_SECONDS  least copy time promised to each later tier-1 source (default 20)
#   LOG_BACKUP_DEADLINE_GRACE_SECONDS / LOG_BACKUP_KILL_GRACE_SECONDS  a copy past its share gets SIGTERM after the
#                           first (default 10) and SIGKILL after the second more (default 10)
#   LOG_BACKUP_VERSIONS     exactly 0 turns off versions/STAMP (loud warning); anything else keeps them
#   LOG_BACKUP_BULK_CHUNK   files per checkpointed bulk copy (default 100, 1-99999); see bulk_upload
# Freshness contract, two tiers with their own markers. log-backup.last-ok (transcripts, WALs, ledgers) is written
# atomically with the run START time only after every tier-1 source copied cleanly and a primary source
# (.claude/projects or .codex/sessions) held files. log-backup.bulk-last-ok (archived sessions, narrowed work tree)
# is written only after every tier-2 source copied cleanly. A run skipped because another run holds the lock writes
# log-backup.last-skip and touches neither marker.
set -u
SELF_DIR=$(cd "$(dirname "$0")" && pwd)
cd / || exit 1
RCLONE=${LOG_BACKUP_RCLONE:-rclone}
HOST=${LOG_BACKUP_HOST:-$(hostname -s)}
STARTED=$(date -u +%FT%TZ)
STAMP=$(date -u +%Y%m%dT%H%M%SZ)
LOGDIR="$HOME/.agent-harness/logs"
LOG="$LOGDIR/log-backup.log"
LOCKD="$LOGDIR/log-backup.lock.d"
EXCLUDES=${LOG_BACKUP_EXCLUDES:-$SELF_DIR/log-backup.excludes}
STALE_LOCK_SECONDS=86400
WORK_EXCLUDES=${LOG_BACKUP_WORK_EXCLUDES:-$SELF_DIR/log-backup.work-excludes}
BUDGET_SECONDS=${LOG_BACKUP_BUDGET_SECONDS:-780}   # one run must end inside the 15 minute period
RUN_START=$(date +%s)
SCRIPT_START=$RUN_START
TPSLIMIT=${LOG_BACKUP_TPSLIMIT:-1}       # Dropbox write budget is shared by every host that backs up to the account:
TRANSFERS=${LOG_BACKUP_TRANSFERS:-2}     # keep each host's share small (the Mac, dev2 and T2 together stay near 3/s)
BULK_EVERY=${LOG_BACKUP_BULK_EVERY_SECONDS:-3600}   # the bulk tier (work tree, archives) runs hourly, transcripts every time
JITTER=${LOG_BACKUP_JITTER_SECONDS:-0}   # random start delay so hosts on the same schedule do not collide
SLICE_RESERVE=${LOG_BACKUP_SLICE_RESERVE_SECONDS:-20}  # the least copy time each later tier-1 source is promised
DEADLINE_GRACE=${LOG_BACKUP_DEADLINE_GRACE_SECONDS:-10}  # a copy still running this long past its share gets SIGTERM
KILL_GRACE=${LOG_BACKUP_KILL_GRACE_SECONDS:-10}  # and SIGKILL this long after that (rclone drains batches on TERM)
PERIOD=${LOG_BACKUP_PERIOD_SECONDS:-900}  # the schedule interval: a run, start delay included, ends before the next one
for rate in TPSLIMIT TRANSFERS; do
  if ! printf '%s' "${!rate}" | grep -Eq '^[1-9][0-9]?$'; then
    echo "log-backup: $rate must be a whole number from 1 to 99" >&2; exit 2
  fi
done
BULK_CHUNK=${LOG_BACKUP_BULK_CHUNK:-100}
printf '%s' "$BULK_CHUNK" | grep -Eq '^[1-9][0-9]{0,4}$' || { echo "log-backup: LOG_BACKUP_BULK_CHUNK must be 1-99999" >&2; exit 2; }
for numeric in BUDGET_SECONDS LOG_BACKUP_RETRIES LOG_BACKUP_RETRY_SLEEP BULK_EVERY JITTER DEADLINE_GRACE SLICE_RESERVE KILL_GRACE PERIOD; do
  # No leading zeros: bash would read 08 as octal and abort the arithmetic.
  if ! printf '%s' "${!numeric:-0}" | grep -Eq '^(0|[1-9][0-9]{0,4})$'; then
    echo "log-backup: $numeric must be a whole number of at most 5 digits without leading zeros" >&2; exit 2
  fi
done
# Size limits go to rclone, so they must be plain sizes: digits, an optional K, M or G, and not zero (a zero transfer
# cap would stop every run immediately and the bulk marker would never be written).
for sized in LOG_BACKUP_WORK_MAX_SIZE LOG_BACKUP_WORK_MAX_TRANSFER; do
  if [ -n "${!sized:-}" ] && ! printf '%s' "${!sized}" | grep -Eq '^[1-9][0-9]{0,5}[KMG]?$'; then
    echo "log-backup: $sized must look like 25M (a non-zero number, optional K, M or G)" >&2; exit 2
  fi
done

umask 077
mkdir -p "$LOGDIR" || { echo "log-backup: cannot create $LOGDIR" >&2; exit 1; }
chmod 700 "$LOGDIR" 2>/dev/null
[ -e "$LOGDIR/log-backup.first-run" ] || date -u +%FT%TZ > "$LOGDIR/log-backup.first-run"
# Never let an inherited rclone option redirect or reconfigure a run; only the config file location passes through.
for v in $(env | sed -n 's/^\(RCLONE_[A-Za-z0-9_]*\)=.*/\1/p'); do
  [ "$v" = RCLONE_CONFIG ] || unset "$v"
done
# Keep the log bounded: past 10 MB it is renamed to log-backup.log.1 (one generation) before this run writes.
rotate_log() {
  local size
  size=$(wc -c < "$LOG" 2>/dev/null | tr -d ' ')
  if [ -n "$size" ] && [ "$size" -gt 10485760 ]; then mv -f -- "$LOG" "$LOG.1" 2>/dev/null; fi
}
[ -f "$LOG" ] && rotate_log
say() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$1" >> "$LOG"; }
fail() { say "$1"; echo "log-backup: $1" >&2; echo "$STARTED exit=$2" > "$LOGDIR/log-backup.last-run"; exit "$2"; }

file_age() { # seconds since modification of $1; BSD stat on Darwin, GNU stat elsewhere
  local m
  if [ "$(uname)" = Darwin ]; then m=$(stat -f %m "$1" 2>/dev/null); else m=$(stat -c %Y "$1" 2>/dev/null); fi
  [ -n "$m" ] || { echo 0; return; }
  echo $(( $(date +%s) - m ))
}

raw_age() { # like file_age but prints nothing when the modification time cannot be read
  local m
  if [ "$(uname)" = Darwin ]; then m=$(stat -f %m "$1" 2>/dev/null); else m=$(stat -c %Y "$1" 2>/dev/null); fi
  case "$m" in ''|*[!0-9]*) return 0 ;; esac
  echo $(( $(date +%s) - m ))
}

# The hand-installed script keeps its own lock directories (transcripts: stale after 1 h, bulk: after 6 h). A young
# one means its run is still going: skip, never take over. An unreadable modification time counts as a live run; a
# time in the future counts as live only within the stale limit (beyond it the lock cannot belong to a real run).
legacy_run_active() {
  local spec dir limit age
  for spec in log-backup.transcripts.lock.d:3600 log-backup.bulk.lock.d:21600; do
    dir="$LOGDIR/${spec%%:*}"; limit=${spec##*:}
    [ -d "$dir" ] || continue
    age=$(raw_age "$dir")
    [ -n "$age" ] || return 0
    if [ "$age" -lt "$limit" ] && [ "$age" -gt "-$limit" ]; then return 0; fi
  done
  return 1
}

holder_alive() { # pid $1 is running and is a log-backup run (a recycled pid belongs to something else)
  kill -0 "$1" 2>/dev/null || return 1
  # args must read: <shell> <path ending in log-backup.sh>. The path may contain spaces (a HOME with a space), so the
  # whole remainder is matched, not one word; a remainder that starts with a flag (sh -c ... log-backup.sh) is a spoof.
  local args first rest
  args=$(ps -p "$1" -o args= 2>/dev/null) || return 1
  first=${args%% *}; rest=${args#* }
  [ "$rest" != "$args" ] || return 1
  case "$first" in sh|bash|dash|zsh|*/sh|*/bash|*/dash|*/zsh) ;; *) return 1 ;; esac
  case "$rest" in -*) return 1 ;; esac
  case "$rest" in *log-backup.sh) return 0 ;; esac
  return 1
}

acquire_lock() {
  if mkdir "$LOCKD" 2>/dev/null; then echo $$ > "$LOCKD/pid"; return 0; fi
  local holder age
  holder=$(cat "$LOCKD/pid" 2>/dev/null)
  age=$(file_age "$LOCKD")
  if [ -n "$holder" ]; then
    holder_alive "$holder" && [ "$age" -lt $STALE_LOCK_SECONDS ] && return 1
  elif [ "$age" -lt $STALE_LOCK_SECONDS ]; then
    # No pid file: the owner has not written it yet, or the lock belongs to the older hand-installed script (same
    # lock.d directory, no pid). Never take that over while it is young; its owner stops it, or it ages out.
    return 1
  fi
  # Stale. Takeovers are serialized by a second mkdir guard, so two runners cannot both judge the same lock and
  # one of them move the other's fresh lock. A guard left by a crashed takeover expires after 5 minutes.
  local guard="$LOCKD.takeover"
  if ! mkdir "$guard" 2>/dev/null; then
    [ "$(file_age "$guard")" -gt 300 ] || return 1
    rmdir "$guard" 2>/dev/null; mkdir "$guard" 2>/dev/null || return 1
  fi
  if [ -d "$LOCKD" ] && [ "$(cat "$LOCKD/pid" 2>/dev/null)" != "$holder" ]; then
    rmdir "$guard" 2>/dev/null  # the lock changed hands while we waited for the guard: it is not stale any more
    return 1
  fi
  say "taking over stale lock (holder=${holder:-none} age=${age}s)"
  local gone="$LOCKD.stale.$$" got=1
  if mv "$LOCKD" "$gone" 2>/dev/null; then
    rm -f "$gone/pid"; rmdir "$gone" 2>/dev/null
  fi
  if mkdir "$LOCKD" 2>/dev/null; then echo $$ > "$LOCKD/pid"; got=0; fi
  rmdir "$guard" 2>/dev/null
  return $got
}

[ "$JITTER" -gt 0 ] && sleep $((RANDOM % (JITTER + 1)))
RUN_START=$(date +%s)   # the budget is for copying: the start delay must not spend it (2026-11-07)
# One wall-clock deadline for every copy, its stop and its kill: the budget after the start delay, but never past the
# next scheduled start (less 30 s to write the markers), so a long delay shrinks the copying time instead.
WALL_END=$(( RUN_START + BUDGET_SECONDS ))
[ $(( SCRIPT_START + PERIOD - 30 )) -ge $WALL_END ] || WALL_END=$(( SCRIPT_START + PERIOD - 30 ))
MIN_SLICE=$SLICE_RESERVE; [ "$MIN_SLICE" -ge 1 ] || MIN_SLICE=1
if legacy_run_active || ! acquire_lock; then
  say "skipped: another backup run holds the lock (this is not a successful backup)"
  date -u +%FT%TZ > "$LOGDIR/log-backup.last-skip"
  exit 0
fi
trap '[ "$(cat "$LOCKD/pid" 2>/dev/null)" = "$$" ] && { rm -f "$LOCKD/pid"; rmdir "$LOCKD" 2>/dev/null; }' EXIT
# A watchdog that outlived a killed run can leave its marker; with the lock held, none of them is current.
rm -f "$LOGDIR"/.log-backup.deadline.* 2>/dev/null

command -v "$RCLONE" >/dev/null 2>&1 || fail "rclone not found (set LOG_BACKUP_RCLONE or fix PATH)" 127
[ -r "$WORK_EXCLUDES" ] || fail "work exclude file missing: $WORK_EXCLUDES" 2
[ -r "$EXCLUDES" ] || fail "exclude file missing: $EXCLUDES (refusing to run without credential excludes)" 2
for anchor in auth.json rclone.conf member.key '*.secret' '.env'; do
  grep -qxF -- "$anchor" "$EXCLUDES" || fail "exclude file lacks required pattern $anchor (refusing to run)" 2
done
case "$HOST" in ''|*[!A-Za-z0-9._-]*|-*|.*) fail "invalid host label" 2 ;; esac

remotes=$("$RCLONE" listremotes --long --ask-password=false </dev/null 2>/dev/null)
BASE=${LOG_BACKUP_REMOTE:-}
if [ -z "$BASE" ]; then
  for cand in lessons-dropbox dropbox; do
    if printf '%s\n' "$remotes" | awk -v n="$cand:" '$1==n && ($2=="dropbox" || $2=="crypt") {f=1} END {exit !f}'; then
      BASE="$cand:Backups/agent-logs"; break
    fi
  done
  [ -n "$BASE" ] || fail "no usable rclone remote (expected a dropbox or crypt remote named lessons-dropbox: or dropbox:); set LOG_BACKUP_REMOTE" 3
fi
case "$BASE" in
  /*) [ "${LOG_BACKUP_ALLOW_LOCAL:-0}" = 1 ] || fail "LOG_BACKUP_REMOTE must be NAME:path" 3 ;;
  *)
    case "$BASE" in
      -*|:*|*..*|*[!A-Za-z0-9_./:-]*|*:*:*) fail "LOG_BACKUP_REMOTE is not a plain NAME:path" 3 ;;
    esac
    name=${BASE%%:*}
    case "$BASE" in *:*) ;; *) fail "LOG_BACKUP_REMOTE must be NAME:path" 3 ;; esac
    printf '%s\n' "$remotes" | awk -v n="$name:" '$1==n && ($2=="dropbox" || $2=="crypt") {f=1} END {exit !f}' \
      || fail "remote $name: is not a configured dropbox or crypt remote" 3
    # Pin the remote so a changed rclone setup cannot silently split the backup history across accounts.
    pin="$LOGDIR/log-backup.remote"
    if [ -e "$pin" ]; then
      [ "$(cat "$pin")" = "$name" ] || fail "remote changed from $(cat "$pin"): to $name:; remove $pin if intended" 4
    else
      echo "$name" > "$pin"
    fi ;;
esac
R="$BASE/$HOST"
[ "${LOG_BACKUP_VERSIONS:-1}" != 0 ] || say "WARNING: versions disabled; a truncated local file would overwrite its remote copy"

ok=0 found=0 primary=0
STAGE=${LOG_BACKUP_STAGE:-$HOME/.agent-harness/backup-stage}
# Live sources (transcripts and WALs grow while uploaded, so Dropbox's hash check would fail) are snapshotted into a
# local stage first and uploaded from there. Static sources upload in place, skipping files younger than 2 minutes.
# Smallest first, .claude/projects last (goodqa#15044 N2): the single files and the WAL tree finish in seconds, and
# the large, always-changing transcript tree then gets all the time that is left instead of a fixed early share.
LIVE=(.claude/history.jsonl .codex/history.jsonl .agent-harness/work-assignments.json .agent-harness/work-ledger.json
  .agent-harness/work-ledger.events.jsonl .agent-harness/work-ledger.archive.jsonl .agent-harness/work-ledger.failures.jsonl
  .agent-harness/work-ledger.spool.jsonl .claude/wals .codex/sessions .claude/projects)
DIRECT=(.codex/archived_sessions .agent-harness/work)
command -v rsync >/dev/null 2>&1 || fail "rsync not found (needed to snapshot live files)" 127
# The stage must be a private directory of its own: absolute, no `..`, not a symlink, not HOME or any ancestor of a
# source, and not inside a source (it would nest into itself or be uploaded as data).
STAGE=$(printf '%s' "$STAGE" | sed 's#//*#/#g; s#/$##')   # collapse repeated and trailing slashes
case "$STAGE" in "$HOME"/?*) ;; *) fail "LOG_BACKUP_STAGE must be an absolute path below $HOME" 2 ;; esac
case "$STAGE" in *..*|*[[:cntrl:]]*) fail "LOG_BACKUP_STAGE is not a plain path" 2 ;; esac
for guarded in "$HOME" "$HOME/.claude" "$HOME/.codex" "$HOME/.agent-harness/work"; do
  case "$STAGE/" in "$guarded/"*) [ "$guarded" = "$HOME" ] && continue; fail "LOG_BACKUP_STAGE must not sit inside $guarded" 2 ;; esac
  case "$guarded/" in "$STAGE/"*) fail "LOG_BACKUP_STAGE must not contain $guarded" 2 ;; esac
done
[ ! -L "$STAGE" ] || fail "LOG_BACKUP_STAGE must not be a symlink" 2
mkdir -p "$STAGE" && chmod 700 "$STAGE" || fail "cannot create the stage directory" 1
# rclone matches the exclude file case-insensitively (--ignore-case) but rsync cannot, so give rsync a case-folded
# copy of the same patterns (auth.json becomes [aA][uU][tT][hH].[jJ][sS][oO][nN]): Auth.JSON or .ENV never reach the stage.
RSYNC_EXCLUDES="$LOGDIR/log-backup.rsync-excludes"
awk '/^[ \t]*(#|$)/ {next} {out=""; for (i = 1; i <= length($0); i++) {c = substr($0, i, 1); if (c ~ /[A-Za-z]/) out = out "[" tolower(c) toupper(c) "]"; else out = out c} print out}' "$EXCLUDES" > "$RSYNC_EXCLUDES" \
  || fail "cannot build the snapshot exclude list" 1
[ -s "$RSYNC_EXCLUDES" ] || fail "the snapshot exclude list is empty (refusing to stage without credential excludes)" 2
# Leftover partial files of a crashed snapshot are never data: start each run with an empty temp directory.
rm -rf "$STAGE/.rsync-tmp"
say "stage size $(du -sk "$STAGE" 2>/dev/null | cut -f1) KiB"

rate_limit_note() { # rate_limit_note LOG-OFFSET: name a Dropbox write rate limit seen since LOG-OFFSET, and count the
  # other rclone uploads to this remote on the host, which share the account's write budget (the cause on 2026-11-07).
  local from=$(( ${1:-0} + 1 )) others
  tail -c +"$from" "$LOG" 2>/dev/null | grep -Eq 'too_many_write_operations|Too many requests or write operations' || return 0
  # Count only uploads whose words start with this exact remote name, and leave out this script's own copy.
  others=$(ps -axo pid=,command= 2>/dev/null | awk -v remote="${BASE%%:*}:" -v own="$LOG" \
    '$2 ~ /(^|\/)rclone$/ && !index($0, own) {for (i = 3; i <= NF; i++) if (index($i, remote) == 1) {n++; break}} END {print n+0}')
  say "Dropbox write rate limit (too_many_write_operations) during this copy; other rclone uploads running now: $others (see: ps -axo pid,command | grep rclone)"
}

upload() { # upload LOCAL-PATH SRC-REL [extra rclone args]
  local p="$1" rel="$2" dst
  shift 2
  if [ -d "$p" ]; then dst="$R/$rel"; else dst="$R/$(dirname "$rel")"; fi
  args=(copy --dropbox-batch-mode sync --dropbox-batch-size 100 --tpslimit "$TPSLIMIT" --transfers "$TRANSFERS" --checkers 4
    --checksum --retries 3 --retries-sleep 30s --low-level-retries 20 --contimeout 60s --timeout 300s --log-file "$LOG" --log-level NOTICE)
  # A --files-from-raw copy must carry no other filter (rclone refuses the mix): its list was made with the
  # credential excludes and the source filters (bulk_upload). Every other copy gets the credential excludes here.
  case " $* " in *" --files-from-raw "*) ;; *) args+=(--exclude-from "$EXCLUDES" --ignore-case) ;; esac
  args+=("$@")
  if [ "${LOG_BACKUP_VERSIONS:-1}" != 0 ]; then args+=(--backup-dir "$R/versions/$STAMP/$rel"); fi
  local remaining
  # Dropbox can rate-limit (too_many_write_operations): retry the source with a pause before calling it a failure.
  # A source that still fails makes the whole run non-fresh.
  attempt=0 copied=0
  while :; do
    # This copy's share: wall time left, less its own stop and kill grace, less what the later tier-1 sources are
    # promised (RESERVE). It is never under MIN_SLICE; when even that does not fit, the source waits for the next run.
    remaining=$(( WALL_END - $(date +%s) - DEADLINE_GRACE - KILL_GRACE ))
    if [ $remaining -lt $MIN_SLICE ]; then
      say "run time budget (${BUDGET_SECONDS}s) used up before $rel; the next run continues"; ok=1; budget_hit=1; return
    fi
    remaining=$(( remaining - ${RESERVE:-0} )); [ $remaining -ge $MIN_SLICE ] || remaining=$MIN_SLICE
    log_mark=$(wc -c < "$LOG" 2>/dev/null | tr -d ' '); log_mark=${log_mark:-0}
    # rclone's --max-duration does not cut short a Dropbox pacer wait (too_many_write_operations asks for 300 s), so a
    # rate-limited copy overran the budget and later runs slipped past the 15 minute schedule (Mac, 2026-11-07).
    # A watchdog stops this script's own copy DEADLINE_GRACE seconds past its share, and kills it KILL_GRACE seconds
    # later: on SIGTERM rclone commits its pending Dropbox batch with no time limit, which a rate limit can stretch to
    # minutes. Partial progress is kept. Stopping between --backup-dir's move and the upload leaves that one file only
    # under versions/ until the next run (no data is lost); this was already possible with --max-duration.
    "$RCLONE" "${args[@]}" --max-duration "${remaining}s" -- "$p" "$dst" </dev/null &
    copy_pid=$!
    rm -f "$LOGDIR/.log-backup.deadline.$copy_pid"
    # The watchdog ends its own sleep when it is stopped, so no orphan sleep holds the caller's output open; it writes
    # its marker before signalling, so the copy's exit can never be read before the marker exists.
    ( nap=
      trap 'kill ${nap:+"$nap"} 2>/dev/null; exit 0' TERM
      sleep $((remaining + DEADLINE_GRACE)) & nap=$!
      wait "$nap" || exit 0
      touch "$LOGDIR/.log-backup.deadline.$copy_pid"
      kill -TERM "$copy_pid" 2>/dev/null || exit 0
      sleep "$KILL_GRACE" & nap=$!
      wait "$nap" || exit 0
      kill -KILL "$copy_pid" 2>/dev/null ) </dev/null >/dev/null 2>&1 &
    dog_pid=$!
    wait "$copy_pid"; rc=$?
    kill "$dog_pid" 2>/dev/null; wait "$dog_pid" 2>/dev/null
    if [ -e "$LOGDIR/.log-backup.deadline.$copy_pid" ]; then
      rm -f "$LOGDIR/.log-backup.deadline.$copy_pid"
      say "copy of $rel stopped at the run deadline (${remaining}s + ${DEADLINE_GRACE}s grace, killed after ${KILL_GRACE}s more if still running); partial, last-ok withheld"
      rate_limit_note "$log_mark"; ok=1; budget_hit=1; return
    fi
    if [ $rc -eq 0 ]; then copied=1; break; fi
    if [ $rc -eq 8 ] || [ $rc -eq 10 ]; then
      # --max-transfer (8) or --max-duration (10) reached: partial progress is kept, the next run continues.
      say "budget reached for $rel (rclone exit $rc); partial, last-ok withheld"; rate_limit_note "$log_mark"; ok=1; budget_hit=1; return
    fi
    attempt=$((attempt + 1))
    [ $attempt -le "${LOG_BACKUP_RETRIES:-2}" ] || break
    say "copy of $rel failed; retry $attempt after ${LOG_BACKUP_RETRY_SLEEP:-30}s (file changed mid-copy or rate limit)"
    sleep "${LOG_BACKUP_RETRY_SLEEP:-30}"
  done
  if [ $copied -eq 1 ]; then
    found=$((found + 1))
    case "$rel" in .claude/projects|.codex/sessions)
      # An empty primary tree is not evidence of a backup.
      # (judged on the live tree: a stage that still holds deleted files must not count)
      if [ -n "$(find "$HOME/$rel" -type f -print -quit 2>/dev/null)" ]; then primary=$((primary + 1)); fi ;;
    esac
  else
    say "copy failed after $attempt attempts: $rel"; rate_limit_note "$log_mark"; ok=1; hard_fail=1
  fi
}

# Bulk sources are far too large for one run (Mac 2026-11-07: 620k files in the work tree, about 7 minutes of copy
# time per run). A fresh copy re-checked the same first files every run and never got further (goodqa#15062), so
# a bulk pass is a generation with a checkpoint under $BULK_STATE/KEY:
#   pending  the files of this generation still to send (path, size, mtime), listed once when it starts
#   cursor   how many pending lines are verified; a copy of the next BULK_CHUNK lines that exits 0 advances it
#   done     the files verified by earlier generations; a new generation lists only new or changed files
# A run resumes at the cursor. A chunk cut short is sent again whole (rclone skips what already arrived). When the
# cursor reaches the end, the generation's whole listing becomes the new `done` (dropping deleted files) and the
# source counts as complete. Every list is made with the same filters as the copy, credential excludes included.
BULK_STATE="$LOGDIR/log-backup.bulk.d"
bulk_key() { printf '%s' "$1" | tr '/' '_'; }
bulk_needs_listing() { # bulk_needs_listing SRC-REL: true when no generation is in progress for SRC-REL
  local st="$BULK_STATE/$(bulk_key "$1")"
  [ -s "$st/pending" ] && [ "$(cat "$st/remote" 2>/dev/null)" = "$R" ] && return 1
  return 0
}
bulk_upload() { # bulk_upload SRC-REL [filter args...] -- [copy args...]: one checkpointed pass; 0 when finished
  local rel="$1" st n cur total chunk
  shift
  local list_filters=() copy_args=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do list_filters+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  copy_args=("$@")
  st="$BULK_STATE/$(bulk_key "$rel")"
  mkdir -p "$st" && chmod 700 "$BULK_STATE" "$st" || { say "cannot create bulk state for $rel"; ok=1; hard_fail=1; return 1; }
  # A checkpoint belongs to one destination: another remote or host starts over.
  if [ "$(cat "$st/remote" 2>/dev/null)" != "$R" ]; then
    rm -f "$st/pending" "$st/cursor" "$st/done" "$st/listing" && printf '%s\n' "$R" > "$st/remote"
  fi
  if [ ! -s "$st/pending" ]; then
    local filters=(--exclude-from "$EXCLUDES" --ignore-case "${list_filters[@]+"${list_filters[@]}"}")
    "$RCLONE" lsf -R --files-only --format pst --separator $'\t' "${filters[@]}" -- "$HOME/$rel" \
      </dev/null > "$st/listing.tmp" 2>> "$LOG"
    rc=$?
    if [ $rc -ne 0 ]; then say "listing $rel failed (rclone exit $rc)"; ok=1; hard_fail=1; rm -f "$st/listing.tmp"; return 1; fi
    # Exactly three fields: a path with a tab or a newline cannot be checkpointed safely and is left to the next
    # full listing (it is counted, so it is never silently dropped).
    awk -F'\t' 'NF != 3 {bad++} END {print bad + 0}' "$st/listing.tmp" > "$st/odd"
    awk -F'\t' 'NF == 3' "$st/listing.tmp" > "$st/listing" && rm -f "$st/listing.tmp"
    touch "$st/done"
    awk -F'\t' 'FILENAME == ARGV[1] {seen[$0] = 1; next} !($0 in seen)' "$st/done" "$st/listing" > "$st/pending.tmp" \
      && mv "$st/pending.tmp" "$st/pending" && echo 0 > "$st/cursor" || { say "cannot build the $rel checkpoint"; ok=1; hard_fail=1; return 1; }
    [ "$(cat "$st/odd")" = 0 ] || say "$rel: $(cat "$st/odd") paths with a tab or newline are not checkpointed"
    say "$rel: new pass, $(wc -l < "$st/pending" | tr -d ' ') of $(wc -l < "$st/listing" | tr -d ' ') files new or changed"
  fi
  total=$(wc -l < "$st/pending" | tr -d ' ')
  cur=$(cat "$st/cursor" 2>/dev/null)
  printf '%s' "$cur" | grep -Eq '^(0|[1-9][0-9]*)$' || cur=0
  while [ "$cur" -lt "$total" ]; do
    sed -n "$((cur + 1)),$((cur + BULK_CHUNK))p;$((cur + BULK_CHUNK))q" "$st/pending" > "$st/chunk"
    n=$(wc -l < "$st/chunk" | tr -d ' ')
    cut -f1 "$st/chunk" > "$st/chunk.paths"
    upload "$HOME/$rel" "$rel" "${copy_args[@]+"${copy_args[@]}"}" --files-from-raw "$st/chunk.paths" --no-traverse
    [ "$copied" -eq 1 ] || { say "$rel: pass at $cur of $total files; the next run resumes there"; return 1; }
    cur=$((cur + n))
    echo "$cur" > "$st/cursor.tmp" && mv "$st/cursor.tmp" "$st/cursor"
  done
  # Close the generation: drop pending first, so a crash or a failed step here can only make the next run list
  # again (and re-verify against the old `done`), never leave a finished pending that every later run reports as
  # complete without listing new files (PR #123 review L1).
  rm -f "$st/pending" "$st/cursor" "$st/chunk" "$st/chunk.paths" || { say "cannot close the $rel checkpoint"; ok=1; hard_fail=1; return 1; }
  if [ -f "$st/listing" ]; then
    mv "$st/listing" "$st/done" || { say "cannot record the $rel pass; the next run lists it again"; ok=1; hard_fail=1; return 1; }
  else
    say "$rel: the pass listing is missing; the next run lists it again"
    ok=1
    return 1
  fi
  say "$rel: pass complete ($total files sent or verified)"
  return 0
}

later=0
for src in "${LIVE[@]}"; do [ -e "$HOME/$src" ] && later=$((later + 1)); done
for src in "${LIVE[@]}"; do
  [ -e "$HOME/$src" ] || [ -L "$HOME/$src" ] || continue
  later=$((later - 1)); [ $later -ge 0 ] || later=0
  # A later copy that hangs costs its slice, both graces and about 3 s to snapshot the source first.
  RESERVE=$(( later * (MIN_SLICE + DEADLINE_GRACE + KILL_GRACE + 3) ))
  if [ -L "$HOME/$src" ]; then say "refusing symlinked source root: $src"; ok=1; continue; fi
  snap="$STAGE/$src"
  mkdir -p "$(dirname "$snap")" || { say "cannot stage $src"; ok=1; continue; }
  if [ -d "$HOME/$src" ]; then
    # rsync -a keeps symlinks as links; rclone never follows them. Exit 24 = a file vanished mid-copy (not an error).
    # --temp-dir sits outside every uploaded tree: a crash mid-copy leaves its partial files there, never beside data
    # that rclone would upload as current. rsync renames within the stage volume, so a full disk fails the copy
    # (exit 11 or 23, source skipped, run non-fresh) instead of leaving a truncated file in place.
    # The trash directory is pruned before the catch-all directory include below (first rsync rule wins), at any depth (B7).
    mkdir -p "$STAGE/.rsync-tmp" || { say "cannot create the stage temp directory"; ok=1; continue; }
    rsync -a --temp-dir="$STAGE/.rsync-tmp" --exclude='.[gG][oO][oO][dD][qQ][aA]-[tT][rR][aA][sS][hH]/' --include='*/' --exclude-from="$RSYNC_EXCLUDES" -- "$HOME/$src/" "$snap/" </dev/null; rc=$?
    if [ $rc -eq 23 ]; then
      # Partial transfer (e.g. one unreadable file): rsync renames files into place, so the stage is consistent.
      # Back up what was staged, but withhold last-ok for this run.
      say "snapshot partial (rsync exit 23): $src"; ok=1
    elif [ $rc -ne 0 ] && [ $rc -ne 24 ]; then
      say "snapshot failed (rsync exit $rc): $src"; ok=1; continue
    fi
  else
    cp -p "$HOME/$src" "$snap" || { say "snapshot failed: $src"; ok=1; continue; }
  fi
  upload "$snap" "$src"
done
# Tier 1 (transcripts, WALs, ledgers) is done: mark it on its own, so a slow bulk pass can never hide a gap here.
[ $primary -gt 0 ] || { say "no primary source (.claude/projects or .codex/sessions) was copied"; ok=1; }
say "transcripts exit=$ok sources=$found remote=${R%%:*}"
transcripts_ok=$ok
if [ $ok -eq 0 ]; then
  echo "$STARTED sources=$found remote=${R%%:*}" > "$LOGDIR/log-backup.last-ok.tmp.$$" \
    && mv "$LOGDIR/log-backup.last-ok.tmp.$$" "$LOGDIR/log-backup.last-ok"
fi
ok=0
# Tier 2 runs at most once per BULK_EVERY seconds: its marker allows 6 hours, and transcripts must not wait behind it.
bulk_ran=1 sources_bulk=("${DIRECT[@]}")
bulk_try="$LOGDIR/log-backup.bulk-last-try"
if [ -e "$bulk_try" ]; then
  bulk_age=$(raw_age "$bulk_try")
  if [ -n "$bulk_age" ] && [ "$bulk_age" -ge 0 ] && [ "$bulk_age" -lt "$BULK_EVERY" ]; then
    bulk_ran=0 sources_bulk=()
    say "bulk tier skipped: last attempt ${bulk_age}s ago (every ${BULK_EVERY}s)"
  fi
fi
# Copy time left before a source would be told the budget is used up (the same test upload makes).
time_left() { echo $(( WALL_END - $(date +%s) - DEADLINE_GRACE - KILL_GRACE )); }
# Mac 2026-11-07: tier 1 used the whole budget, so every hourly bulk attempt copied nothing, failed the run and still
# spent the hour. With no time left the tier is deferred instead: not an attempt, no failure, the next run tries it.
if [ $bulk_ran -eq 1 ] && [ ${#sources_bulk[@]} -gt 0 ] && [ "$(time_left)" -lt "$MIN_SLICE" ]; then
  bulk_ran=0 sources_bulk=()
  say "bulk tier deferred: no run time left after tier 1; the next run with time left tries it"
fi
[ $bulk_ran -eq 1 ] && : > "$bulk_try"
RESERVE=0 budget_hit=0 hard_fail=0
# The git-tree scan of the work tree is not time-bounded (26 s on the Mac, 301 trees, warm cache). It starts only when
# the last measured scan time plus a copy slice still fits, so a short remainder is not spent scanning every run.
scan_file="$LOGDIR/log-backup.work-scan-seconds"
scan_need=$(cat "$scan_file" 2>/dev/null)
printf '%s' "$scan_need" | grep -Eq '^(0|[1-9][0-9]{0,4})$' || scan_need=60
# One slow scan (cold cache, launchd's low priority) must not lock the work tree out for good: the measurement is only
# rewritten when a scan runs, so it is capped at half the budget and a run with most of its time free always scans.
[ "$scan_need" -le $(( BUDGET_SECONDS / 2 )) ] || scan_need=$(( BUDGET_SECONDS / 2 ))
for src in "${sources_bulk[@]+"${sources_bulk[@]}"}"; do
  [ -e "$HOME/$src" ] || [ -L "$HOME/$src" ] || continue
  if [ -L "$HOME/$src" ]; then say "refusing symlinked source root: $src"; ok=1; hard_fail=1; continue; fi
  extra=(--min-age 2m)
  if [ "$src" = .agent-harness/work ] && bulk_needs_listing "$src" && [ "$(time_left)" -lt $(( MIN_SLICE + scan_need )) ]; then
    say "run time budget (${BUDGET_SECONDS}s) used up before $src (its scan needs about ${scan_need}s); the next run continues"
    ok=1; budget_hit=1; continue
  fi
  if [ "$src" = .agent-harness/work ]; then
    scan_start=$(date +%s)
    # The work tree holds git worktrees, checkouts, screenshots and mutation trees (hundreds of GB). Back up only
    # the small durable state: skip every directory that has a .git entry, media files, and files over the size cap.
    gen="$LOGDIR/log-backup.worktrees.excludes"
    if bulk_needs_listing "$src"; then
    : > "$gen"
    unsafe=0
    while IFS= read -r -d '' g; do
      d=${g%/.git}; rel=${d#"$HOME/$src"}
      if [ -z "$rel" ]; then printf '/.git/**\n' >> "$gen"; continue; fi   # the work root is itself a checkout
      case "$rel" in
        *[\\*?\[\]{}]*|*$'\n'*|*$'\r'*) unsafe=$((unsafe + 1)); continue ;;   # cannot be written as a safe pattern
      esac
      printf '%s/**\n' "$rel" >> "$gen"
    done < <(find "$HOME/$src" -xdev -maxdepth 12 -name .git -prune -print0 2>/dev/null)
    echo $(( $(date +%s) - scan_start )) > "$scan_file"
    say "work: $(wc -l < "$gen" | tr -d ' ') git trees excluded, $unsafe with unsafe names left in (uploaded)"
    fi
    extra+=(--exclude-from "$WORK_EXCLUDES" --exclude-from "$gen" --max-size "${LOG_BACKUP_WORK_MAX_SIZE:-25M}"
            -- --max-transfer "${LOG_BACKUP_WORK_MAX_TRANSFER:-5G}")
  fi
  bulk_upload "$src" "${extra[@]}"
done
# Tier 2 (bulk: archived sessions and the narrowed work tree) has its own marker.
bulk_ok=$ok
[ $bulk_ran -eq 1 ] && say "bulk exit=$bulk_ok"
if [ $bulk_ran -eq 1 ] && [ $budget_hit -eq 1 ] && [ $hard_fail -eq 0 ]; then
  # A pass cut short by the run budget is not finished: the next run continues it instead of waiting BULK_EVERY.
  # A pass where any source really failed (a rate limit that outlasted its retries, say) keeps the hourly gap.
  rm -f "$bulk_try"
  say "bulk tier stopped on the run budget; the next run continues it"
fi
if [ $bulk_ok -eq 0 ] && [ $bulk_ran -eq 1 ]; then
  echo "$STARTED" > "$LOGDIR/log-backup.bulk-last-ok.tmp.$$" \
    && mv "$LOGDIR/log-backup.bulk-last-ok.tmp.$$" "$LOGDIR/log-backup.bulk-last-ok"
fi
rc=0
{ [ $transcripts_ok -eq 0 ] && [ $bulk_ok -eq 0 ]; } || rc=1
echo "$STARTED exit=$rc transcripts=$transcripts_ok bulk=$bulk_ok" > "$LOGDIR/log-backup.last-run"
exit $rc
