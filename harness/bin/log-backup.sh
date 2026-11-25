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
#   LOG_BACKUP_STAGE_ENGINE auto (default): snapshot live files with APFS clonefile (`cp -c`) or GNU
#                           `cp --reflink=always` when a probe on the stage volume shows they do not use a
#                           second allocation; otherwise rsync as a full copy. `clone` requires that engine.
#                           `rsync` forces a full copy. Live files are never hardlinked: an append would
#                           change the snapshot mid-upload and Dropbox would reject the hash.
#   LOG_BACKUP_STAGE_MIN_FREE_GIB  skip a full-copy snapshot when free space on the stage volume is below
#                           this many GiB (default 20). Clonefile/reflink snapshots still run. 0 disables.
#   LOG_BACKUP_STAGE_KEEP   exactly 0 removes each staged source after its upload returns. The default
#                           leaves the stage in place: clonefile snapshots share extents with the source
#                           (so they do not take a second allocation), and a full-copy fallback stays
#                           incremental. A first clone pass replaces leftover full copies with clones.
#   LOG_BACKUP_STAGE_MAX_PLACE  optional cap on file/symlink placements per source in the clone loop
#                           (unset or 0: no cap). Hitting the cap is treated like the run deadline:
#                           last-ok is withheld and the next run resumes from files not yet staged.
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
#   LOG_BACKUP_BULK_CHUNK   files per checkpointed bulk copy (default 300 in the lane run, 100 otherwise, 1-99999),
#                           never more than fit the time left at about 2 rate-limited operations a file
#   LOG_BACKUP_BULK_LANE    exactly 1 runs the bulk tier as its own detached run (the bulk lane), so tier 1 can no
#                           longer use up the bulk tier's time. The lane yields to tier 1 (goodqa#15147): it never
#                           copies while a tier-1 run holds the run lock, and a copy in flight when one starts is
#                           stopped and its chunk sent again later. Tier 1 always copies at the full TPSLIMIT. The
#                           launchd plist leaves it off (0) until three tier-1 runs in a row finish inside the budget.
#   LOG_BACKUP_BUDGET_FILE  the shared Dropbox budget (default ~/.claude/hooks/dropbox_budget.conf, goodqa#15218):
#                           its log-backup.<host> share is the rate when LOG_BACKUP_TPSLIMIT is unset, else a ceiling
#   LOG_BACKUP_BULK_TPS     the lane's rate (default TPSLIMIT, 1-99, never more than TPSLIMIT)
#   LOG_BACKUP_LANE_POLL_SECONDS  how often a lane copy checks for a tier-1 run (default 2, 1-60)
#   LOG_BACKUP_LANE_BUDGET_SECONDS  wall time of one lane run (default 10800); the next scheduled run starts another
#   LOG_BACKUP_TIER         internal: bulk marks the lane run itself; nothing else may set it
# Freshness contract, two tiers with their own markers. Each tier-1 source (transcripts, WALs, ledgers) has its own
# marker in log-backup.src.d, the START time of the run whose snapshot of it was sent in full (a staged tree is sent as
# a checkpointed pass that may span runs). log-backup.last-ok is written atomically with the oldest of those once every
# present tier-1 source has one and a primary source (.claude/projects or .codex/sessions) with files is among them. log-backup.bulk-last-ok (archived sessions, narrowed work tree)
# is written only after every tier-2 source copied cleanly. A run skipped because another run holds the lock writes
# log-backup.last-skip and touches neither marker. With the lane on, the lane run writes bulk-last-ok and its own
# log-backup.lane.last-run; the scheduled run's last-run then reads bulk=lane.
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
TRANSFERS=${LOG_BACKUP_TRANSFERS:-2}     # keep each host's share small (all hosts together stay near 3/s)
BULK_EVERY=${LOG_BACKUP_BULK_EVERY_SECONDS:-3600}   # the bulk tier (work tree, archives) runs hourly, transcripts every time
JITTER=${LOG_BACKUP_JITTER_SECONDS:-0}   # random start delay so hosts on the same schedule do not collide
SLICE_RESERVE=${LOG_BACKUP_SLICE_RESERVE_SECONDS:-20}  # the least copy time each later tier-1 source is promised
DEADLINE_GRACE=${LOG_BACKUP_DEADLINE_GRACE_SECONDS:-10}  # a copy still running this long past its share gets SIGTERM
KILL_GRACE=${LOG_BACKUP_KILL_GRACE_SECONDS:-10}  # and SIGKILL this long after that (rclone drains batches on TERM)
PERIOD=${LOG_BACKUP_PERIOD_SECONDS:-900}  # the schedule interval: a run, start delay included, ends before the next one
LANE=${LOG_BACKUP_BULK_LANE:-0}          # 1: the bulk tier runs as its own detached run beside tier 1 (goodqa#15062)
BULK_TPS=${LOG_BACKUP_BULK_TPS:-$TPSLIMIT}   # the lane's rate; it never copies beside tier 1, so no split
LANE_POLL=${LOG_BACKUP_LANE_POLL_SECONDS:-2}
LANE_BUDGET=${LOG_BACKUP_LANE_BUDGET_SECONDS:-10800}
TIER=${LOG_BACKUP_TIER:-all}             # all: both tiers in this run; live: tier 1 only; bulk: the lane run
for rate in TPSLIMIT TRANSFERS BULK_TPS; do
  if ! printf '%s' "${!rate}" | grep -Eq '^[1-9][0-9]?$'; then
    echo "log-backup: $rate must be a whole number from 1 to 99" >&2; exit 2
  fi
done
# One write budget for the whole Dropbox account (goodqa#15218): this host's share in the budget file caps TPSLIMIT.
# A missing or invalid file, or one without a share for this host, leaves today's value (LOG_BACKUP_TPSLIMIT or 1).
BUDGET_FILE=${LOG_BACKUP_BUDGET_FILE:-$HOME/.claude/hooks/dropbox_budget.conf}
# The line rule is the one heavy_job_guard.budget_shares applies (keep the two in step).
budget_share=
if [ ! -L "$BUDGET_FILE" ] && [ -f "$BUDGET_FILE" ] && [ "$(wc -c < "$BUDGET_FILE" 2>/dev/null)" -le 65536 ]; then
  budget_share=$(LC_ALL=C awk -v want="log-backup.$HOST" '
    {sub(/\r$/, "")}
    /^[ \t]*(#.*)?$/ {next}
    $0 !~ /^[A-Za-z0-9._-]+[ \t]+[1-9][0-9]?[ \t]*$/ || ($1 in v) {bad = 1; next}
    {v[$1] = $2 + 0; if ($1 != "account") sum += $2}
    END {if (bad || !("account" in v) || sum > v["account"] || !(want in v)) exit 1; print v[want]}' "$BUDGET_FILE") \
    || budget_share=
  [ -n "$budget_share" ] || echo "log-backup: no valid share for log-backup.$HOST in $BUDGET_FILE; using LOG_BACKUP_TPSLIMIT ($TPSLIMIT)" >&2
fi
if [ -n "$budget_share" ]; then
  if [ -z "${LOG_BACKUP_TPSLIMIT:-}" ] || [ "$budget_share" -lt "$TPSLIMIT" ]; then TPSLIMIT=$budget_share; fi
  [ -n "${LOG_BACKUP_BULK_TPS:-}" ] || BULK_TPS=$TPSLIMIT
fi
BULK_CHUNK=${LOG_BACKUP_BULK_CHUNK:-}
[ -z "$BULK_CHUNK" ] || printf '%s' "$BULK_CHUNK" | grep -Eq '^[1-9][0-9]{0,4}$' || { echo "log-backup: LOG_BACKUP_BULK_CHUNK must be 1-99999" >&2; exit 2; }
for numeric in BUDGET_SECONDS LOG_BACKUP_RETRIES LOG_BACKUP_RETRY_SLEEP BULK_EVERY JITTER DEADLINE_GRACE SLICE_RESERVE KILL_GRACE PERIOD LANE_BUDGET LANE_POLL; do
  # No leading zeros: bash would read 08 as octal and abort the arithmetic.
  if ! printf '%s' "${!numeric:-0}" | grep -Eq '^(0|[1-9][0-9]{0,4})$'; then
    echo "log-backup: $numeric must be a whole number of at most 5 digits without leading zeros" >&2; exit 2
  fi
done
STAGE_ENGINE=${LOG_BACKUP_STAGE_ENGINE:-auto}
case "$STAGE_ENGINE" in auto|clone|rsync) ;; *) echo "log-backup: LOG_BACKUP_STAGE_ENGINE must be auto, clone or rsync" >&2; exit 2 ;; esac
STAGE_MIN_FREE_GIB=${LOG_BACKUP_STAGE_MIN_FREE_GIB:-20}
if ! printf '%s' "$STAGE_MIN_FREE_GIB" | grep -Eq '^(0|[1-9][0-9]{0,2})$'; then
  echo "log-backup: LOG_BACKUP_STAGE_MIN_FREE_GIB must be a whole number 0-999 without leading zeros" >&2; exit 2
fi
STAGE_MAX_PLACE=${LOG_BACKUP_STAGE_MAX_PLACE:-0}
if ! printf '%s' "$STAGE_MAX_PLACE" | grep -Eq '^(0|[1-9][0-9]{0,4})$'; then
  echo "log-backup: LOG_BACKUP_STAGE_MAX_PLACE must be a whole number 0-99999 without leading zeros" >&2; exit 2
fi
case "$LANE" in 0|1) ;; *) echo "log-backup: LOG_BACKUP_BULK_LANE must be 0 or 1" >&2; exit 2 ;; esac
case "$TIER" in
  all) ;;
  bulk) [ "$LANE" = 1 ] || { echo "log-backup: LOG_BACKUP_TIER=bulk is the lane run; it needs LOG_BACKUP_BULK_LANE=1" >&2; exit 2; } ;;
  *) echo "log-backup: LOG_BACKUP_TIER is internal (only bulk, set by the lane itself)" >&2; exit 2 ;;
esac
[ "$LANE_BUDGET" -le 43200 ] || { echo "log-backup: LOG_BACKUP_LANE_BUDGET_SECONDS must be at most 43200 (a lock over a day old is taken over)" >&2; exit 2; }
[ "$LANE_POLL" -ge 1 ] && [ "$LANE_POLL" -le 60 ] || { echo "log-backup: LOG_BACKUP_LANE_POLL_SECONDS must be 1-60" >&2; exit 2; }
if [ "$BULK_TPS" -gt "$TPSLIMIT" ]; then   # never above the host's budget; tier 1 must not stop over a lane setting
  [ "$LANE" != 1 ] || echo "log-backup: LOG_BACKUP_BULK_TPS ($BULK_TPS) is above LOG_BACKUP_TPSLIMIT; the lane uses $TPSLIMIT" >&2
  BULK_TPS=$TPSLIMIT
fi
if [ "$LANE" = 1 ]; then
  # The lane yields to tier 1 instead of splitting the budget (goodqa#15147): the two never copy at the same time, so
  # tier 1 keeps the full rate for its 13 minutes and the lane uses the time tier 1 leaves.
  if [ "$TIER" = bulk ]; then TPSLIMIT=$BULK_TPS; else TIER=live; fi
fi
# Lane chunks are small enough that one cut short by a tier-1 run costs little to send again (goodqa#15147).
[ -n "$BULK_CHUNK" ] || { if [ "$TIER" = bulk ]; then BULK_CHUNK=300; else BULK_CHUNK=100; fi; }
# The lane run keeps its own run marker, watchdog markers and log prefix, so the two runs never clear each other's.
TAG= SAY_TAG=
[ "$TIER" = bulk ] && TAG=.lane SAY_TAG="[lane] "
LASTRUN="$LOGDIR/log-backup${TAG}.last-run"
LOG="$LOGDIR/log-backup${TAG}.log"
LANE_LOCKD="$LOGDIR/log-backup.lane.lock.d"   # held by whichever run uses the bulk checkpoint (lane or all)
LANE_STATE="$LOGDIR/log-backup.lane.state"    # the lane's "copying PID" or "idle PID" (goodqa#15147)
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
say() { printf '%s %s%s\n' "$(date -u +%FT%TZ)" "$SAY_TAG" "$1" >> "$LOG"; }
fail() { say "$1"; echo "log-backup: $1" >&2; echo "$STARTED exit=$2" > "$LASTRUN"; exit "$2"; }

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
  args=$(ps -p "$1" -o args= 2>/dev/null) || return 0   # ps refused (a sandbox): never take a live pid's lock
  first=${args%% *}; rest=${args#* }
  [ "$rest" != "$args" ] || return 1
  case "$first" in sh|bash|dash|zsh|*/sh|*/bash|*/dash|*/zsh) ;; *) return 1 ;; esac
  case "$rest" in -*) return 1 ;; esac
  case "$rest" in *log-backup.sh) return 0 ;; esac
  return 1
}

acquire_lock() { # acquire_lock [LOCK-DIR]: the run lock by default
  local lockd=${1:-$LOCKD}
  if mkdir "$lockd" 2>/dev/null; then echo $$ > "$lockd/pid"; return 0; fi
  local holder age
  holder=$(cat "$lockd/pid" 2>/dev/null)
  age=$(file_age "$lockd")
  if [ -n "$holder" ]; then
    holder_alive "$holder" && [ "$age" -lt $STALE_LOCK_SECONDS ] && return 1
  elif [ "$age" -lt $STALE_LOCK_SECONDS ]; then
    # No pid file: the owner has not written it yet, or the lock belongs to the older hand-installed script (same
    # lock.d directory, no pid). Never take that over while it is young; its owner stops it, or it ages out.
    return 1
  fi
  # Stale. Takeovers are serialized by a second mkdir guard, so two runners cannot both judge the same lock and
  # one of them move the other's fresh lock. A guard left by a crashed takeover expires after 5 minutes.
  local guard="$lockd.takeover"
  if ! mkdir "$guard" 2>/dev/null; then
    [ "$(file_age "$guard")" -gt 300 ] || return 1
    rmdir "$guard" 2>/dev/null; mkdir "$guard" 2>/dev/null || return 1
  fi
  if [ -d "$lockd" ] && [ "$(cat "$lockd/pid" 2>/dev/null)" != "$holder" ]; then
    rmdir "$guard" 2>/dev/null  # the lock changed hands while we waited for the guard: it is not stale any more
    return 1
  fi
  say "taking over stale lock (holder=${holder:-none} age=${age}s)"
  local gone="$lockd.stale.$$" got=1
  if mv "$lockd" "$gone" 2>/dev/null; then
    rm -f "$gone/pid"; rmdir "$gone" 2>/dev/null
  fi
  if mkdir "$lockd" 2>/dev/null; then echo $$ > "$lockd/pid"; got=0; fi
  rmdir "$guard" 2>/dev/null
  return $got
}

[ "$JITTER" -gt 0 ] && [ "$TIER" != bulk ] && sleep $((RANDOM % (JITTER + 1)))   # the lane starts after its parent's delay
RUN_START=$(date +%s)   # the budget is for copying: the start delay must not spend it (2026-11-07)
# One wall-clock deadline for every copy, its stop and its kill: the budget after the start delay, but never past the
# next scheduled start (less 30 s to write the markers), so a long delay shrinks the copying time instead.
WALL_END=$(( RUN_START + BUDGET_SECONDS ))
[ $(( SCRIPT_START + PERIOD - 30 )) -ge $WALL_END ] || WALL_END=$(( SCRIPT_START + PERIOD - 30 ))
# The lane run has its own budget and no schedule slot to fit: the scheduled run that started it keeps that slot.
[ "$TIER" = bulk ] && WALL_END=$(( RUN_START + LANE_BUDGET ))
MIN_SLICE=$SLICE_RESERVE; [ "$MIN_SLICE" -ge 1 ] || MIN_SLICE=1
# Copy time left before a source would be told the budget is used up (the same test upload makes).
time_left() { echo $(( WALL_END - $(date +%s) - DEADLINE_GRACE - KILL_GRACE )); }
release_locks() { local d; for d in "$@"; do [ "$(cat "$d/pid" 2>/dev/null)" = "$$" ] && { rm -f "$d/pid"; rmdir "$d" 2>/dev/null; }; done; }
if [ "$TIER" = bulk ]; then
  if legacy_run_active || ! acquire_lock "$LANE_LOCKD"; then
    say "bulk lane: another run holds the bulk checkpoint; this lane run exits"
    exit 0
  fi
  echo "idle $$" > "$LANE_STATE.tmp.$$" && mv "$LANE_STATE.tmp.$$" "$LANE_STATE"   # a lane that yields (goodqa#15147)
  echo $$ > "$LOGDIR/log-backup.lane.started"   # the run that started this lane waits for this line
elif legacy_run_active || ! acquire_lock; then
  say "skipped: another backup run holds the lock (this is not a successful backup)"
  date -u +%FT%TZ > "$LOGDIR/log-backup.last-skip"
  exit 0
fi
lane_clear_state() { [ "$TIER" = bulk ] && [ "$(cut -d' ' -f2 "$LANE_STATE" 2>/dev/null)" = "$$" ] && rm -f "$LANE_STATE"; return 0; }
trap 'release_locks "$LOCKD" "$LANE_LOCKD"; lane_clear_state' EXIT
copy_pid= dog_pid= nap_pid=
nap() { sleep "$1" & nap_pid=$!; wait "$nap_pid"; nap_pid=; }   # a pause a signal can interrupt (and stop)
on_term() {
  # rclone commits its pending batch on TERM: wait for it up to KILL_GRACE, then kill it, and only then release the
  # lock, so the next run never starts a copy beside one still committing (PR #124 delta review N2).
  local waited=0
  [ -z "$dog_pid" ] || kill -TERM "$dog_pid" 2>/dev/null
  [ -z "$nap_pid" ] || kill -TERM "$nap_pid" 2>/dev/null
  if [ -n "$copy_pid" ]; then
    kill -TERM "$copy_pid" 2>/dev/null
    while kill -0 "$copy_pid" 2>/dev/null && [ $waited -lt $(( KILL_GRACE * 5 )) ]; do sleep 0.2; waited=$((waited + 1)); done
    kill -KILL "$copy_pid" 2>/dev/null
  fi
  say "stopped by a signal; this run's copy was stopped first"
  exit 143
}
trap on_term TERM INT
# A watchdog that outlived a killed run can leave its marker; with the lock held, none of this tier's is current.
rm -f "$LOGDIR"/.log-backup${TAG}.deadline.* "$LOGDIR"/.log-backup${TAG}.yield.* 2>/dev/null

command -v "$RCLONE" >/dev/null 2>&1 || fail "rclone not found (set LOG_BACKUP_RCLONE or fix PATH)" 127
[ -r "$WORK_EXCLUDES" ] || fail "work exclude file missing: $WORK_EXCLUDES" 2
[ -r "$EXCLUDES" ] || fail "exclude file missing: $EXCLUDES (refusing to run without credential excludes)" 2
for anchor in auth.json rclone.conf member.key '*.secret' '.env'; do
  grep -qxF -- "$anchor" "$EXCLUDES" || fail "exclude file lacks required pattern $anchor (refusing to run)" 2
done
# A bulk checkpoint is listed with these filters; when either list changes, the pass in progress is listed again.
filter_id() { cat -- "$EXCLUDES" "$WORK_EXCLUDES" | cksum | tr -s ' \t' '-'; }
FILTER_ID=$(filter_id) || fail "cannot read the exclude lists" 2
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

ok=0 found=0 primary=0 throttled=0 throttle_src=
STAGE=${LOG_BACKUP_STAGE:-$HOME/.agent-harness/backup-stage}
# Live sources (transcripts and WALs grow while uploaded, so Dropbox's hash check would fail) are snapshotted into a
# local stage first and uploaded from there. Static sources upload in place, skipping files younger than 2 minutes.
# Smallest first, .claude/projects last (goodqa#15044 N2): the single files and the WAL tree finish in seconds, and
# the large, always-changing transcript tree then gets all the time that is left instead of a fixed early share.
LIVE=(.claude/history.jsonl .codex/history.jsonl .agent-harness/work-assignments.json .agent-harness/work-ledger.json
  .agent-harness/work-ledger.events.jsonl .agent-harness/work-ledger.archive.jsonl .agent-harness/work-ledger.failures.jsonl
  .agent-harness/work-ledger.spool.jsonl .claude/wals .codex/sessions .claude/projects)
DIRECT=(.codex/archived_sessions .agent-harness/work)
if [ "$TIER" != bulk ]; then   # the stage belongs to tier 1: the lane run must never rebuild or clear it mid-snapshot
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
STAGE_CLONE=0
STAGE_CLONE_KIND=
RSYNC_8=
rsync -h 2>&1 | grep -q -- "--8-bit-output" && RSYNC_8=--8-bit-output
stage_free_kib() { # POSIX df: available 1K-blocks on the stage volume
  df -kP "$STAGE" 2>/dev/null | awk 'NR==2 {print $4}'
}
stage_same_inode() { # 0 when $1 and $2 are the same inode (a hardlink, unsafe for live files)
  local a b
  a=$(stat -f %d:%i "$1" 2>/dev/null || stat -c %d:%i "$1" 2>/dev/null) || return 1
  b=$(stat -f %d:%i "$2" 2>/dev/null || stat -c %d:%i "$2" 2>/dev/null) || return 1
  [ -n "$a" ] && [ "$a" = "$b" ]
}
stage_dev() { stat -f %d "$1" 2>/dev/null || stat -c %d "$1" 2>/dev/null; }
stage_same_volume() { # 0 when $1 and $2 are on the same device (cp -c otherwise falls back to a full copy)
  local a b
  a=$(stage_dev "$1") || return 1
  b=$(stage_dev "$2") || return 1
  [ -n "$a" ] && [ "$a" = "$b" ]
}
stage_path_plain() { # 0 when $1 is STAGE or a path under it and no component from STAGE down is a symlink
  local p="$1" cur rel part
  [ -n "$p" ] && [ -n "$STAGE" ] || return 1
  [ ! -L "$STAGE" ] || return 1
  [ "$p" = "$STAGE" ] && return 0
  case "$p" in "$STAGE"/*) ;; *) return 1 ;; esac
  cur="$STAGE"
  rel="${p#"$STAGE"/}"
  while [ -n "$rel" ]; do
    part="${rel%%/*}"
    if [ "$part" = "$rel" ]; then rel=; else rel="${rel#*/}"; fi
    [ -n "$part" ] || continue
    cur="$cur/$part"
    [ -L "$cur" ] && return 1
    [ -e "$cur" ] || return 0
  done
  return 0
}
stage_physical_under_stage() { # 0 when the physical directory of $1 sits under the physical stage
  local phys_stage phys_dir target="$1"
  phys_stage=$(cd -P "$STAGE" 2>/dev/null && pwd -P) || return 1
  if [ -d "$target" ] && [ ! -L "$target" ]; then
    phys_dir=$(cd -P "$target" 2>/dev/null && pwd -P) || return 1
  else
    phys_dir=$(cd -P "$(dirname "$target")" 2>/dev/null && pwd -P) || return 1
  fi
  case "$phys_dir" in "$phys_stage"|"$phys_stage"/*) return 0 ;; esac
  return 1
}
stage_dest_safe() { # 0 when writes or removals of $1 cannot escape the stage through a symlink
  stage_path_plain "$1" && stage_physical_under_stage "$1"
}
stage_path_unused() { # 0 when no rclone/rsync command line is using $1 (do not kill those processes)
  local p="$1" proc pids extra
  # Only look at rclone/rsync (and LOG_BACKUP_RCLONE's basename) pids. -ww: macOS truncates args without a tty.
  # A false match leaves the path in place rather than deleting under a reader.
  extra=$(basename "${RCLONE:-rclone}")
  for proc in rclone rsync "$extra"; do
    [ -n "$proc" ] || continue
    pids=$(pgrep -x "$proc" 2>/dev/null) || continue
    [ -n "$pids" ] || continue
    if ps -ww -p $(printf '%s' "$pids" | tr '\n' , | sed 's/,$//') -o args= 2>/dev/null | grep -F -- "$p" >/dev/null; then
      return 1
    fi
  done
  return 0
}
stage_remove_path() { # only a path strictly inside the stage; never follow a symlink to ~/.claude, ~/.codex or work
  local p="$1"
  [ -n "$p" ] && [ -n "$STAGE" ] || return 1
  [ "$p" != "$STAGE" ] || return 1
  case "$p" in "$STAGE"/*) ;; *) say "refusing to remove a path outside the stage"; return 1 ;; esac
  case "$p" in *..*) say "refusing to remove a path with .."; return 1 ;; esac
  for guarded in "$HOME" "$HOME/.claude" "$HOME/.codex" "$HOME/.agent-harness/work"; do
    [ "$p" = "$guarded" ] && { say "refusing to remove a guarded path"; return 1; }
  done
  if [ -L "$p" ]; then rm -f -- "$p"; return 0; fi
  stage_dest_safe "$p" || { say "refusing to remove a staged path that is not a plain directory under the stage"; return 1; }
  # find -P does not descend through directory symlinks; do not use rm -rf (it can follow a mid-path link).
  find -P "$p" \( -type f -o -type l \) -delete 2>/dev/null
  find -P "$p" -depth -type d -exec rmdir {} + 2>/dev/null
  if [ -e "$p" ] || [ -L "$p" ]; then
    say "could not fully remove staged $p"; return 1
  fi
  return 0
}
stage_allow_full_copy() { # 0 when a full copy of $1 may be written into the stage
  local need free min
  [ "$STAGE_MIN_FREE_GIB" = 0 ] && return 0
  need=$(du -k "$1" 2>/dev/null | awk 'END {print $1}')
  printf '%s' "$need" | grep -Eq '^[0-9]+$' || need=0
  free=$(stage_free_kib)
  printf '%s' "$free" | grep -Eq '^[0-9]+$' || return 0  # unreadable df: do not invent a block
  min=$((STAGE_MIN_FREE_GIB * 1024 * 1024))
  # after the copy, at least MIN GiB should remain
  [ $((free - need)) -ge "$min" ]
}
stage_probe_clone() { # set STAGE_CLONE when cp -c or cp --reflink=always makes a distinct-inode copy on this volume
  # Those flags fail instead of silently writing a full copy, so a successful probe is enough; a df delta on a
  # busy volume is too noisy and would fall back to rsync (and then skip when free space is under the floor).
  local d="$STAGE/.rsync-tmp/probe.$$"
  STAGE_CLONE=0
  STAGE_CLONE_KIND=
  mkdir -p "$d" || return 0
  printf x > "$d/a" || { rm -rf "$d"; return 0; }
  if cp -c -p "$d/a" "$d/b" 2>/dev/null && [ -f "$d/b" ] && ! stage_same_inode "$d/a" "$d/b"; then
    STAGE_CLONE=1
    STAGE_CLONE_KIND="cp -c"
  elif rm -f "$d/b" && cp --reflink=always -p "$d/a" "$d/b" 2>/dev/null && [ -f "$d/b" ] && ! stage_same_inode "$d/a" "$d/b"; then
    STAGE_CLONE=1
    STAGE_CLONE_KIND="cp --reflink=always"
  fi
  rm -rf "$d"
}
stage_try_clone() { # stage_try_clone SRC DEST: 0 when DEST is a clone of SRC, not a hardlink
  # macOS cp -c falls back to a full copy across volumes; refuse that here so the free-space floor applies.
  stage_same_volume "$1" "$STAGE" || return 1
  case "$STAGE_CLONE_KIND" in
    "cp -c") cp -c -p "$1" "$2" 2>/dev/null || return 1 ;;
    "cp --reflink=always") cp --reflink=always -p "$1" "$2" 2>/dev/null || return 1 ;;
    *) return 1 ;;
  esac
  [ -f "$2" ] || return 1
  if stage_same_inode "$1" "$2"; then rm -f "$2"; return 1; fi
  return 0
}
stage_unchanged() { # 0 when DEST already matches SRC in size and mtime and is not a hardlink
  local src="$1" dest="$2" ss ds sm dm
  [ -f "$dest" ] && [ ! -L "$dest" ] || return 1
  stage_same_inode "$src" "$dest" && return 1
  ss=$(stat -f %z "$src" 2>/dev/null || stat -c %s "$src" 2>/dev/null) || return 1
  ds=$(stat -f %z "$dest" 2>/dev/null || stat -c %s "$dest" 2>/dev/null) || return 1
  sm=$(stat -f %m "$src" 2>/dev/null || stat -c %Y "$src" 2>/dev/null) || return 1
  dm=$(stat -f %m "$dest" 2>/dev/null || stat -c %Y "$dest" 2>/dev/null) || return 1
  [ "$ss" = "$ds" ] && [ "$sm" = "$dm" ]
}
stage_converted() { grep -Fxq "$1" "$LOGDIR/log-backup.stage-cloned" 2>/dev/null; }
stage_note_converted() {
  local f="$LOGDIR/log-backup.stage-cloned" tmp="$LOGDIR/log-backup.stage-cloned.tmp.$$"
  stage_converted "$1" && return 0
  { cat "$f" 2>/dev/null; printf '%s\n' "$1"; } > "$tmp" && mv "$tmp" "$f"
  rm -f "$tmp"
}
stage_place_file() { # stage_place_file SRC DEST: clone when possible, else a full copy if free space allows
  local src="$1" dest="$2" tmp
  stage_dest_safe "$(dirname "$dest")" || { say "refusing to write a staged path that is not plain under the stage"; return 1; }
  mkdir -p "$(dirname "$dest")" "$STAGE/.rsync-tmp" || return 1
  stage_dest_safe "$(dirname "$dest")" || { say "refusing to write a staged path that is not plain under the stage"; return 1; }
  tmp="$STAGE/.rsync-tmp/f.$$.$RANDOM"
  rm -f "$tmp"
  if [ "$STAGE_CLONE" = 1 ] && stage_try_clone "$src" "$tmp"; then
    :
  else
    if ! stage_allow_full_copy "$src"; then
      say "snapshot skipped full copy (free space below ${STAGE_MIN_FREE_GIB} GiB)"
      rm -f "$tmp"
      return 2
    fi
    cp -p "$src" "$tmp" || { rm -f "$tmp"; return 1; }
    if stage_same_inode "$src" "$tmp"; then rm -f "$tmp"; return 1; fi
  fi
  # Replace the dest only if it is a regular file already under the stage, or does not exist.
  if [ -e "$dest" ] || [ -L "$dest" ]; then
    stage_dest_safe "$dest" || { rm -f "$tmp"; say "refusing to replace a staged path that is not plain under the stage"; return 1; }
    [ -L "$dest" ] && { rm -f "$tmp"; say "refusing to replace a symlink in the stage"; return 1; }
    [ -d "$dest" ] && { rm -f "$tmp"; say "refusing to replace a directory with a staged file"; return 1; }
  fi
  mv -f "$tmp" "$dest"
}
stage_place_symlink() { # stage_place_symlink SRC DEST: copy a symlink; never follow DEST if it is a link to a directory
  # BSD mv -f into an existing symlink-to-dir moves the temp *into* the target (outside the stage).
  local src="$1" dest="$2" tmp src_t dest_t
  [ -L "$src" ] || return 1
  stage_dest_safe "$(dirname "$dest")" || { say "refusing to write a staged path that is not plain under the stage"; return 1; }
  mkdir -p "$(dirname "$dest")" "$STAGE/.rsync-tmp" || return 1
  if [ -L "$dest" ]; then
    src_t=$(readlink "$src") || return 1
    dest_t=$(readlink "$dest") || return 1
    [ "$src_t" = "$dest_t" ] && return 0
    # Remove the staged link itself; rm of a symlink does not follow it.
    rm -f -- "$dest"
  elif [ -d "$dest" ]; then
    say "refusing to replace a directory with a staged symlink"
    return 1
  elif [ -e "$dest" ]; then
    stage_dest_safe "$dest" || { say "refusing to replace a staged path that is not plain under the stage"; return 1; }
    rm -f -- "$dest"
  fi
  tmp="$STAGE/.rsync-tmp/l.$$.$RANDOM"
  rm -f "$tmp"
  if ! cp -P "$src" "$tmp"; then rm -f "$tmp"; return 1; fi
  # dest does not exist (or was removed), so mv cannot follow a symlink-to-dir.
  mv -f "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
}
stage_drop_after_upload() { # remove the staged copy of $1 only when KEEP is exactly 0
  local snap="$1"
  [ "${LOG_BACKUP_STAGE_KEEP:-}" = 0 ] || return 0
  stage_path_unused "$snap" || { say "leaving staged $snap: a copy process still names it"; return 0; }
  stage_remove_path "$snap" && say "reclaimed staged $snap after upload"
}
stage_unescape_rel() { # print rsync --out-format %n with \#ooo (and a following literal) decoded
  python3 -c 'import sys,re; s=sys.argv[1]; s=re.sub(r"\\#([0-7]{3})", lambda m: chr(int(m.group(1),8)), s); sys.stdout.write(s)' "$1"
}
# Choose the snapshot engine on this volume. A clone probe writes a few MB under .rsync-tmp and deletes it.
case "$STAGE_ENGINE" in
  rsync) STAGE_CLONE=0; STAGE_CLONE_KIND= ;;
  clone|auto)
    stage_probe_clone
    if [ "$STAGE_CLONE" != 1 ]; then
      if [ "$STAGE_ENGINE" = clone ]; then
        fail "LOG_BACKUP_STAGE_ENGINE=clone but clonefile/reflink is not available on the stage volume" 2
      fi
      STAGE_CLONE_KIND=
    fi
    ;;
esac
say "stage engine=${STAGE_CLONE_KIND:-rsync} size=$(du -sk "$STAGE" 2>/dev/null | cut -f1) KiB free=$(stage_free_kib) KiB"
fi

rate_limit_note() { # rate_limit_note LOG-OFFSET: name a Dropbox write rate limit seen since LOG-OFFSET, and count the
  # other rclone uploads to this remote on the host, which share the account's write budget (the cause on 2026-11-07).
  local from=$(( ${1:-0} + 1 )) others
  tail -c +"$from" "$LOG" 2>/dev/null | grep -Eq 'too_many_write_operations|Too many requests or write operations' || return 0
  # Count only uploads whose words start with this exact remote name, and leave out this script's own copy.
  others=$(ps -axo pid=,command= 2>/dev/null | awk -v remote="${BASE%%:*}:" -v own="$LOG" \
    '$2 ~ /(^|\/)rclone$/ && !index($0, own) {for (i = 3; i <= NF; i++) if (index($i, remote) == 1) {n++; break}} END {print n+0}')
  say "Dropbox write rate limit (too_many_write_operations) during this copy; other rclone uploads running now: $others (see: ps -axo pid,command | grep rclone)"
  # Every caller is a copy that failed or was cut short (goodqa#15218): more copies in this run would only spend the
  # account's write budget again (2026-11-05: one throttled copy ran for two days). The run stops copying here;
  # a rate limit that rclone retried to success is never reported through this function, so it stops nothing.
  [ "$throttled" = 1 ] || { throttled=1 throttle_src="$rel others=$others"; }
}

# The lane yields to tier 1 (goodqa#15147). tier1_active: a live tier-1 run holds the run lock (a lock whose pid is
# not written yet counts until it is stale, as in acquire_lock; a ps refusal counts as live). lane_gate, before every lane copy, says
# "copying" FIRST and only then looks at the lock; tier 1 takes the lock FIRST and only then reads the state
# (lane_quiet). Whichever acts second sees the other, so the lane never starts a copy beside a tier-1 run.
tier1_active() {
  [ -d "$LOCKD" ] || return 1
  local holder
  holder=$(cat "$LOCKD/pid" 2>/dev/null)
  # A pid-less lock counts as long as acquire_lock treats it as held (red-team F7): never copy beside it.
  if [ -z "$holder" ]; then [ "$(file_age "$LOCKD")" -lt $STALE_LOCK_SECONDS ]; return; fi
  holder_alive "$holder"
}
lane_set_state() { echo "$1 $$" > "$LANE_STATE.tmp.$$" && mv "$LANE_STATE.tmp.$$" "$LANE_STATE"; }
lane_gate() { # 0: clear to copy (state is copying); 1: the lane's time ran out while it waited
  local said=0
  while :; do
    lane_set_state copying
    tier1_active || return 0
    lane_set_state idle
    [ $said -eq 1 ] || { say "a tier-1 run holds the lock; the lane waits for it"; said=1; }
    [ "$(time_left)" -ge "$MIN_SLICE" ] || return 1
    nap "$LANE_POLL"
  done
}

# goodqa#16123: Dropbox refuses a few file names outright. rclone's backend/dropbox rule is
#   (?i)(^|/)(desktop\.ini|thumbs\.db|\.ds_store|icon\r|\.dropbox|\.dropbox.attr)$
# and each refused file is a hard error ("Failed to copy: file name ... is disallowed - not uploading", no retry), so one
# .DS_Store failed every copy of the work tree for two days. The names are filtered out of every list (log-backup.excludes
# for the stage, the plain copies and the checkpoint listing; REFUSED_RE for a checkpoint list made before an edit). A refusal
# that still reaches the remote is counted and reported, and fails the run only when something else failed with it.
REFUSED_RE=$'(^|/)(desktop\\.ini|thumbs\\.db|\\.ds_store|icon\r|\\.dropbox|\\.dropbox\\.attr)$'
REFUSED_N=0
refused_only() { # refused_only LOG-OFFSET: 0 (and the count on stdout) when the copy's log lines since LOG-OFFSET hold
  # name refusals and no other error; 1 otherwise (including a log with no "Failed to copy" line at all)
  tail -c +"$(( $1 + 1 ))" "$LOG" 2>/dev/null | LC_ALL=C awk '
    / ERROR : / {
      if ($0 ~ /: Failed to copy: file name ".*" is disallowed - not uploading$/) { d++; next }
      if ($0 ~ / ERROR : Can.t retry any of the errors - not attempting retries$/) next
      if ($0 ~ / ERROR : Attempt [0-9]+\/[0-9]+ failed with [0-9]+ errors and: file name ".*" is disallowed - not uploading$/) next
      other++; next
    }
    / NOTICE: Failed to copy: / { seen++; if ($0 !~ /Failed to copy: file name ".*" is disallowed - not uploading$/) other++; next }
    / NOTICE: Failed to copy with [0-9]+ errors: last error was: / {
      seen++; n = $0; sub(/.*Failed to copy with /, "", n); sub(/ errors.*/, "", n); need = n + 0
      if ($0 !~ /last error was: file name ".*" is disallowed - not uploading$/) other++
      next
    }
    END { if (d > 0 && seen > 0 && !other && d >= need) { print d; exit 0 } exit 1 }'
}
note_refused() { # note_refused SRC-REL COUNT WHAT
  REFUSED_N=$(( REFUSED_N + $2 ))
  say "$1: $2 file(s) $3 by the remote by name; not backed up, and the run is not failed for them"
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
  attempt=0 copied=0 yielded=0
  # The transcripts themselves (the primary sources, copied last so the reserve protects them) still get their own
  # copy: stopping them too would let a throttled WAL or ledger copy starve the transcript backup run after run.
  case "$rel" in .claude/projects|.codex/sessions) ;; *)
    if [ "$throttled" = 1 ]; then
      say "skipped $rel: an earlier copy in this run failed on the Dropbox write rate limit; the next run sends it"
      ok=1; budget_hit=1; return
    fi ;;
  esac
  while :; do
    if [ "$TIER" = bulk ] && ! lane_gate; then
      say "lane budget (${LANE_BUDGET}s) used up waiting for tier 1 before $rel; the next lane run continues"; ok=1; budget_hit=1; return
    fi
    # This copy's share: wall time left, less its own stop and kill grace, less what the later tier-1 sources are
    # promised (RESERVE). It is never under MIN_SLICE; when even that does not fit, the source waits for the next run.
    remaining=$(( WALL_END - $(date +%s) - DEADLINE_GRACE - KILL_GRACE ))
    if [ $remaining -lt $MIN_SLICE ]; then
      [ "$TIER" != bulk ] || lane_set_state idle
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
    rm -f "$LOGDIR/.log-backup${TAG}.deadline.$copy_pid"
    # The watchdog ends its own sleep when it is stopped, so no orphan sleep holds the caller's output open; it writes
    # its marker before signalling, so the copy's exit can never be read before the marker exists.
    ( nap=
      trap 'kill ${nap:+"$nap"} 2>/dev/null; exit 0' TERM
      sleep $((remaining + DEADLINE_GRACE)) & nap=$!
      wait "$nap" || exit 0
      touch "$LOGDIR/.log-backup${TAG}.deadline.$copy_pid"
      kill -TERM "$copy_pid" 2>/dev/null || exit 0
      sleep "$KILL_GRACE" & nap=$!
      wait "$nap" || exit 0
      kill -KILL "$copy_pid" 2>/dev/null ) </dev/null >/dev/null 2>&1 &
    dog_pid=$!
    if [ "$TIER" = bulk ]; then
      # A tier-1 run that starts during this copy gets the budget: stop the copy (TERM, then KILL after KILL_GRACE) and
      # send its chunk again later. The overlap is at most one poll plus the stop grace (goodqa#15147 NEG-1).
      while kill -0 "$copy_pid" 2>/dev/null; do
        if tier1_active; then
          touch "$LOGDIR/.log-backup${TAG}.yield.$copy_pid"
          kill -TERM "$copy_pid" 2>/dev/null
          waited=0
          while kill -0 "$copy_pid" 2>/dev/null && [ $waited -lt $(( KILL_GRACE * 5 )) ]; do sleep 0.2; waited=$((waited + 1)); done
          kill -KILL "$copy_pid" 2>/dev/null
          break
        fi
        nap "$LANE_POLL"
      done
    fi
    wait "$copy_pid"; rc=$?
    kill "$dog_pid" 2>/dev/null; wait "$dog_pid" 2>/dev/null
    dog_pid=   # reaped: a later signal must not reach a recycled pid
    done_pid=$copy_pid copy_pid=
    [ "$TIER" != bulk ] || lane_set_state idle
    if [ -e "$LOGDIR/.log-backup${TAG}.yield.$done_pid" ]; then
      rm -f "$LOGDIR/.log-backup${TAG}.yield.$done_pid" "$LOGDIR/.log-backup${TAG}.deadline.$done_pid"
      say "copy of $rel stopped: a tier-1 run started; this chunk is sent again after it"
      yielded=1; return
    fi
    if [ -e "$LOGDIR/.log-backup${TAG}.deadline.$done_pid" ]; then
      rm -f "$LOGDIR/.log-backup${TAG}.deadline.$done_pid"
      say "copy of $rel stopped at the run deadline (${remaining}s + ${DEADLINE_GRACE}s grace, killed after ${KILL_GRACE}s more if still running); partial, last-ok withheld"
      rate_limit_note "$log_mark"; ok=1; budget_hit=1; return
    fi
    if [ $rc -eq 0 ]; then copied=1; break; fi
    if [ $rc -eq 8 ] || [ $rc -eq 10 ]; then
      # --max-transfer (8) or --max-duration (10) reached: partial progress is kept, the next run continues.
      say "budget reached for $rel (rclone exit $rc); partial, last-ok withheld"; rate_limit_note "$log_mark"; ok=1; budget_hit=1; return
    fi
    if [ $rc -eq 1 ] || [ $rc -eq 6 ]; then
      # Only name refusals in this copy's log: the rest of the copy went through, so it counts as copied (goodqa#16123).
      if refused=$(refused_only "$log_mark"); then note_refused "$rel" "$refused" "refused"; copied=1; break; fi
    fi
    attempt=$((attempt + 1))
    [ $attempt -le "${LOG_BACKUP_RETRIES:-2}" ] || break
    say "copy of $rel failed; retry $attempt after ${LOG_BACKUP_RETRY_SLEEP:-30}s (file changed mid-copy or rate limit)"
    nap "${LOG_BACKUP_RETRY_SLEEP:-30}"
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
  [ -s "$st/pending" ] && [ "$(cat "$st/remote" 2>/dev/null)" = "$R" ] && [ "$(cat "$st/filters" 2>/dev/null)" = "$FILTER_ID" ] && return 1
  return 0
}
bulk_upload() { # bulk_upload SRC-REL [filter args...] -- [copy args...]: one checkpointed pass; 0 when finished
  # CK_ROOT (default ~/SRC-REL) is the local tree that is listed and sent; CK_PREFIX keeps a separate checkpoint (tier 1
  # sends its staged snapshot through here with CK_PREFIX=live_, so it never shares state with the bulk tier).
  local rel="$1" st n cur total chunk root
  shift
  root=${CK_ROOT:-$HOME/$rel}
  local list_filters=() copy_args=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do list_filters+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  copy_args=("$@")
  st="$BULK_STATE/${CK_PREFIX:-}$(bulk_key "$rel")"
  mkdir -p "$st" && chmod 700 "$BULK_STATE" "$st" || { say "cannot create bulk state for $rel"; ok=1; hard_fail=1; return 1; }
  # A checkpoint belongs to one destination: another remote or host starts over.
  if [ "$(cat "$st/remote" 2>/dev/null)" != "$R" ]; then
    rm -f "$st/pending" "$st/cursor" "$st/done" "$st/listing" "$st/seeded" && printf '%s\n' "$R" > "$st/remote"
  fi
  # A pass listed with other exclude lists would send what they now exclude: list it again (the old `done` stays, so
  # files already verified are still not sent twice). A checkpoint from before this marker existed counts as changed.
  if [ -s "$st/pending" ] && [ "$(cat "$st/filters" 2>/dev/null)" != "$FILTER_ID" ]; then
    say "$rel: the exclude lists changed since this pass was listed; listing it again"
    rm -f "$st/pending" "$st/cursor" "$st/chunk" "$st/chunk.paths" "$st/listing"
  fi
  if [ ! -s "$st/pending" ]; then
    local filters=(--exclude-from "$EXCLUDES" --ignore-case "${list_filters[@]+"${list_filters[@]}"}")
    "$RCLONE" lsf -R --files-only --format pst --separator $'\t' "${filters[@]}" -- "$root" \
      </dev/null > "$st/listing.tmp" 2>> "$LOG"
    rc=$?
    if [ $rc -ne 0 ]; then say "listing $rel failed (rclone exit $rc)"; ok=1; hard_fail=1; rm -f "$st/listing.tmp"; return 1; fi
    # Exactly three fields: a path with a tab or a newline cannot be checkpointed safely and is left to the next
    # full listing (it is counted, so it is never silently dropped).
    awk -F'\t' 'NF != 3 {bad++} END {print bad + 0}' "$st/listing.tmp" > "$st/odd"
    awk -F'\t' 'NF == 3' "$st/listing.tmp" > "$st/listing" && rm -f "$st/listing.tmp"
    [ -z "${CK_SEED:-}" ] || ck_seed "$st" "$rel"
    touch "$st/done"
    awk -F'\t' 'FILENAME == ARGV[1] {seen[$0] = 1; next} !($0 in seen)' "$st/done" "$st/listing" > "$st/pending.tmp" \
      && mv "$st/pending.tmp" "$st/pending" && echo 0 > "$st/cursor" || { say "cannot build the $rel checkpoint"; ok=1; hard_fail=1; return 1; }
    # The run that listed this generation: when it completes, the source is backed up as of this run's start.
    if [ "${CK_CLEAN:-1}" = 1 ]; then printf '%s\n' "$STARTED" > "$st/listed"; else echo partial > "$st/listed"; fi
    # Written last: a crash before this line leaves no matching marker, so the next run lists again.
    printf '%s\n' "$FILTER_ID" > "$st/filters.tmp" && mv "$st/filters.tmp" "$st/filters" \
      || { say "cannot record the $rel filters; the next run lists it again"; ok=1; hard_fail=1; return 1; }
    [ "$(cat "$st/odd")" = 0 ] || say "$rel: $(cat "$st/odd") paths with a tab or newline are not checkpointed"
    say "$rel: new pass, $(wc -l < "$st/pending" | tr -d ' ') of $(wc -l < "$st/listing" | tr -d ' ') files new or changed"
  fi
  total=$(wc -l < "$st/pending" | tr -d ' ')
  cur=$(cat "$st/cursor" 2>/dev/null)
  printf '%s' "$cur" | grep -Eq '^(0|[1-9][0-9]*)$' || cur=0
  while [ "$cur" -lt "$total" ]; do
    # An exclude list edited during this run must not wait for the next pass: stop here, and the next run lists again.
    if [ "$(filter_id 2>/dev/null)" != "$FILTER_ID" ]; then
      say "$rel: the exclude lists changed during this run; stopping at $cur of $total, the next run lists it again"
      rm -f "$st/pending" "$st/cursor" "$st/chunk" "$st/chunk.paths" "$st/listing"
      ok=1; budget_hit=1; return 1
    fi
    # No more files than fit the time left (about 2 rate-limited operations a file): a chunk cut short is sent again
    # whole and never advances the cursor (PR #124 review F1).
    size=$BULK_CHUNK fit=$(( $(time_left) * TPSLIMIT / 2 ))
    [ "$fit" -ge "$size" ] || size=$fit
    [ "$size" -ge 1 ] || size=1
    sed -n "$((cur + 1)),$((cur + size))p;$((cur + size))q" "$st/pending" > "$st/chunk" \
      || { say "cannot read the $rel chunk"; ok=1; hard_fail=1; return 1; }
    n=$(wc -l < "$st/chunk"); n=${n//[[:space:]]/}
    printf '%s' "$n" | grep -Eq '^[0-9]+$' || { say "cannot count the $rel chunk"; ok=1; hard_fail=1; return 1; }
    cut -f1 "$st/chunk" > "$st/chunk.paths" || { say "cannot read the $rel chunk"; ok=1; hard_fail=1; return 1; }
    # A pass listed before the exclude lists changed still holds names the remote refuses: drop them from the chunk
    # (counted, and the cursor still moves past them) so the copy never offers them (goodqa#16123). Every status is
    # checked: grep exits 0 (some paths kept) or 1 (all excluded); any other status, or counts that do not add up, means
    # the list may be short, and a short list must never be sent, replace the chunk or move the cursor (PR #259 review).
    LC_ALL=C grep -Eiv -- "$REFUSED_RE" "$st/chunk.paths" > "$st/chunk.paths.tmp"; grc=$?
    kept=$(wc -l < "$st/chunk.paths.tmp"); wrc=$?; kept=${kept//[[:space:]]/}
    LC_ALL=C grep -Eic -- "$REFUSED_RE" "$st/chunk.paths" > "$st/chunk.refused.tmp"; crc=$?
    dropped=$(cat "$st/chunk.refused.tmp" 2>/dev/null)
    rm -f "$st/chunk.refused.tmp"
    if [ $grc -gt 1 ] || [ $crc -gt 1 ] || [ $wrc -ne 0 ] \
       || ! printf '%s' "$kept" | grep -Eq '^[0-9]+$' || ! printf '%s' "$dropped" | grep -Eq '^[0-9]+$' \
       || [ $(( kept + dropped )) -ne "$n" ] || { [ $grc -eq 0 ] && [ "$kept" -eq 0 ]; } || { [ $grc -eq 1 ] && [ "$kept" -ne 0 ]; }; then
      say "cannot filter the $rel chunk (grep exit $grc/$crc, kept=${kept:-?} refused=${dropped:-?} of $n); nothing sent, the cursor stays at $cur"
      rm -f "$st/chunk.paths.tmp"
      ok=1; hard_fail=1; return 1
    fi
    if [ "$dropped" -gt 0 ]; then note_refused "$rel" "$dropped" "left out of the chunk, refused"; fi
    mv "$st/chunk.paths.tmp" "$st/chunk.paths" || { say "cannot filter the $rel chunk"; ok=1; hard_fail=1; return 1; }
    if [ -s "$st/chunk.paths" ]; then
      upload "$root" "$rel" "${copy_args[@]+"${copy_args[@]}"}" --files-from-raw "$st/chunk.paths" --no-traverse
    else
      copied=1 yielded=0   # nothing left in this chunk to send
    fi
    # A chunk stopped for tier 1 never advances the cursor: the same lines are sent again whole (goodqa#15147 NEG-2).
    [ "$yielded" -eq 0 ] || continue
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
  CK_LISTED=$(cat "$st/listed" 2>/dev/null)
  return 0
}

# Tier-1 freshness per source (log-backup.src.d/KEY holds "STAMP REMOTE"): a source is backed up as of STAMP, the start
# of the run whose snapshot was sent in full. log-backup.last-ok is then the oldest of them, so a run that stops on the
# budget or the rate limit still counts for the sources it finished (before, partial progress never counted and the
# marker stayed stuck from 2026-11-13).
SRC_STATE="$LOGDIR/log-backup.src.d"
ck_seed() { # ck_seed STATE-DIR SRC-REL: once per checkpoint, take the files already on the remote as verified
  # A new tier-1 checkpoint would otherwise check every file the full copies already sent, one rate-limited operation
  # each (about a day of runs for 38,000 files). One recursive listing of the remote is a few dozen operations; a file
  # whose path, size and modification time match is not sent again. Tried once: a failed or stopped listing seeds
  # nothing, and the pass then checks every file.
  local st="$1" rel="$2" limit pid dog rc
  [ ! -e "$st/done" ] && [ ! -e "$st/seeded" ] || return 0
  limit=$(( $(time_left) / 3 ))
  [ "$limit" -ge 30 ] || return 0
  : > "$st/seeded"
  "$RCLONE" lsf -R --files-only --fast-list --format pst --separator $'\t' --tpslimit "$TPSLIMIT" \
    --exclude-from "$EXCLUDES" --ignore-case -- "$R/$rel" </dev/null > "$st/seed.tmp" 2>> "$LOG" &
  pid=$!
  ( sleep "$limit"; kill -TERM "$pid" 2>/dev/null ) </dev/null >/dev/null 2>&1 &
  dog=$!
  wait "$pid"; rc=$?
  kill "$dog" 2>/dev/null; wait "$dog" 2>/dev/null
  if [ $rc -eq 0 ]; then
    awk -F'\t' 'NF == 3' "$st/seed.tmp" > "$st/done.tmp" && mv "$st/done.tmp" "$st/done" \
      && say "$rel: $(wc -l < "$st/done" | tr -d ' ') files already on the remote taken as sent"
  else
    say "$rel: listing the remote to seed the checkpoint failed (rclone exit $rc); this pass checks every file"
  fi
  rm -f "$st/seed.tmp" "$st/done.tmp"
}
src_mark() { # src_mark SRC-REL STAMP
  printf '%s' "$2" | grep -Eq '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$' || return 1
  mkdir -p "$SRC_STATE" && chmod 700 "$SRC_STATE" || return 1
  printf '%s %s\n' "$2" "$R" > "$SRC_STATE/$(bulk_key "$1").tmp.$$" && mv "$SRC_STATE/$(bulk_key "$1").tmp.$$" "$SRC_STATE/$(bulk_key "$1")"
}
src_stamp() { # src_stamp SRC-REL: the source's stamp for this remote, or nothing
  local line
  line=$(head -c 512 "$SRC_STATE/$(bulk_key "$1")" 2>/dev/null) || return 0
  [ "${line#* }" = "$R" ] || return 0
  printf '%s' "${line%% *}" | grep -E '^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$'
}

bulk_try="$LOGDIR/log-backup.bulk-last-try"
bulk_due() { # the hourly gap has passed (or a pass stopped on the budget cleared it)
  local a
  [ -e "$bulk_try" ] || return 0
  a=$(raw_age "$bulk_try")
  [ -z "$a" ] || [ "$a" -lt 0 ] || [ "$a" -ge "$BULK_EVERY" ]
}
lane_yields() { # the live lane run $1 is one that yields to tier 1 (it keeps a state file under its pid)
  case "$(cat "$LANE_STATE" 2>/dev/null)" in "copying $1"|"idle $1") return 0 ;; esac
  return 1
}
lane_quiet() { # wait, bounded, until the lane run $1 has no copy in flight; it stops one when it sees this run's lock
  local waited=0 limit=$(( (LANE_POLL + KILL_GRACE + 5) * 5 ))
  while [ "$(cat "$LANE_STATE" 2>/dev/null)" = "copying $1" ] && holder_alive "$1"; do
    if [ $waited -ge $limit ]; then
      say "WARNING: the bulk lane (pid $1) did not pause within $((limit / 5))s; tier 1 copies anyway"
      return 1
    fi
    sleep 0.2; waited=$((waited + 1))
  done
  return 0
}
lane_pid=$(cat "$LANE_LOCKD/pid" 2>/dev/null)
if [ "$TIER" != bulk ] && [ -n "$lane_pid" ] && holder_alive "$lane_pid"; then
  waited=0   # a lane writes its state right after taking its lock: allow it 2 s before calling it a pre-#15147 lane
  while ! lane_yields "$lane_pid" && [ $waited -lt 10 ] && holder_alive "$lane_pid"; do sleep 0.2; waited=$((waited + 1)); done
  if ! lane_yields "$lane_pid" && ! holder_alive "$lane_pid"; then
    say "bulk lane (pid $lane_pid) ended while tier 1 checked it"   # re-review N4: not a lane that does not yield
    lane_pid=
  fi
fi
if [ "$TIER" != bulk ] && [ -n "$lane_pid" ] && holder_alive "$lane_pid"; then
  if lane_yields "$lane_pid"; then
    lane_quiet "$lane_pid" && say "bulk lane running (pid $lane_pid); it pauses while tier 1 copies at ${TPSLIMIT}/s"
  elif [ "$TPSLIMIT" -gt 1 ]; then
    # A lane started by the version before goodqa#15147 does not yield: share the budget with it until it ends.
    TPSLIMIT=$(( TPSLIMIT - 1 ))
    say "bulk lane still running (pid $lane_pid) and it does not yield; tier 1 copies at ${TPSLIMIT}/s"
  else
    say "WARNING: a bulk lane run that does not yield is going and LOG_BACKUP_TPSLIMIT is 1; this host runs over its budget until it ends"
  fi
elif [ "$TIER" = live ] && bulk_due; then
  rm -f "$LOGDIR/log-backup.lane.started"
  LOG_BACKUP_TIER=bulk /bin/bash "$SELF_DIR/$(basename "$0")" </dev/null >/dev/null 2>&1 &
  lane_pid=$! waited=0
  while [ "$(cat "$LOGDIR/log-backup.lane.started" 2>/dev/null)" != "$lane_pid" ] && [ $waited -lt 50 ]; do
    kill -0 "$lane_pid" 2>/dev/null || break
    sleep 0.2; waited=$((waited + 1))
  done
  if [ "$(cat "$LOGDIR/log-backup.lane.started" 2>/dev/null)" = "$lane_pid" ]; then
    lane_quiet "$lane_pid"
    say "bulk lane started (pid $lane_pid); it copies at ${BULK_TPS}/s only while no tier-1 run holds the lock"
  else
    say "bulk lane did not start (pid $lane_pid; see log-backup.lane.log); tier 1 copies at ${TPSLIMIT}/s"
  fi
fi
transcripts_ok=0
if [ "$TIER" != bulk ]; then
later=0
for src in "${LIVE[@]}"; do [ -e "$HOME/$src" ] && later=$((later + 1)); done
run_fail=0
for src in "${LIVE[@]}"; do
  # ok is per source inside this loop (a source is clean when it ends at 0); run_fail keeps the run's result.
  [ $ok -eq 0 ] || run_fail=1; ok=0
  [ -e "$HOME/$src" ] || [ -L "$HOME/$src" ] || continue
  later=$((later - 1)); [ $later -ge 0 ] || later=0
  # A later copy that hangs costs its slice, both graces and about 3 s to snapshot the source first.
  RESERVE=$(( later * (MIN_SLICE + DEADLINE_GRACE + KILL_GRACE + 3) ))
  if [ -L "$HOME/$src" ]; then say "refusing symlinked source root: $src"; ok=1; continue; fi
  snap="$STAGE/$src"
  stage_dest_safe "$(dirname "$snap")" || { say "refusing to use a staged $src that is not a plain path under the stage"; ok=1; continue; }
  mkdir -p "$(dirname "$snap")" || { say "cannot stage $src"; ok=1; continue; }
  if [ -e "$snap" ] || [ -L "$snap" ]; then
    stage_dest_safe "$snap" || { say "refusing to use a staged $src that is not a plain path under the stage"; ok=1; continue; }
  fi
  if [ -d "$HOME/$src" ]; then
    # rsync -a keeps symlinks as links; rclone never follows them. Exit 24 = a file vanished mid-copy (not an error).
    # --temp-dir sits outside every uploaded tree: a crash mid-copy leaves its partial files there, never beside data
    # that rclone would upload as current. rsync (and the clone path's temp files) rename within the stage volume,
    # so a full disk fails the copy (exit 11 or 23, source skipped, run non-fresh) instead of leaving a truncated
    # file in place.
    # The trash directory is pruned before the catch-all directory include below (first rsync rule wins), at any depth (B7).
    mkdir -p "$STAGE/.rsync-tmp" || { say "cannot create the stage temp directory"; ok=1; continue; }
    if [ "$STAGE_CLONE" != 1 ]; then
      # Full-copy fallback: do not start a tree copy that would leave less than MIN_FREE GiB.
      if [ "$STAGE_MIN_FREE_GIB" != 0 ]; then
        free=$(stage_free_kib)
        if printf '%s' "$free" | grep -Eq '^[0-9]+$' && [ "$free" -lt $((STAGE_MIN_FREE_GIB * 1024 * 1024)) ]; then
          say "snapshot skipped (full copy): ${free} KiB free, need ${STAGE_MIN_FREE_GIB} GiB; $src"
          ok=1
          continue
        fi
      fi
      rsync -a --temp-dir="$STAGE/.rsync-tmp" --exclude='.[gG][oO][oO][dD][qQ][aA]-[tT][rR][aA][sS][hH]/' --include='*/' --exclude-from="$RSYNC_EXCLUDES" -- "$HOME/$src/" "$snap/" </dev/null; rc=$?
      if [ $rc -eq 23 ]; then
        # Partial transfer (e.g. one unreadable file): rsync renames files into place, so the stage is consistent.
        # Back up what was staged, but withhold last-ok for this run.
        say "snapshot partial (rsync exit 23): $src"; ok=1
      elif [ $rc -ne 0 ] && [ $rc -ne 24 ]; then
        say "snapshot failed (rsync exit $rc): $src"; ok=1; continue
      fi
    else
      # Clonefile/reflink snapshot: list with the same rsync excludes against the existing
      # snapshot (not an empty tree) so only new or changed files are placed. A deadline-stopped
      # pass therefore resumes on the next run instead of re-cloning from the top. Unchanged
      # files are also skipped in the loop as a backstop.
      mkdir -p "$snap" || { say "cannot stage $src"; ok=1; continue; }
      stage_dest_safe "$snap" || { say "refusing to use a staged $src that is not a plain path under the stage"; ok=1; continue; }
      list="$STAGE/.rsync-tmp/list.$$"
      rsync -a -n $RSYNC_8 --out-format='%n' --temp-dir="$STAGE/.rsync-tmp" --exclude='.[gG][oO][oO][dD][qQ][aA]-[tT][rR][aA][sS][hH]/' --include='*/' --exclude-from="$RSYNC_EXCLUDES" -- "$HOME/$src/" "$snap/" > "$list" </dev/null; rc=$?
      list_ok=1
      if [ $rc -eq 23 ]; then
        say "snapshot partial (rsync exit 23): $src"; ok=1; list_ok=0
      elif [ $rc -ne 0 ] && [ $rc -ne 24 ]; then
        say "snapshot failed (rsync exit $rc): $src"; ok=1; rm -f "$list"; continue
      fi
      snap_done=1
      src_ok=1
      placed=0
      while IFS= read -r rel || [ -n "$rel" ]; do
        [ -n "$rel" ] || continue
        case "$rel" in .|./) continue ;; esac
        if [ "$(time_left)" -lt $(( MIN_SLICE + DEADLINE_GRACE + KILL_GRACE + RESERVE )) ]; then
          say "snapshot stopped at the run deadline: $src"; ok=1; snap_done=0; break
        fi
        if [ "$STAGE_MAX_PLACE" != 0 ] && [ "$placed" -ge "$STAGE_MAX_PLACE" ]; then
          say "snapshot stopped after LOG_BACKUP_STAGE_MAX_PLACE files: $src"; ok=1; snap_done=0; break
        fi
        srcp="$HOME/$src/$rel"
        destp="$snap/$rel"
        if [ ! -e "$srcp" ] && [ ! -L "$srcp" ]; then
          decoded=$(stage_unescape_rel "$rel")
          if [ -n "$decoded" ] && [ "$decoded" != "$rel" ]; then
            rel="$decoded"
            srcp="$HOME/$src/$rel"
            destp="$snap/$rel"
          fi
        fi
        case "$destp" in "$snap"|"$snap"/*) ;; *) ok=1; src_ok=0; continue ;; esac
        if [ "${rel%/}" != "$rel" ]; then
          stage_dest_safe "${destp%/}" || { say "snapshot partial (unsafe dest): $src/$rel"; ok=1; src_ok=0; continue; }
          mkdir -p "${destp%/}" || { say "snapshot partial (mkdir): $src/$rel"; ok=1; src_ok=0; }
          continue
        fi
        if [ -d "$srcp" ] && [ ! -L "$srcp" ]; then
          stage_dest_safe "$destp" || { say "snapshot partial (unsafe dest): $src/$rel"; ok=1; src_ok=0; continue; }
          mkdir -p "$destp" || { say "snapshot partial (mkdir): $src/$rel"; ok=1; src_ok=0; }
          continue
        fi
        if [ ! -e "$srcp" ] && [ ! -L "$srcp" ]; then
          # A listed name that still cannot be resolved may be rsync-escaped; do not call the run fresh.
          say "snapshot partial (unresolved name): $src"; ok=1; src_ok=0
          continue
        fi
        stage_dest_safe "$(dirname "$destp")" || { say "snapshot partial (unsafe dest): $src/$rel"; ok=1; src_ok=0; continue; }
        mkdir -p "$(dirname "$destp")" || { say "snapshot partial (mkdir): $src/$rel"; ok=1; src_ok=0; continue; }
        if [ -L "$srcp" ]; then
          if stage_place_symlink "$srcp" "$destp"; then
            placed=$((placed + 1))
          else
            say "snapshot partial (symlink): $src/$rel"; ok=1; src_ok=0
          fi
        elif [ -f "$srcp" ]; then
          if stage_unchanged "$srcp" "$destp"; then
            continue
          fi
          if stage_place_file "$srcp" "$destp"; then
            placed=$((placed + 1))
          else
            say "snapshot partial (file): $src/$rel"; ok=1; src_ok=0
          fi
        fi
      done < "$list"
      rm -f "$list"
      # Mark a finished conversion so a later engine or stage change can still be told apart.
      # Do not mark a partial pass: leftover full copies with the same size and mtime would then
      # never be replaced by a dedicated conversion pass.
      if [ "$snap_done" = 1 ] && [ "$src_ok" = 1 ] && [ "$list_ok" = 1 ]; then
        stage_note_converted "$src"
      fi
    fi
  else
    if ! stage_place_file "$HOME/$src" "$snap"; then
      say "snapshot failed: $src"; ok=1; continue
    fi
  fi
  if [ -d "$snap" ] && [ ! -L "$snap" ]; then
    # A staged tree is sent as a checkpointed pass of its new or changed files (the bulk tier's checkpoint): a full
    # copy re-listed about 38,000 files against Dropbox every run and used the whole budget on it (2026-11-25).
    # The staged copy keeps the source's files, so a chunk cut short is sent again and the cursor resumes there.
    found_before=$found primary_before=$primary CK_LISTED=
    if [ $ok -eq 0 ]; then src_clean=1; else src_clean=0; fi
    if CK_ROOT="$snap" CK_PREFIX=live_ CK_SEED=1 CK_CLEAN=$src_clean bulk_upload "$src" --; then
      found=$((found_before + 1)) primary=$primary_before
      case "$src" in .claude/projects|.codex/sessions)
        if [ -n "$(find "$HOME/$src" -type f -print -quit 2>/dev/null)" ]; then primary=$((primary + 1)); fi ;;
      esac
      [ $src_clean -eq 1 ] && [ $ok -eq 0 ] && { src_mark "$src" "$CK_LISTED" || say "cannot record the $src marker"; }
    else
      found=$found_before primary=$primary_before; ok=1
    fi
  else
    upload "$snap" "$src"
    [ $ok -eq 0 ] && { src_mark "$src" "$STARTED" || say "cannot record the $src marker"; }
  fi
  stage_drop_after_upload "$snap"
done
[ $ok -eq 0 ] || run_fail=1; ok=$run_fail
# Tier 1 (transcripts, WALs, ledgers) is done: mark it on its own, so a slow bulk pass can never hide a gap here.
[ $primary -gt 0 ] || { say "no primary source (.claude/projects or .codex/sessions) was copied"; ok=1; }
say "transcripts exit=$ok sources=$found remote=${R%%:*}"
transcripts_ok=$ok
# last-ok is the oldest per-source stamp over the live sources present, once each has one and a primary source with
# files has one. It never moves back.
oldest= oldest_src= have_primary=0 missing=
for src in "${LIVE[@]}"; do
  [ -e "$HOME/$src" ] || continue
  st_=$(src_stamp "$src")
  if [ -z "$st_" ]; then missing="$missing $src"; continue; fi
  case "$src" in .claude/projects|.codex/sessions)
    [ -z "$(find "$HOME/$src" -type f -print -quit 2>/dev/null)" ] || have_primary=1 ;;
  esac
  if [ -z "$oldest" ] || [[ "$st_" < "$oldest" ]]; then oldest=$st_ oldest_src=$src; fi
done
prev_ok=$(head -c 512 "$LOGDIR/log-backup.last-ok" 2>/dev/null | awk 'NR == 1 {print $1}')
if [ -n "$missing" ]; then
  say "last-ok withheld: no completed pass yet for$missing"
elif [ -z "$oldest" ] || [ $have_primary -eq 0 ]; then
  say "last-ok withheld: no primary source (.claude/projects or .codex/sessions) with files has a completed pass"
elif [ -n "$prev_ok" ] && ! [[ "$prev_ok" < "$oldest" ]]; then
  [ $ok -eq 0 ] || say "last-ok unchanged at $prev_ok (oldest source $oldest_src at $oldest)"
else
  echo "$oldest sources=$found remote=${R%%:*} oldest=$oldest_src" > "$LOGDIR/log-backup.last-ok.tmp.$$" \
    && mv "$LOGDIR/log-backup.last-ok.tmp.$$" "$LOGDIR/log-backup.last-ok"
  [ "$oldest" = "$STARTED" ] || say "last-ok advanced to $oldest (oldest source $oldest_src)"
fi
fi   # tier 1
ok=0
# Tier 2 runs at most once per BULK_EVERY seconds: its marker allows 6 hours, and transcripts must not wait behind it.
bulk_ran=1 sources_bulk=("${DIRECT[@]}")
[ "$TIER" = live ] && bulk_ran=0 sources_bulk=()   # the lane run copies tier 2
if [ $bulk_ran -eq 1 ] && [ -e "$bulk_try" ]; then
  bulk_age=$(raw_age "$bulk_try")
  if [ -n "$bulk_age" ] && [ "$bulk_age" -ge 0 ] && [ "$bulk_age" -lt "$BULK_EVERY" ]; then
    bulk_ran=0 sources_bulk=()
    say "bulk tier skipped: last attempt ${bulk_age}s ago (every ${BULK_EVERY}s)"
  fi
fi
# Mac 2026-11-07: tier 1 used the whole budget, so every hourly bulk attempt copied nothing, failed the run and still
# spent the hour. With no time left the tier is deferred instead: not an attempt, no failure, the next run tries it.
if [ $bulk_ran -eq 1 ] && [ ${#sources_bulk[@]} -gt 0 ] && [ "$(time_left)" -lt "$MIN_SLICE" ]; then
  bulk_ran=0 sources_bulk=()
  say "bulk tier deferred: no run time left after tier 1; the next run with time left tries it"
fi
# One writer per bulk checkpoint: a run with the lane off still takes the lane lock, so it never shares the
# checkpoint with a lane run that is still going (the lane run took it at its start).
if [ "$TIER" = all ] && [ $bulk_ran -eq 1 ] && ! acquire_lock "$LANE_LOCKD"; then
  bulk_ran=0 sources_bulk=()
  say "bulk tier skipped: a bulk lane run holds the bulk checkpoint"
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
if [ "$throttled" = 1 ]; then
  # Read by log_backup.py status and the backup alert: the run ended early on the rate limit, not on a hang.
  echo "$STARTED stopped at $throttle_src" > "$LOGDIR/log-backup${TAG}.throttled.tmp.$$" \
    && mv "$LOGDIR/log-backup${TAG}.throttled.tmp.$$" "$LOGDIR/log-backup${TAG}.throttled"
  say "run stopped early on the Dropbox write rate limit (log-backup${TAG}.throttled); the next scheduled run continues"
fi
# How many files the remote refused by name in this run (goodqa#16123): not failures, and not backed up.
echo "$STARTED refused=$REFUSED_N" > "$LOGDIR/log-backup${TAG}.refused.tmp.$$" \
  && mv "$LOGDIR/log-backup${TAG}.refused.tmp.$$" "$LOGDIR/log-backup${TAG}.refused"
rc=0
{ [ $transcripts_ok -eq 0 ] && [ $bulk_ok -eq 0 ]; } || rc=1
case "$TIER" in
  bulk) echo "$STARTED exit=$rc bulk=$bulk_ok" > "$LASTRUN" ;;
  live) echo "$STARTED exit=$rc transcripts=$transcripts_ok bulk=lane" > "$LASTRUN" ;;
  *) echo "$STARTED exit=$rc transcripts=$transcripts_ok bulk=$bulk_ok" > "$LASTRUN" ;;
esac
exit $rc
