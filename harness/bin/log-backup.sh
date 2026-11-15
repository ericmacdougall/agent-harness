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
#   LOG_BACKUP_LARGE_MB     live files of this many MiB or more (default 100) that changed since their last verified
#                           upload are sent by the large-file tier, not by tier 1 (goodqa#16123); 1-99999
#   LOG_BACKUP_LARGE_EVERY_SECONDS  least gap between large-tier passes (default 7200)
#   LOG_BACKUP_LARGE_BUDGET_SECONDS wall time of one pass (default 3000; in a scheduled run without the lane, the time
#                           that run has left). A file not sent in time stays pending, the pass is not complete, and
#                           log-backup.large-last-ok is not written (log_backup.py allows it 6 h)
#   LOG_BACKUP_LARGE_TPS    --tpslimit of a large upload (default 1), never above this host's share. A large upload never
#                           yields to tier 1 (a 500 MB upload restarted by every tier-1 run would never finish), so the
#                           share is split: the lane says "large PID" in log-backup.lane.state, never starts a large file
#                           while a tier-1 run holds the lock, and keeps at most a quarter of the share (share 1: 0.25/s)
#                           for the upload; a tier-1 run that starts during it copies with the rest (0.75/s).
#   Large files keep the versions/ move: it is a server-side move (no data sent), but it keeps one full old copy per pass
#   (about 6 GB a day for one 530 MB transcript at the default gap); see the review packet for why it is not skipped.
# Freshness contract, two tiers with their own markers. log-backup.last-ok (transcripts, WALs, ledgers) is written
# atomically with the run START time only after every tier-1 source copied cleanly and a primary source
# (.claude/projects or .codex/sessions) held files. log-backup.bulk-last-ok (archived sessions, narrowed work tree)
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
TRANSFERS=${LOG_BACKUP_TRANSFERS:-2}     # keep each host's share small (the Mac, dev2 and T2 together stay near 3/s)
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
# The large-file tier (goodqa#16123): live files of LARGE_MB or more that changed since their last verified upload. One
# active 530 MB transcript, re-sent whole every run, used up tier 1's budget on the Mac for two days, so such files go
# to their own tier: its own pass gap, budget, rate, marker (log-backup.large-last-ok) and 6 h limit in log_backup.py.
LARGE_MB=${LOG_BACKUP_LARGE_MB:-100}
LARGE_EVERY=${LOG_BACKUP_LARGE_EVERY_SECONDS:-7200}     # least gap between large-tier passes
LARGE_BUDGET=${LOG_BACKUP_LARGE_BUDGET_SECONDS:-3000}   # wall time of one pass, never past the run's own end
LARGE_TPS=${LOG_BACKUP_LARGE_TPS:-1}                    # large uploads use few operations; they do not yield to tier 1
printf '%s' "$LARGE_MB" | grep -Eq '^[1-9][0-9]{0,4}$' || { echo "log-backup: LARGE_MB must be a whole number from 1 to 99999" >&2; exit 2; }
printf '%s' "$LARGE_TPS" | grep -Eq '^[1-9][0-9]?$' || { echo "log-backup: LOG_BACKUP_LARGE_TPS must be a whole number from 1 to 99" >&2; exit 2; }
LARGE_BYTES=$(( LARGE_MB * 1048576 ))
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
for numeric in LARGE_EVERY LARGE_BUDGET BUDGET_SECONDS LOG_BACKUP_RETRIES LOG_BACKUP_RETRY_SLEEP BULK_EVERY JITTER DEADLINE_GRACE SLICE_RESERVE KILL_GRACE PERIOD LANE_BUDGET LANE_POLL; do
  # No leading zeros: bash would read 08 as octal and abort the arithmetic.
  if ! printf '%s' "${!numeric:-0}" | grep -Eq '^(0|[1-9][0-9]{0,4})$'; then
    echo "log-backup: $numeric must be a whole number of at most 5 digits without leading zeros" >&2; exit 2
  fi
done
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
trap 'release_locks "$LOCKD" "$LANE_LOCKD"; lane_clear_state; type large_cleanup >/dev/null 2>&1 && large_cleanup all' EXIT
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
say "stage size $(du -sk "$STAGE" 2>/dev/null | cut -f1) KiB"
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
  # account's write budget again (dev2 2026-11-05: one throttled copy ran for two days). The run stops copying here;
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
large_gate() { # 0: clear to start a large upload (state is "large"); 1: the time ran out while tier 1 held the lock.
  # A large upload does not stop for tier 1 (it would never finish), so it says so in the lane state ("large PID") and
  # never starts beside a tier-1 run: same protocol as lane_gate, whichever side acts second sees the other. A tier-1
  # run that starts during the upload reads that state and takes the rest of the host share (see large_share).
  local said=0
  while :; do
    lane_set_state large
    tier1_active || return 0
    lane_set_state idle
    [ $said -eq 1 ] || { say "a tier-1 run holds the lock; the large upload waits for it (one uploader at a time until it ends)"; said=1; }
    [ "$(time_left)" -ge "$MIN_SLICE" ] || return 1
    nap "$LANE_POLL"
  done
}
# The host's write share is split when a large upload and tier 1 run together: the large upload keeps LARGE_TPS but at
# most a quarter of the share, tier 1 gets the rest, so the two together never exceed the share (PR #261 review v3).
# rclone takes a fractional --tpslimit (share 1: 0.25 and 0.75).
large_share() { awk -v t="$1" -v l="$LARGE_TPS" 'BEGIN {c = t / 4; if (l < c) c = l; printf "%g", c}'; }
large_rate() { # the --tpslimit of a large upload: never above the host share (TPSLIMIT is capped by it already)
  if [ "$TIER" = bulk ]; then large_share "$TPSLIMIT"   # the lane: a tier-1 run can start beside it
  else awk -v t="$TPSLIMIT" -v l="$LARGE_TPS" 'BEGIN {printf "%g", (l < t ? l : t)}'; fi   # a scheduled run copies one thing at a time
}
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
    if [ "$TIER" = bulk ] && [ "${NO_YIELD:-0}" != 1 ] && ! lane_gate; then
      say "lane budget (${LANE_BUDGET}s) used up waiting for tier 1 before $rel; the next lane run continues"; ok=1; budget_hit=1; return
    fi
    if [ "$TIER" = bulk ] && [ "${NO_YIELD:-0}" = 1 ] && ! large_gate; then
      say "large tier: its time ran out waiting for tier 1 before $rel; it stays pending"; ok=1; budget_hit=1; return
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
    if [ "$TIER" = bulk ] && [ "${NO_YIELD:-0}" != 1 ]; then
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
  local rel="$1" st n cur total chunk
  shift
  local list_filters=() copy_args=()
  while [ $# -gt 0 ] && [ "$1" != -- ]; do list_filters+=("$1"); shift; done
  [ $# -gt 0 ] && shift
  copy_args=("$@")
  st="$BULK_STATE/$(bulk_key "$rel")"
  # The checkpoint directories are ours: real directories (never a link, so the fixed-name rm and mv below cannot reach
  # another tree), owned by us, made private (PR #261 F1 audit).
  bulk_dir "$BULK_STATE" && bulk_dir "$st" || { say "cannot create bulk state for $rel (it must be a real directory of ours, not a link)"; ok=1; hard_fail=1; return 1; }
  # A checkpoint belongs to one destination: another remote or host starts over.
  if [ "$(cat "$st/remote" 2>/dev/null)" != "$R" ]; then
    rm -f "$st/pending" "$st/cursor" "$st/done" "$st/listing" && printf '%s\n' "$R" > "$st/remote"
  fi
  # A pass listed with other exclude lists would send what they now exclude: list it again (the old `done` stays, so
  # files already verified are still not sent twice). A checkpoint from before this marker existed counts as changed.
  if [ -s "$st/pending" ] && [ "$(cat "$st/filters" 2>/dev/null)" != "$FILTER_ID" ]; then
    say "$rel: the exclude lists changed since this pass was listed; listing it again"
    rm -f "$st/pending" "$st/cursor" "$st/chunk" "$st/chunk.paths" "$st/listing"
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
      upload "$HOME/$rel" "$rel" "${copy_args[@]+"${copy_args[@]}"}" --files-from-raw "$st/chunk.paths" --no-traverse
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
  return 0
}

# ---- the large-file tier (goodqa#16123) ---------------------------------------------------------------------------------
# State: $LARGE_STATE/done.tsv holds "path<TAB>size<TAB>mtime" of every large file whose copy rclone reported complete
# (exit 0 after its own checksum verification), written only after that. A file is pending when its listed size or time
# differs from its last record, so a file whose upload failed, or that changed since, is pending and never counted as
# backed up. log-backup.large-last-ok gets the pass START time only when no file is left pending.
#
# Safety (PR #261 review F1): the snapshot area is a private directory this script creates or verifies (a real directory,
# ours, mode 0700, no link on the way from $HOME), each run works in a fresh mktemp directory below it, a snapshot is a
# flat file in a fresh directory of its own (cp -n; nothing can exist there to follow), and cleanup removes only the
# files and directories this run created, by name (rm -f of one file, rmdir), never a recursive delete.
LARGE_STATE="$LOGDIR/log-backup.large.d"
LARGE_STAGE="$(printf '%s' "$STAGE" | sed 's#//*#/#g; s#/$##')-large"
large_ok=0
LARGE_RUN= LARGE_CUR= LARGE_FILE=
owner_of() { if [ "$(uname)" = Darwin ]; then stat -f %u "$1" 2>/dev/null; else stat -c %u "$1" 2>/dev/null; fi; }
mode_of() { if [ "$(uname)" = Darwin ]; then stat -f %Lp "$1" 2>/dev/null; else stat -c %a "$1" 2>/dev/null; fi; }
size_of() { if [ "$(uname)" = Darwin ]; then stat -f %z "$1" 2>/dev/null; else stat -c %s "$1" 2>/dev/null; fi; }
mtime_of() { if [ "$(uname)" = Darwin ]; then stat -f %m "$1" 2>/dev/null; else stat -c %Y "$1" 2>/dev/null; fi; }
no_link_below() { # no_link_below ROOT PATH: 0 when no component of PATH below ROOT is a symlink (stops at the first
  # component that does not exist); 1 when one is, or PATH is not below ROOT. ROOT itself is not examined.
  local root=$1 path=$2 rest cur part
  case "$path" in "$root") return 0 ;; "$root"/*) ;; *) return 1 ;; esac
  rest=${path#"$root"/} cur=$root
  while [ -n "$rest" ]; do
    part=${rest%%/*}
    if [ "$part" = "$rest" ]; then rest=; else rest=${rest#*/}; fi
    [ -n "$part" ] || continue
    cur="$cur/$part"
    [ ! -L "$cur" ] || return 1
    [ -e "$cur" ] || return 0
  done
  return 0
}
bulk_dir() { # bulk_dir DIR: a real directory of ours below $HOME with no link on the way, created if missing, made 0700
  case "$1" in "$HOME"/?*) ;; *) return 1 ;; esac
  no_link_below "$HOME" "$1" || return 1
  [ -d "$1" ] || mkdir -- "$1" 2>/dev/null || return 1
  [ -d "$1" ] && [ ! -L "$1" ] && [ "$(owner_of "$1")" = "$(id -u)" ] && chmod 700 "$1"
}
private_dir() { # private_dir DIR: DIR exists as a real directory of ours with mode 0700 (created without -p when it
  # is missing), below $HOME with no link on the way and an existing parent; nothing is chmodded or followed
  local d=$1 parent
  case "$d" in "$HOME"/?*) ;; *) return 1 ;; esac
  case "$d" in *..*|*[[:cntrl:]]*) return 1 ;; esac
  parent=$(dirname "$d")
  no_link_below "$HOME" "$parent" && [ -d "$parent" ] && [ ! -L "$parent" ] || return 1
  [ ! -L "$d" ] || return 1
  if [ ! -e "$d" ]; then (umask 077; mkdir -- "$d") 2>/dev/null || return 1; fi
  [ -d "$d" ] && [ ! -L "$d" ] && [ "$(owner_of "$d")" = "$(id -u)" ] && [ "$(mode_of "$d")" = 700 ]
}
bounded() { # bounded SECONDS CMD [ARGS...]: CMD runs with stdin closed and is stopped (TERM, then KILL after KILL_GRACE)
  # when SECONDS pass. Status: CMD's own, or 124 when it ran out of time. CMD must be a program, not a shell function
  # (a stopped function would leave its child running).
  local secs=$1 flag="$LOGDIR/.log-backup${TAG}.bounded.$$" rc
  shift
  [ "$secs" -ge 1 ] 2>/dev/null || secs=1
  rm -f "$flag"
  "$@" </dev/null &
  copy_pid=$!
  ( nap=
    trap 'kill ${nap:+"$nap"} 2>/dev/null; exit 0' TERM
    sleep "$secs" & nap=$!
    wait "$nap" || exit 0
    touch "$flag"
    kill -TERM "$copy_pid" 2>/dev/null || exit 0
    sleep "$KILL_GRACE" & nap=$!
    wait "$nap" || exit 0
    kill -KILL "$copy_pid" 2>/dev/null ) </dev/null >/dev/null 2>&1 &
  dog_pid=$!
  wait "$copy_pid"; rc=$?
  kill "$dog_pid" 2>/dev/null; wait "$dog_pid" 2>/dev/null
  dog_pid= copy_pid=
  if [ -e "$flag" ]; then rm -f "$flag"; return 124; fi
  return $rc
}
large_cleanup() { # large_cleanup [all]: removes only what this run created, by name: the current snapshot file and its
  # directory, and with "all" the run directory too (rmdir: it only goes when empty)
  if [ -n "$LARGE_FILE" ] && no_link_below "$LARGE_STAGE" "$LARGE_FILE"; then rm -f -- "$LARGE_FILE"; fi
  if [ -n "$LARGE_CUR" ] && no_link_below "$LARGE_STAGE" "$LARGE_CUR"; then rmdir -- "$LARGE_CUR" 2>/dev/null; fi
  LARGE_CUR= LARGE_FILE=
  if [ "${1:-}" = all ] && [ -n "$LARGE_RUN" ] && no_link_below "$LARGE_STAGE" "$LARGE_RUN"; then rmdir -- "$LARGE_RUN" 2>/dev/null; LARGE_RUN=; fi
  return 0
}
large_fail() { say "large tier: $1"; large_ok=1; }
large_pass() {
  local st="$LARGE_STATE" lst src rc key size mt snap base idx=0 sent=0 total left n
  : > "$LOGDIR/log-backup.large-last-try"
  private_dir "$st" || { large_fail "its state directory is not a private directory of ours; nothing was sent"; return 1; }
  for n in "$HOME/.claude" "$HOME/.codex" "$HOME/.agent-harness/work"; do
    case "$LARGE_STAGE/" in "$n/"*) large_fail "the large stage is inside $n"; return 1 ;; esac
    case "$n/" in "$LARGE_STAGE/"*) large_fail "the large stage contains $n"; return 1 ;; esac
  done
  private_dir "$LARGE_STAGE" || { large_fail "the large stage is not a private directory of ours (not a link, mode 0700); nothing was sent"; return 1; }
  n=$(find "$LARGE_STAGE" -mindepth 1 -maxdepth 1 2>/dev/null | wc -l | tr -d ' ')
  [ "${n:-0}" = 0 ] || say "large tier: $n leftover entries in the large stage from an interrupted run or an older version; they are not removed"
  lst="$st/listing"
  [ ! -L "$lst" ] && [ ! -L "$st/done.tsv" ] && [ ! -L "$st/one.tmp" ] && [ ! -L "$st/pending" ] && [ ! -L "$st/pending.tmp" ] \
    || { large_fail "its state directory holds a link"; return 1; }
  : > "$lst" && touch "$st/done.tsv" || { large_fail "cannot write its listing"; return 1; }
  for src in "${LIVE[@]}"; do
    if [ -L "$HOME/$src" ]; then continue; fi
    left=$(time_left)
    if [ "$left" -lt "$MIN_SLICE" ]; then large_fail "its budget is used up before listing $src; nothing is marked"; return 1; fi
    if [ -d "$HOME/$src" ]; then
      bounded "$left" "$RCLONE" lsf -R --files-only --format pst --separator $'\t' --min-size "${LARGE_MB}M" --exclude-from "$EXCLUDES" --ignore-case \
        -- "$HOME/$src" > "$st/one.tmp" 2>> "$LOG"
      rc=$?
      if [ $rc -eq 124 ]; then large_fail "listing $src ran out of time; nothing is marked"; return 1; fi
      if [ $rc -ne 0 ]; then large_fail "listing $src failed (rclone exit $rc)"; return 1; fi
      # A path with a tab or newline cannot be tracked: it fails the pass (never silently counted as backed up).
      awk -F'\t' -v s="$src" 'NF == 3 {print s "/" $1 "\t" $2 "\t" $3} NF != 3 {bad++} END {exit bad > 0}' "$st/one.tmp" >> "$lst" \
        || { large_fail "$src has a large file whose path has a tab or newline; it cannot be tracked"; return 1; }
    elif [ -f "$HOME/$src" ]; then   # a standalone live file (history, ledgers): the same threshold
      size=$(size_of "$HOME/$src"); mt=$(mtime_of "$HOME/$src")
      printf '%s' "$size" | grep -Eq '^[0-9]+$' && printf '%s' "$mt" | grep -Eq '^[0-9]+$' \
        || { large_fail "cannot read the size of $src"; return 1; }
      if [ "$size" -ge "$LARGE_BYTES" ]; then printf '%s\t%s\t%s\n' "$src" "$size" "$mt" >> "$lst" || { large_fail "cannot write its listing"; return 1; }; fi
    fi
  done
  awk -F'\t' 'FILENAME == ARGV[1] {have[$1] = $2 "\t" $3; next} !($1 in have) || have[$1] != $2 "\t" $3' "$st/done.tsv" "$lst" > "$st/pending.tmp" \
    && mv "$st/pending.tmp" "$st/pending" || { large_fail "cannot work out what is pending"; return 1; }
  total=$(wc -l < "$st/pending"); total=${total//[[:space:]]/}
  printf '%s' "$total" | grep -Eq '^[0-9]+$' || { large_fail "cannot count what is pending"; return 1; }
  say "large tier: $total of $(wc -l < "$lst" | tr -d ' ') large files (${LARGE_MB} MiB or more) changed since their last upload"
  if [ "$total" -gt 0 ]; then
    LARGE_RUN=$(mktemp -d "$LARGE_STAGE/run.XXXXXX" 2>/dev/null) && [ -d "$LARGE_RUN" ] && [ ! -L "$LARGE_RUN" ] \
      || { LARGE_RUN=; large_fail "cannot create this run's snapshot directory"; return 1; }
  fi
  while IFS=$'\t' read -r key size mt; do
    left=$(time_left)
    if [ "$left" -lt "$MIN_SLICE" ]; then large_fail "its budget is used up; the files left stay pending"; break; fi
    if [ ! -f "$HOME/$key" ] || [ -L "$HOME/$key" ]; then say "large tier: $key is gone; nothing to send"; continue; fi
    idx=$((idx + 1)); base=${key##*/}
    LARGE_CUR="$LARGE_RUN/$idx" LARGE_FILE="$LARGE_RUN/$idx/$base"
    if ! mkdir -- "$LARGE_CUR" 2>/dev/null; then large_fail "cannot create the snapshot directory for $key"; LARGE_CUR= LARGE_FILE=; continue; fi
    # cp -n never replaces anything (the directory is new, so nothing is there). The first attempt clones (APFS -c, or a
    # reflink: no space and no data copied) and may leave a partial file when it fails; that file is removed by name
    # before the plain copy, which would otherwise accept it as already there (PR #261 review v2 F2).
    if [ "$(uname)" = Darwin ]; then clone=-c; else clone=--reflink=always; fi
    bounded "$left" cp -n "$clone" -p -- "$HOME/$key" "$LARGE_FILE" 2>/dev/null; rc=$?
    if [ $rc -ne 0 ] && [ $rc -ne 124 ]; then
      if no_link_below "$LARGE_STAGE" "$LARGE_FILE"; then rm -f -- "$LARGE_FILE"; fi
      if [ -e "$LARGE_FILE" ] || [ -L "$LARGE_FILE" ]; then large_fail "cannot clear the failed snapshot of $key"; large_cleanup; continue; fi
      left=$(time_left)
      if [ "$left" -lt "$MIN_SLICE" ]; then large_fail "its budget is used up; $key stays pending"; large_cleanup; break; fi
      bounded "$left" cp -n -p -- "$HOME/$key" "$LARGE_FILE"; rc=$?
    fi
    if [ $rc -eq 124 ]; then large_fail "the snapshot of $key ran out of time; it stays pending"; large_cleanup; break; fi
    if [ $rc -ne 0 ] || [ ! -f "$LARGE_FILE" ] || [ -L "$LARGE_FILE" ]; then large_fail "cannot snapshot $key"; large_cleanup; continue; fi
    # The file can only have grown since it was listed: a shorter snapshot is a truncated copy, never uploaded or recorded.
    snapsize=$(size_of "$LARGE_FILE")
    if ! printf '%s' "$snapsize" | grep -Eq '^[0-9]+$' || [ "$snapsize" -lt "$size" ]; then
      large_fail "the snapshot of $key is shorter than the listed ${size} bytes; it is not uploaded and stays pending"; large_cleanup; continue
    fi
    before=$REFUSED_N
    upload "$LARGE_FILE" "$key" --tpslimit "$(large_rate)" --transfers 1
    if [ "$copied" -eq 1 ] && [ "$REFUSED_N" -eq "$before" ]; then
      printf '%s\t%s\t%s\n' "$key" "$size" "$mt" >> "$st/done.tsv" && sent=$((sent + 1)) || large_fail "cannot record $key as sent"
    else
      large_fail "$key was not backed up"
    fi
    large_cleanup
    [ "$budget_hit" -eq 0 ] || break
  done < "$st/pending"
  large_cleanup all
  if [ $large_ok -eq 0 ]; then
    echo "$STARTED" > "$LOGDIR/log-backup.large-last-ok.tmp.$$" && mv "$LOGDIR/log-backup.large-last-ok.tmp.$$" "$LOGDIR/log-backup.large-last-ok" \
      || { large_fail "cannot write its marker"; return 1; }
    say "large tier: pass complete ($sent file(s) sent)"
  else
    say "large tier: pass incomplete ($sent file(s) sent); log-backup.large-last-ok is not written"
  fi
}
large_tier() {
  local try="$LOGDIR/log-backup.large-last-try" age saved_end=$WALL_END lend rc
  # The completion state belongs to one destination ($R: remote, path and host), like the bulk checkpoint (PR #261
  # review v2 F1). When it changes, nothing sent elsewhere counts: the record, the pass gap and the marker are reset
  # so the first pass to the new destination starts now and no old marker vouches for it.
  private_dir "$LARGE_STATE" || { large_fail "its state directory is not a private directory of ours; nothing was sent"; return 1; }
  if [ "$(cat "$LARGE_STATE/remote" 2>/dev/null)" != "$R" ]; then
    [ ! -e "$LARGE_STATE/remote" ] || say "large tier: the destination changed; its completion record, pass gap and marker are reset"
    rm -f -- "$LARGE_STATE/done.tsv" "$try" "$LOGDIR/log-backup.large-last-ok" \
      && printf '%s\n' "$R" > "$LARGE_STATE/remote.tmp.$$" && mv "$LARGE_STATE/remote.tmp.$$" "$LARGE_STATE/remote" \
      || { large_fail "cannot reset its state for the new destination"; return 1; }
  fi
  if [ -e "$try" ]; then
    age=$(raw_age "$try")
    if [ -n "$age" ] && [ "$age" -ge 0 ] && [ "$age" -lt "$LARGE_EVERY" ]; then
      say "large tier skipped: last pass started ${age}s ago (every ${LARGE_EVERY}s)"; return 0
    fi
  fi
  if [ "$(time_left)" -lt "$MIN_SLICE" ]; then say "large tier deferred: no run time left"; return 0; fi
  # The pass deadline starts here, before the first listing: listing, snapshot and upload all run inside it.
  lend=$(( $(date +%s) + LARGE_BUDGET + DEADLINE_GRACE + KILL_GRACE ))
  [ "$lend" -ge "$WALL_END" ] || WALL_END=$lend
  NO_YIELD=1
  large_pass; rc=$?
  NO_YIELD=0 WALL_END=$saved_end
  large_cleanup all
  return $rc
}

bulk_try="$LOGDIR/log-backup.bulk-last-try"
bulk_due() { # the hourly gap has passed (or a pass stopped on the budget cleared it)
  local a
  [ -e "$bulk_try" ] || return 0
  a=$(raw_age "$bulk_try")
  [ -z "$a" ] || [ "$a" -lt 0 ] || [ "$a" -ge "$BULK_EVERY" ]
}
lane_yields() { # the live lane run $1 is one that yields to tier 1 (it keeps a state file under its pid)
  case "$(cat "$LANE_STATE" 2>/dev/null)" in "copying $1"|"idle $1"|"large $1") return 0 ;; esac
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
  if [ "$(cat "$LANE_STATE" 2>/dev/null)" = "large $lane_pid" ]; then
    # A large upload is in flight and does not pause for tier 1. This host's write share is split, not doubled: the
    # upload keeps its part (large_share), tier 1 copies with the rest (PR #261 review v3 F2).
    large_part=$(large_share "$TPSLIMIT")
    TPSLIMIT=$(awk -v t="$TPSLIMIT" -v c="$large_part" 'BEGIN {printf "%g", t - c}')
    say "a large-file upload is in flight in the bulk lane (pid $lane_pid) and does not pause; the host share is split: tier 1 copies at ${TPSLIMIT}/s, the upload keeps at most ${large_part}/s"
  elif lane_yields "$lane_pid"; then
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
for src in "${LIVE[@]}"; do
  [ -e "$HOME/$src" ] || [ -L "$HOME/$src" ] || continue
  later=$((later - 1)); [ $later -ge 0 ] || later=0
  # A later copy that hangs costs its slice, both graces and about 3 s to snapshot the source first.
  RESERVE=$(( later * (MIN_SLICE + DEADLINE_GRACE + KILL_GRACE + 3) ))
  if [ -L "$HOME/$src" ]; then say "refusing symlinked source root: $src"; ok=1; continue; fi
  snap="$STAGE/$src"
  # A link anywhere below the stage root would let mkdir, rsync, cp or rm reach a file outside the stage (PR #261 F1):
  # refuse the source, never follow it. The stage is ours; a link in it is a fault to fix by hand, not to guess about.
  no_link_below "$STAGE" "$snap" || { say "the stage path for $src holds a symlink; nothing was staged or sent for it (remove the link by hand)"; ok=1; continue; }
  mkdir -p "$(dirname "$snap")" || { say "cannot stage $src"; ok=1; continue; }
  if [ -d "$HOME/$src" ]; then
    # rsync -a keeps symlinks as links; rclone never follows them. Exit 24 = a file vanished mid-copy (not an error).
    # --temp-dir sits outside every uploaded tree: a crash mid-copy leaves its partial files there, never beside data
    # that rclone would upload as current. rsync renames within the stage volume, so a full disk fails the copy
    # (exit 11 or 23, source skipped, run non-fresh) instead of leaving a truncated file in place.
    # The trash directory is pruned before the catch-all directory include below (first rsync rule wins), at any depth (B7).
    mkdir -p "$STAGE/.rsync-tmp" || { say "cannot create the stage temp directory"; ok=1; continue; }
    # Files of LARGE_MB or more belong to the large-file tier (goodqa#16123). Tier 1 must neither stage nor send them,
    # and a stale smaller stage copy of a file that has since grown must go, or tier 1 would send that old copy over the
    # remote's newer one. A failed search leaves that unknown, so the source is not backed up this run.
    large_list="$STAGE/.rsync-tmp/large.$$" large_excl="$STAGE/.rsync-tmp/large-excl.$$"
    if ! find "$HOME/$src" -type f -size +"$(( LARGE_BYTES - 1 ))"c -print0 > "$large_list" 2>/dev/null; then
      say "cannot search $src for large files; skipped, the run is not fresh"; ok=1; continue
    fi
    : > "$large_excl" || { say "cannot write the large-file exclude list"; ok=1; continue; }
    stage_link=0
    while IFS= read -r -d '' lf; do
      lrel=${lf#"$HOME/$src"}
      case "$lrel" in *[\\*?\[\]]*|*$'\n'*) ;; *) printf '%s\n' "$lrel" >> "$large_excl" ;; esac
      # One file, by name, and only when no component of its stage path is a link (PR #261 F1).
      if ! no_link_below "$STAGE" "$snap$lrel"; then stage_link=1; break; fi
      rm -f -- "$snap$lrel"
    done < "$large_list"
    if [ $stage_link -eq 1 ]; then
      rm -f "$large_list" "$large_excl"
      say "the stage path for $src holds a symlink below it; nothing was staged or sent for it (remove the link by hand)"; ok=1; continue
    fi
    rsync -a --temp-dir="$STAGE/.rsync-tmp" --exclude='.[gG][oO][oO][dD][qQ][aA]-[tT][rR][aA][sS][hH]/' --exclude-from="$large_excl" --include='*/' --exclude-from="$RSYNC_EXCLUDES" -- "$HOME/$src/" "$snap/" </dev/null; rc=$?
    rm -f "$large_list" "$large_excl"
    if [ $rc -eq 23 ]; then
      # Partial transfer (e.g. one unreadable file): rsync renames files into place, so the stage is consistent.
      # Back up what was staged, but withhold last-ok for this run.
      say "snapshot partial (rsync exit 23): $src"; ok=1
    elif [ $rc -ne 0 ] && [ $rc -ne 24 ]; then
      say "snapshot failed (rsync exit $rc): $src"; ok=1; continue
    fi
  else
    # A standalone file of LARGE_MB or more (history, ledgers) belongs to the large tier like a large file in a tree.
    fsz=$(size_of "$HOME/$src")
    if [ -f "$HOME/$src" ] && printf '%s' "$fsz" | grep -Eq '^[0-9]+$' && [ "$fsz" -ge "$LARGE_BYTES" ]; then
      [ ! -e "$snap" ] || rm -f -- "$snap"   # a stale smaller stage copy (no link on its path: checked above)
      continue
    fi
    cp -p "$HOME/$src" "$snap" || { say "snapshot failed: $src"; ok=1; continue; }
  fi
  if [ -d "$HOME/$src" ]; then upload "$snap" "$src" --max-size "$(( LARGE_BYTES - 1 ))"; else upload "$snap" "$src"; fi
done
# Tier 1 (transcripts, WALs, ledgers) is done: mark it on its own, so a slow bulk pass can never hide a gap here.
[ $primary -gt 0 ] || { say "no primary source (.claude/projects or .codex/sessions) was copied"; ok=1; }
say "transcripts exit=$ok sources=$found remote=${R%%:*}"
transcripts_ok=$ok
if [ $ok -eq 0 ]; then
  echo "$STARTED sources=$found remote=${R%%:*}" > "$LOGDIR/log-backup.last-ok.tmp.$$" \
    && mv "$LOGDIR/log-backup.last-ok.tmp.$$" "$LOGDIR/log-backup.last-ok"
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
# The large-file tier runs before the bulk sources, which can take days, with its own budget, so they never starve it.
# Its failures stay its own: they do not touch the bulk marker or the bulk tier's hourly gap.
if [ $bulk_ran -eq 1 ]; then
  large_tier
  ok=0 budget_hit=0 hard_fail=0 RESERVE=0
fi
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
{ [ $transcripts_ok -eq 0 ] && [ $bulk_ok -eq 0 ] && [ $large_ok -eq 0 ]; } || rc=1
case "$TIER" in
  bulk) echo "$STARTED exit=$rc bulk=$bulk_ok large=$large_ok" > "$LASTRUN" ;;
  live) echo "$STARTED exit=$rc transcripts=$transcripts_ok bulk=lane" > "$LASTRUN" ;;
  *) echo "$STARTED exit=$rc transcripts=$transcripts_ok bulk=$bulk_ok large=$large_ok" > "$LASTRUN" ;;
esac
exit $rc
