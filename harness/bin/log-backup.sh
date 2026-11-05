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
#   LOG_BACKUP_VERSIONS     exactly 0 turns off versions/STAMP (loud warning); anything else keeps them
# Freshness contract: log-backup.last-ok is written (atomically, with the run START time) only after every source
# copied cleanly and at least one primary source (.claude/projects or .codex/sessions) was copied. A run skipped
# because another run holds the lock writes log-backup.last-skip and leaves last-ok alone.
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

mkdir -p "$LOGDIR" || { echo "log-backup: cannot create $LOGDIR" >&2; exit 1; }
chmod 700 "$LOGDIR" 2>/dev/null
# Never let an inherited rclone option redirect or reconfigure a run; only the config file location passes through.
for v in $(env | sed -n 's/^\(RCLONE_[A-Za-z0-9_]*\)=.*/\1/p'); do
  [ "$v" = RCLONE_CONFIG ] || unset "$v"
done
say() { printf '%s %s\n' "$(date -u +%FT%TZ)" "$1" >> "$LOG"; }
fail() { say "$1"; echo "log-backup: $1" >&2; echo "$STARTED exit=$2" > "$LOGDIR/log-backup.last-run"; exit "$2"; }

file_age() { # seconds since modification of $1; BSD stat on Darwin, GNU stat elsewhere
  local m
  if [ "$(uname)" = Darwin ]; then m=$(stat -f %m "$1" 2>/dev/null); else m=$(stat -c %Y "$1" 2>/dev/null); fi
  [ -n "$m" ] || { echo 0; return; }
  echo $(( $(date +%s) - m ))
}

holder_alive() { # pid $1 is running and is a log-backup run (a recycled pid belongs to something else)
  kill -0 "$1" 2>/dev/null || return 1
  ps -p "$1" -o args= 2>/dev/null | awk '$1 ~ /(^|\/)(ba|da|z)?sh$/ && $2 ~ /log-backup\.sh$/ {f=1} END {exit !f}'
}

acquire_lock() {
  if mkdir "$LOCKD" 2>/dev/null; then echo $$ > "$LOCKD/pid"; return 0; fi
  local holder age
  holder=$(cat "$LOCKD/pid" 2>/dev/null)
  age=$(file_age "$LOCKD")
  if [ -n "$holder" ]; then
    holder_alive "$holder" && [ "$age" -lt $STALE_LOCK_SECONDS ] && return 1
  elif [ "$age" -lt 60 ]; then
    return 1 # the owner has created the directory but not yet written its pid
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

if ! acquire_lock; then
  say "skipped: another backup run holds the lock (this is not a successful backup)"
  date -u +%FT%TZ > "$LOGDIR/log-backup.last-skip"
  exit 0
fi
trap '[ "$(cat "$LOCKD/pid" 2>/dev/null)" = "$$" ] && { rm -f "$LOCKD/pid"; rmdir "$LOCKD" 2>/dev/null; }' EXIT

command -v "$RCLONE" >/dev/null 2>&1 || fail "rclone not found (set LOG_BACKUP_RCLONE or fix PATH)" 127
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
for src in .claude/projects .claude/wals .claude/history.jsonl .codex/sessions .codex/archived_sessions .codex/history.jsonl .agent-harness/work \
    .agent-harness/work-assignments.json .agent-harness/work-ledger.json .agent-harness/work-ledger.events.jsonl \
    .agent-harness/work-ledger.archive.jsonl .agent-harness/work-ledger.failures.jsonl .agent-harness/work-ledger.spool.jsonl; do
  [ -e "$HOME/$src" ] || [ -L "$HOME/$src" ] || continue
  if [ -L "$HOME/$src" ]; then say "refusing symlinked source root: $src"; ok=1; continue; fi
  if [ -d "$HOME/$src" ]; then dst="$R/$src"; else dst="$R/$(dirname "$src")"; fi
  args=(copy --dropbox-batch-mode sync --dropbox-batch-size 100 --tpslimit 2 --transfers 2 --checkers 4
    --retries 10 --retries-sleep 30s --low-level-retries 20 --contimeout 60s --timeout 300s --log-file "$LOG" --log-level NOTICE --exclude-from "$EXCLUDES" --ignore-case)
  if [ "${LOG_BACKUP_VERSIONS:-1}" != 0 ]; then args+=(--backup-dir "$R/versions/$STAMP/$src"); fi
  # Actively written files (live transcripts, WALs) can change mid-upload and Dropbox can rate-limit: retry the
  # source with a pause before calling it a failure. A source that still fails makes the whole run non-fresh.
  attempt=0 copied=0
  while :; do
    if "$RCLONE" "${args[@]}" -- "$HOME/$src" "$dst" </dev/null; then copied=1; break; fi
    attempt=$((attempt + 1))
    [ $attempt -le "${LOG_BACKUP_RETRIES:-2}" ] || break
    say "copy of $src failed; retry $attempt after ${LOG_BACKUP_RETRY_SLEEP:-30}s (file changed mid-copy or rate limit)"
    sleep "${LOG_BACKUP_RETRY_SLEEP:-30}"
  done
  if [ $copied -eq 1 ]; then
    found=$((found + 1))
    case "$src" in .claude/projects|.codex/sessions)
      # An empty primary tree is not evidence of a backup.
      if [ -n "$(find "$HOME/$src" -type f -print -quit 2>/dev/null)" ]; then primary=$((primary + 1)); fi ;;
    esac
  else
    say "copy failed after $attempt attempts: $src"; ok=1
  fi
done
[ $primary -gt 0 ] || { say "no primary source (.claude/projects or .codex/sessions) was copied"; ok=1; }

say "run exit=$ok sources=$found remote=${R%%:*}"
echo "$STARTED exit=$ok" > "$LOGDIR/log-backup.last-run"
if [ $ok -eq 0 ]; then
  echo "$STARTED sources=$found remote=${R%%:*}" > "$LOGDIR/log-backup.last-ok.tmp.$$" \
    && mv "$LOGDIR/log-backup.last-ok.tmp.$$" "$LOGDIR/log-backup.last-ok"
fi
exit $ok
