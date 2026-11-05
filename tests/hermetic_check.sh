#!/bin/bash
# Hermeticity gate (GoodQA #14560 AC-4). Usage: tests/hermetic_check.sh PYTHON TREE [PATTERN]
# PATTERN (optional) is a unittest discover -p glob (one module, or a base-tree control); default is the full suite.
# The suite runs with env -i, a scratch HOME, AGENT_HARNESS_USAGE_DIR and HARNESS_SUITE_PINNED set before Python starts,
# TMPDIR unset (HC_TMPDIR overrides), an ssh recorder first on PATH that records and fails, and a throwaway virtualenv
# whose site-packages load tests/hermetic_audit/hermetic_audit_hook.py through a .pth file. The hook reads its
# configuration from a JSON file, so every Python child is covered whatever its environment (-I, env={}, replaced
# PYTHONPATH, grandchildren) and records each write, mkdir, rename, remove (including dir_fd forms) inside the real
# state dirs, swallowed or not. Every disposable file lives in a fresh mktemp dir outside ~/.agent-harness; the dir is
# printed as REPORT_DIR.
# PASS = suite rc 0 with "Ran N" (N>0) and a final OK line, 0 ssh calls, an empty audit log (opendir records count), the hook
# loaded at least twice, and two canaries: a write into a temp "protected" dir is recorded,
# and the suite's own configuration loads with protected=9. Every FAIL path exits non-zero.
# Limits: ssh is recorded only when found through PATH (bwrap runs in a network namespace with a working loopback, so
# there is no outside network on dev2; the macOS gate does not cut the network); the temp dir is left behind for inspection (it is disposable
# and under TMPDIR; if TMPDIR is under the real home the run is refused with exit 6 after creating that empty dir); a child that execs another interpreter by absolute path (for example /usr/bin/python3) or a non-Python writer is
# not audited; the before/after listing of the real dirs is informational because other agents write there.
# Optional write protection (EPERM or EROFS, never a kill signal): HC_SANDBOX=1 (macOS sandbox-exec: deny writes below the
# real home except the tree, its git common dir and the temp dir; /bin/ps cannot be exec'd inside any sandbox-exec
# profile, so use it for single modules and failing controls) and HC_BWRAP=1 (Linux bubblewrap, no outside network: the whole filesystem is
# read-only except the tree, its git common dir, the temp dir and a tmpfs /tmp; usable for the full suite).
# HC_UNPINNED=1 runs the old tests with the real HOME and no pin (failing controls on a base tree only) and REQUIRES
# HC_SANDBOX=1 or HC_BWRAP=1 so a leak is blocked rather than written.
set -u
self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
hookdir="$(dirname "$self")/hermetic_audit"
py=$1; tree=$2; pattern=${3:-}
R=$(/usr/bin/python3 -c 'import os,pwd;print(os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))')
TREE=$(cd "$tree" && pwd -P) || { echo "tree not found: $tree"; exit 9; }
GITCOMMON=$(cd "$TREE" && cd "$(git rev-parse --git-common-dir 2>/dev/null || echo .)" && pwd -P) || { echo "git dir lookup failed"; exit 9; }
[ -n "$TREE" ] && [ -n "$GITCOMMON" ] && [ -n "$R" ] || { echo "empty tree, git dir or home"; exit 9; }
PROT=("$R/.claude" "$R/.codex" "$R/.gitconfig" "$R/.ssh" "$R/.agent-harness/usage" "$R/.agent-harness/state" "$R/.agent-harness/logs" "$R/.agent-harness/commit-policy" "$R/.agent-harness/wals")
for p in "$GITCOMMON" "$TREE"; do
  for q in "${PROT[@]}"; do
    case "$p/" in "$q/"*) echo "tree or git dir is inside a protected real state dir: $p"; exit 6;; esac
    case "$q/" in "$p/"*) echo "a protected real state dir is inside the tree or git dir: $q"; exit 6;; esac
  done
done
if [ -n "${HC_UNPINNED:-}" ] && [ -z "${HC_SANDBOX:-}" ] && [ -z "${HC_BWRAP:-}" ]; then echo "HC_UNPINNED requires HC_SANDBOX=1 or HC_BWRAP=1"; exit 5; fi
[ -f "$hookdir/hermetic_audit_hook.py" ] || { echo "audit hook missing next to the script: $hookdir"; exit 4; }
# Every disposable file (scratch HOME, ssh recorder, audit logs, venv, profile, snapshots) lives in a fresh temp dir.
LOGS=$(mktemp -d "${TMPDIR:-/tmp}/hermetic-check.XXXXXX") || { echo "mktemp failed"; exit 9; }
LOGS_REAL=$(cd "$LOGS" && pwd -P) || { echo "temp dir lookup failed"; exit 9; }
[ -n "$LOGS_REAL" ] || { echo "empty temp dir"; exit 9; }
case "$LOGS_REAL/" in "$R/"*) echo "temp dir is under the real home ($LOGS_REAL); set TMPDIR outside it"; exit 6;; esac
scratch="$LOGS_REAL/home"; shim="$LOGS_REAL/shim"; mkdir -p "$scratch" "$shim" || { echo "mkdir failed"; exit 9; }
printf '#!/bin/sh\necho "$@" >> %s/ssh.calls\nexit 255\n' "$LOGS_REAL" > "$shim/ssh"; chmod +x "$shim/ssh"
"$py" -m venv --without-pip "$LOGS_REAL/venv" || { echo "venv creation failed"; exit 4; }
site=$(echo "$LOGS_REAL"/venv/lib/python*/site-packages)
[ -d "$site" ] || { echo "venv site-packages not found"; exit 4; }
vpy="$LOGS_REAL/venv/bin/python"
cp "$hookdir/hermetic_audit_hook.py" "$site/hermetic_audit_hook.py" || { echo "hook copy failed"; exit 4; }
echo 'import hermetic_audit_hook' > "$site/hermetic_audit.pth"
json_list() { local out="" item; for item in "$@"; do out="$out${out:+,}\"$item\""; done; echo "[$out]"; }
# canary 1: a write into a temp stand-in for a protected dir must be recorded by this interpreter and venv
cdir="$LOGS_REAL/canary-protected"; mkdir -p "$cdir"
echo "{\"log\":\"$LOGS_REAL/canary.log\",\"protect\":[\"$cdir\"],\"allow\":[]}" > "$site/hermetic_audit_config.json"
env -i PATH="/usr/bin:/bin" "$vpy" -c "open('$cdir/x','w').write('1')"
grep -q "open" "$LOGS_REAL/canary.log" 2>/dev/null || { echo "audit canary not recorded: gate cannot detect writes"; exit 7; }
# the suite configuration: the real protected set (explicit, so a failed home lookup cannot empty it)
echo "{\"log\":\"$LOGS_REAL/audit.log\",\"loaded_log\":\"$LOGS_REAL/loaded.log\",\"protect\":$(json_list "${PROT[@]}"),\"allow\":[]}" > "$site/hermetic_audit_config.json"
env -i PATH="/usr/bin:/bin" "$vpy" -c "pass"
grep -q "protected=9" "$LOGS_REAL/loaded.log" 2>/dev/null || { echo "audit hook did not load with the 9 protected paths"; exit 7; }
pin=(HOME="$scratch" AGENT_HARNESS_USAGE_DIR="$scratch/usage" HARNESS_SUITE_PINNED=1)
[ -n "${HC_UNPINNED:-}" ] && pin=(HOME="$R")
envtmp=(); [ -n "${HC_TMPDIR:-}" ] && envtmp=(TMPDIR="$HC_TMPDIR")
args=(discover -s tests); [ -n "$pattern" ] && args+=(-p "$pattern")
wrap=()
if [ -n "${HC_SANDBOX:-}" ]; then
  printf '(version 1)\n(allow default)\n(deny file-write* (subpath "%s"))\n(allow file-write* (subpath "%s") (subpath "%s") (subpath "%s"))\n' "$R" "$TREE" "$LOGS_REAL" "$GITCOMMON" > "$LOGS_REAL/deny.sb"
  wrap=(sandbox-exec -f "$LOGS_REAL/deny.sb")
elif [ -n "${HC_BWRAP:-}" ]; then
  wrap=(bwrap --unshare-net --ro-bind / / --dev /dev --proc /proc --tmpfs /tmp --bind "$TREE" "$TREE" --bind "$LOGS_REAL" "$LOGS_REAL" --bind "$GITCOMMON" "$GITCOMMON")
fi
if [ "$(uname)" = Darwin ]; then statfmt=(-f '%N %z %m'); else statfmt=(-c '%n %s %Y'); fi
snap() { for d in "$R/.agent-harness/state" "$R/.agent-harness/usage" "$R/.agent-harness/logs" "$R/.agent-harness/commit-policy" "$R/.claude/hooks" "$R/.codex"; do find "$d" -path '*__pycache__*' -prune -o -type f -exec stat "${statfmt[@]}" {} + 2>/dev/null; done | sort; }
snap > "$LOGS_REAL/before.snap"
cd "$TREE" || exit 9
${wrap[@]+"${wrap[@]}"} env -i "${pin[@]}" ${envtmp[@]+"${envtmp[@]}"} \
  PATH="$shim:$LOGS_REAL/venv/bin:/usr/bin:/bin" LANG=en_US.UTF-8 GIT_CONFIG_NOSYSTEM=1 \
  "$vpy" -m unittest "${args[@]}" > "$LOGS_REAL/suite.log" 2>&1
rc=$?
snap > "$LOGS_REAL/after.snap"; diff "$LOGS_REAL/before.snap" "$LOGS_REAL/after.snap" > "$LOGS_REAL/snap.diff"; d=$(wc -l < "$LOGS_REAL/snap.diff" | tr -d ' ')
ssh=0; [ -f "$LOGS_REAL/ssh.calls" ] && ssh=$(wc -l < "$LOGS_REAL/ssh.calls" | tr -d ' ')
audited=0; [ -f "$LOGS_REAL/audit.log" ] && audited=$(wc -l < "$LOGS_REAL/audit.log" | tr -d ' ')
errors=0; [ -f "$LOGS_REAL/audit.log.error" ] && errors=$(wc -l < "$LOGS_REAL/audit.log.error" | tr -d ' ')
opendirs=0; [ -f "$LOGS_REAL/audit.log" ] && opendirs=$(grep -c " opendir " "$LOGS_REAL/audit.log")
ran=$(sed -n 's/^Ran \([0-9][0-9]*\) tests\{0,1\} in .*/\1/p' "$LOGS_REAL/suite.log" | tail -1); ran=${ran:-0}
finalok=0; tail -n 3 "$LOGS_REAL/suite.log" | grep -Eq '^OK( \(.*\))?$' && finalok=1
loaded=$(wc -l < "$LOGS_REAL/loaded.log" | tr -d ' ')
if command -v shasum >/dev/null; then sha=$(shasum -a 256 "$self" | cut -c1-16); else sha=$(sha256sum "$self" | cut -c1-16); fi
echo "suite_rc=$rc tests_ran=$ran final_ok=$finalok audit_writes=$audited audit_opendir_records=$opendirs audit_log_errors=$errors ssh_calls=$ssh hook_loaded_in=$loaded snapshot_diff_lines=$d sandbox=${HC_SANDBOX:-no} bwrap=${HC_BWRAP:-no} pinned=$([ -n "${HC_UNPINNED:-}" ] && echo no || echo yes) tmpdir=${HC_TMPDIR:-unset} pattern=${pattern:-full} script_sha256=$sha $(grep -E '^Ran ' "$LOGS_REAL/suite.log")" | tee "$LOGS_REAL/result.txt"
if [ "$rc" = 0 ] && [ "$audited" -eq 0 ] && [ "$errors" -eq 0 ] && [ "$ssh" -eq 0 ] && [ "$loaded" -ge 2 ] && [ "$ran" -gt 0 ] && [ "$finalok" -eq 1 ]; then echo HERMETIC_PASS | tee -a "$LOGS_REAL/result.txt"; echo "REPORT_DIR=$LOGS_REAL"; else echo HERMETIC_FAIL | tee -a "$LOGS_REAL/result.txt"; echo "REPORT_DIR=$LOGS_REAL (audit.log, suite.log, ssh.calls)"; exit 1; fi
