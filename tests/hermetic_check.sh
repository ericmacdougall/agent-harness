#!/bin/bash
# Hermeticity gate (GoodQA #14560 AC-4). Usage: tests/hermetic_check.sh PYTHON TREE [PATTERN]
# PATTERN (optional) is a unittest discover -p glob (one module, or a base-tree control); default is the full suite.
# Runs under env -i with: a scratch HOME, AGENT_HARNESS_USAGE_DIR and HARNESS_SUITE_PINNED set before Python starts,
# TMPDIR unset (HC_TMPDIR overrides), an ssh shim first on PATH that records and fails, and an audit hook
# (tests/hermetic_audit/sitecustomize.py, via PYTHONPATH) that records every attempt by a Python process in the tree to
# write inside the real state dirs, even when the test swallows the error.
# PASS = suite rc 0, 0 ssh calls, empty audit log, and the audit canary recorded. Every FAIL path exits non-zero.
# Limits: a child that does not inherit PYTHONPATH (rebuilt env) or is not Python is not audited; the before/after
# listing of the real dirs is informational because other agents write there; ssh is recorded only when found via PATH.
# HC_SANDBOX=1 additionally runs under sandbox-exec denying all writes below the real home except the tree, the git
# common dir and LOGDIR (macOS only; /bin/ps cannot be exec'd inside any sandbox-exec profile, so use it for single
# modules and failing controls, not the full suite). HC_UNPINNED=1 runs with the real HOME and no pin (failing controls
# on a base tree only: it REQUIRES HC_SANDBOX=1 so a leak is blocked rather than written).
set -u
self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
py=$1; tree=$2; pattern=${3:-}
R=$(/usr/bin/python3 -c 'import os,pwd;print(os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))')
TREE=$(cd "$tree" && pwd -P)
GITCOMMON=$(cd "$TREE" && cd "$(git rev-parse --git-common-dir 2>/dev/null || echo .)" && pwd -P)
for p in "$GITCOMMON" "$TREE"; do
  case "$p/" in "$R/.claude/"*|"$R/.codex/"*|"$R/.ssh/"*|"$R/.agent-harness/usage/"*|"$R/.agent-harness/state/"*|"$R/.agent-harness/logs/"*|"$R/.agent-harness/commit-policy/"*|"$R/.agent-harness/wals/"*) echo "LOGDIR, tree or git dir is inside a protected real state dir: $p"; exit 6;; esac
done
if [ -n "${HC_UNPINNED:-}" ] && [ -z "${HC_SANDBOX:-}" ]; then echo "HC_UNPINNED requires HC_SANDBOX=1"; exit 5; fi
# Every disposable file (scratch HOME, ssh recorder, audit log, sandbox profile, snapshots) lives in a fresh temp dir
# outside ~/.agent-harness; the report lines are printed, and the dir is named on the last line for the caller.
LOGS=$(cd "$(mktemp -d "${TMPDIR:-/tmp}/hermetic-check.XXXXXX")" && pwd -P)
case "$LOGS/" in "$R/"*) echo "temp dir is under the real home ($LOGS); set TMPDIR outside it"; exit 6;; esac
scratch=$(mktemp -d "$LOGS/home.XXXXXX"); shim="$LOGS/shim"; mkdir -p "$shim" "$LOGS/pybin"
printf '#!/bin/sh\necho "$@" >> %s/ssh.calls\nexit 255\n' "$LOGS" > "$shim/ssh"; chmod +x "$shim/ssh"
ln -sf "$py" "$LOGS/pybin/python3"; ln -sf "$py" "$LOGS/pybin/$(basename "$py")"
audit="$(dirname "$self")/hermetic_audit"; [ -f "$audit/sitecustomize.py" ] || { echo "audit hook missing next to the script: $audit"; exit 4; }
# canary: the hook must fire under this interpreter (a temp dir stands in for a protected dir)
cdir=$(mktemp -d "$LOGS/canary.XXXXXX")
env -i PATH="/usr/bin:/bin" HC_AUDIT_LOG="$LOGS/canary.log" HC_PROTECT="$cdir" PYTHONPATH="$audit" "$py" -c "open('$cdir/x','w').write('1')"
grep -q "open" "$LOGS/canary.log" 2>/dev/null || { echo "audit canary not recorded: gate cannot detect writes"; exit 7; }
pin=(HOME="$scratch" AGENT_HARNESS_USAGE_DIR="$scratch/usage" HARNESS_SUITE_PINNED=1)
[ -n "${HC_UNPINNED:-}" ] && pin=(HOME="$R")
envtmp=(); [ -n "${HC_TMPDIR:-}" ] && envtmp=(TMPDIR="$HC_TMPDIR")
args=(discover -s tests); [ -n "$pattern" ] && args+=(-p "$pattern")
wrap=()
if [ -n "${HC_SANDBOX:-}" ]; then
  cat > "$LOGS/deny.sb" <<S
(version 1)
(allow default)
(deny file-write* (subpath "$R"))
(allow file-write* (subpath "$TREE") (subpath "$LOGS") (subpath "$GITCOMMON"))
S
  wrap=(sandbox-exec -f "$LOGS/deny.sb")
fi
snap() { for d in "$R/.agent-harness/state" "$R/.agent-harness/usage" "$R/.agent-harness/logs" "$R/.agent-harness/commit-policy" "$R/.claude/hooks" "$R/.codex"; do find "$d" -path '*__pycache__*' -prune -o -type f -exec stat -f '%N %z %m' {} + 2>/dev/null; done | sort; }
snap > "$LOGS/before.snap"
cd "$TREE" || exit 9
${wrap[@]+"${wrap[@]}"} env -i "${pin[@]}" ${envtmp[@]+"${envtmp[@]}"} HC_AUDIT_LOG="$LOGS/audit.log" PYTHONPATH="$audit" \
  PATH="$shim:$LOGS/pybin:/usr/bin:/bin" LANG=en_US.UTF-8 GIT_CONFIG_NOSYSTEM=1 \
  "$py" -m unittest "${args[@]}" > "$LOGS/suite.log" 2>&1
rc=$?
snap > "$LOGS/after.snap"; diff "$LOGS/before.snap" "$LOGS/after.snap" > "$LOGS/snap.diff"; d=$(wc -l < "$LOGS/snap.diff" | tr -d ' ')
ssh=0; [ -f "$LOGS/ssh.calls" ] && ssh=$(wc -l < "$LOGS/ssh.calls" | tr -d ' ')
audited=0; [ -f "$LOGS/audit.log" ] && audited=$(wc -l < "$LOGS/audit.log" | tr -d ' ')
echo "suite_rc=$rc audit_writes=$audited ssh_calls=$ssh snapshot_diff_lines=$d sandbox=${HC_SANDBOX:-no} pinned=$([ -n "${HC_UNPINNED:-}" ] && echo no || echo yes) tmpdir=${HC_TMPDIR:-unset} pattern=${pattern:-full} script_sha256=$(shasum -a 256 "$self" | cut -c1-16) $(grep -E '^Ran ' "$LOGS/suite.log")" | tee "$LOGS/result.txt"
if [ "$rc" = 0 ] && [ "$audited" -eq 0 ] && [ "$ssh" -eq 0 ]; then echo HERMETIC_PASS | tee -a "$LOGS/result.txt"; echo "REPORT_DIR=$LOGS"; else echo HERMETIC_FAIL | tee -a "$LOGS/result.txt"; echo "REPORT_DIR=$LOGS (audit.log, suite.log, ssh.calls)"; exit 1; fi
