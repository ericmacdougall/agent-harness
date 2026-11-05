#!/bin/bash
# Hermeticity gate (GoodQA #14560 AC-4). macOS only (sandbox-exec; cannot be nested inside another sandbox).
# Usage: tests/hermetic_check.sh PYTHON TREE LOGDIR [PATTERN]
# HC_UNPINNED=1 runs with the real HOME and no pin (failing controls on a base tree only; writes are denied by the sandbox).
# PATTERN (optional) is a unittest discover -p glob (a single module or a base tree check); default is the full suite.
# Runs under env -i, a scratch HOME, AGENT_HARNESS_USAGE_DIR and HARNESS_SUITE_PINNED set before Python starts, an ssh
# shim, TMPDIR UNSET (set HC_TMPDIR to override), and a sandbox-exec profile that DENIES writes to the real state dirs
# and process-exec of /usr/bin/ssh. An in-band canary denial must be observed in the system log, so a failed log query
# is a FAIL, not a pass. PASS = suite rc 0, 0 ssh calls, canary seen exactly once, 0 other denials.
set -u
self=$(cd "$(dirname "$0")" && pwd)/$(basename "$0")
py=$1; tree=$2; logs=$3; pattern=${4:-}
R=$(/usr/bin/python3 -c 'import os,pwd;print(os.path.realpath(pwd.getpwuid(os.getuid()).pw_dir))')
mkdir -p "$logs"; TREE=$(cd "$tree" && pwd -P); LOGS=$(cd "$logs" && pwd -P)
scratch=$(mktemp -d "$logs/home.XXXXXX"); shim="$logs/shim"; mkdir -p "$shim" "$logs/pybin"
printf '#!/bin/sh\necho "$@" >> %s/ssh.calls\nexit 255\n' "$logs" > "$shim/ssh"; chmod +x "$shim/ssh"
ln -sf "$py" "$logs/pybin/python3"; ln -sf "$py" "$logs/pybin/$(basename "$py")"
rm -f "$logs/ssh.calls" "$logs/result.txt"
# Deny every write under the real home, then allow only the tree under test and this run's own log dir (SBPL: later
# rules win). Network is not denied here (tests use local sockets); ssh exec is denied and the PATH shim records it.
cat > "$logs/deny.sb" <<S
(version 1)
(allow default)
(deny file-write* (subpath "$R"))
(allow file-write* (subpath "$TREE") (subpath "$LOGS"))
(deny process-exec (literal "/usr/bin/ssh"))
S
snap() { for d in "$R/.agent-harness/state" "$R/.agent-harness/usage" "$R/.agent-harness/logs" "$R/.agent-harness/commit-policy" "$R/.claude/hooks" "$R/.codex"; do find "$d" -path '*__pycache__*' -prune -o -type f -exec stat -f '%N %z %m' {} + 2>/dev/null; done | sort; }
snap > "$logs/before.snap"
start=$(date '+%Y-%m-%d %H:%M:%S')
canary="$R/.agent-harness/usage/.hermetic-canary-$$"; ok_probe="$LOGS/.writable-probe-$$"
sandbox-exec -f "$logs/deny.sb" /bin/sh -c "touch '$canary' 2>/dev/null; true"
sandbox-exec -f "$logs/deny.sb" /bin/sh -c "touch '$ok_probe'"; [ -e "$ok_probe" ] || { echo 'allowed log dir not writable under the profile'; exit 8; }; rm -f "$ok_probe"
[ -e "$canary" ] && { echo "CANARY WAS WRITTEN: sandbox ineffective"; rm -f "$canary"; exit 7; }
cd "$TREE" || exit 9
envtmp=(); [ -n "${HC_TMPDIR:-}" ] && envtmp=(TMPDIR="$HC_TMPDIR")
args=(discover -s tests); [ -n "$pattern" ] && args+=(-p "$pattern")
pin=(HOME="$scratch" AGENT_HARNESS_USAGE_DIR="$scratch/usage" HARNESS_SUITE_PINNED=1)
[ -n "${HC_UNPINNED:-}" ] && pin=(HOME="$R")   # failing controls only: the old tests with the real HOME
sandbox-exec -f "$logs/deny.sb" env -i "${pin[@]}" ${envtmp[@]+"${envtmp[@]}"} \
  PATH="$shim:$logs/pybin:/usr/bin:/bin" LANG=en_US.UTF-8 GIT_CONFIG_NOSYSTEM=1 \
  "$py" -m unittest "${args[@]}" > "$logs/suite.log" 2>&1
rc=$?
snap > "$logs/after.snap"
sleep 3
/usr/bin/log show --start "$start" --predicate 'eventMessage CONTAINS "deny(1)"' > "$logs/denials.log" 2>&1; logrc=$?
canaries=$(grep -c "hermetic-canary-$$" "$logs/denials.log")
others=$(grep -E "($R/|/usr/bin/ssh)" "$logs/denials.log" | grep -vc "hermetic-canary-$$")
ssh=0; [ -f "$logs/ssh.calls" ] && ssh=$(wc -l < "$logs/ssh.calls" | tr -d " ")
diff "$logs/before.snap" "$logs/after.snap" > "$logs/snap.diff"; d=$(wc -l < "$logs/snap.diff")
echo "suite_rc=$rc log_rc=$logrc canary_denials=$canaries other_denials=$others ssh_calls=$ssh snapshot_diff_lines=$d tmpdir=${HC_TMPDIR:-unset} pattern=${pattern:-full} script_sha256=$(shasum -a 256 "$self" | cut -c1-16) $(grep -E '^Ran ' "$logs/suite.log")" | tee "$logs/result.txt"
if [ "$rc" = 0 ] && [ "$logrc" = 0 ] && [ "$canaries" -eq 1 ] && [ "$others" -eq 0 ] && [ "$ssh" -eq 0 ]; then echo HERMETIC_PASS | tee -a "$logs/result.txt"; else echo HERMETIC_FAIL | tee -a "$logs/result.txt"; fi
