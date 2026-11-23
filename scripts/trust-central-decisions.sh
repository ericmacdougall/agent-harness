#!/bin/bash
# Enable signed central top-rung decisions on this Mac and its worker host, then publish one verified approval.
# GoodQA goodqa#16651. Run it yourself, once, from a terminal on the Mac (not from an agent).
#
# What it does, in order (every step stops the run on failure; nothing after a failed step runs):
#  1. Checks each PR (agent-harness, and T2SCAN when given) against its exact-HEAD `peer_review.py pr` receipt:
#     Stage pr, the same repository and PR, Reviewed HEAD equal to the PR head, verdict PASS or PASS-WITH-TICKETS.
#  2. After you confirm, merges each open PR with `gh pr merge --merge --match-head-commit <reviewed head>` and
#     checks that the merge commit's second parent is the reviewed head. It never pushes to main itself.
#  3. Installs the merged harness on the worker and this Mac through the supported repair flow
#     (`~/.agent-harness/bin/repair-harness --ref <merge> --host <host>`, preview then apply).
#  4. Creates (or reuses) the Mac signing key, pins its public key on both hosts, and points both hosts at the
#     ledger ticket.
#  5. For each T2Scan item: records the top-rung permission from your cited message (`ah approve-top`), then
#     publishes it (`ah decision publish`), which re-verifies your own words before signing.
#  6. Updates the worker's trusted T2Scan checkout to the merged T2SCAN commit, reinstalls the Claude adapter
#     (mode 0700) and checks it equals the checkout.
#  7. Verifies on the worker: `ah decision verify` and the adapter's own `authorize` return valid/authorized for
#     every item.
#
# Rollback: `python3 ~/.claude/hooks/ah.py decision withdraw --all` (denies everywhere at once), then, if needed,
# `~/.agent-harness/bin/repair-harness --ref <previous main> --host <host> --apply`.
# T2Scan adapter on the worker: check out the previous trusted commit in ~/t2scan-runtime/t2scan and reinstall
# cli/adapters/claude-assessment.py to ~/.config/t2/assessment-adapters/ (mode 0700); without a pinned key or
# config the central path denies anyway.
set -euo pipefail

HARNESS_REPO=ericmacdougall/agent-harness
T2SCAN_REPO=ericmacdougall/transition2-scanner
LEDGER_PROJECT=goodqa
LEDGER_NUMBER=16652
LEDGER_ISSUE=df6e5927-0772-414a-be9b-03ad45c3d608
HOST=t2-dev
HARNESS_PR='' HARNESS_RECEIPT='' T2SCAN_PR='' T2SCAN_RECEIPT='' USER_MSG='' WAL='' ITEMS_FILE='' ASSUME_YES=0 CHECK_ONLY=0
ITEMS=()
AH=(python3 "$HOME/.claude/hooks/ah.py")
REPAIR="$HOME/.agent-harness/bin/repair-harness"
T2_CHECKOUT='$HOME/t2scan-runtime/t2scan'
T2_ADAPTER='$HOME/.config/t2/assessment-adapters/claude-assessment.py'

die() { printf 'trust-central-decisions: STOPPED: %s\n' "$*" >&2; exit 2; }
say() { printf '==> %s\n' "$*"; }

usage() {
    cat <<'EOF'
usage: scripts/trust-central-decisions.sh --harness-pr N --harness-receipt FILE
           [--t2scan-pr N --t2scan-receipt FILE]
           --user-msg uuid:<session>/<uuid> --wal ~/.claude/wals/<session>/main.jsonl
           (--item ASSIGNMENT:PROJECT:RUN:WORK_ITEM ... | --items-file FILE)
           [--host t2-dev] [--check] [--yes]
--check  verify everything that can be verified without merging, installing or publishing
--yes    do not ask before merging
EOF
}

while (( $# )); do
    case $1 in
        --harness-pr) HARNESS_PR=${2:?}; shift ;;
        --harness-receipt) HARNESS_RECEIPT=${2:?}; shift ;;
        --t2scan-pr) T2SCAN_PR=${2:?}; shift ;;
        --t2scan-receipt) T2SCAN_RECEIPT=${2:?}; shift ;;
        --user-msg) USER_MSG=${2:?}; shift ;;
        --wal) WAL=${2:?}; shift ;;
        --item) ITEMS+=("${2:?}"); shift ;;
        --items-file) ITEMS_FILE=${2:?}; shift ;;
        --host) HOST=${2:?}; shift ;;
        --check) CHECK_ONLY=1 ;;
        --yes) ASSUME_YES=1 ;;
        -h|--help) usage; exit 0 ;;
        *) usage >&2; die "unknown argument: $1" ;;
    esac
    shift
done

[[ $HARNESS_PR =~ ^[1-9][0-9]{0,6}$ ]] || die "--harness-pr must be a PR number"
[[ -f $HARNESS_RECEIPT ]] || die "--harness-receipt must name the exact-HEAD peer_review.py pr report"
if [[ -n $T2SCAN_PR || -n $T2SCAN_RECEIPT ]]; then
    [[ $T2SCAN_PR =~ ^[1-9][0-9]{0,6}$ && -f $T2SCAN_RECEIPT ]] || die "--t2scan-pr needs --t2scan-receipt (and the reverse)"
fi
[[ $USER_MSG =~ ^uuid:[0-9a-f-]{36}/[0-9a-f-]{36}$ ]] || die "--user-msg must be a uuid:<session>/<uuid> id from \`ah user-msg\`"
[[ $HOST =~ ^[A-Za-z0-9][A-Za-z0-9.-]{0,127}$ ]] || die "--host must be a plain SSH host name"
[[ -f $WAL && $(basename "$WAL") == main.jsonl ]] || die "--wal must be the session's main.jsonl"
session_of_msg=${USER_MSG#uuid:}; session_of_msg=${session_of_msg%%/*}
[[ $(basename "$(dirname "$WAL")") == "$session_of_msg" ]] || die "--wal is not the WAL of the session that --user-msg names"
if [[ -n $ITEMS_FILE ]]; then
    [[ -f $ITEMS_FILE ]] || die "--items-file not found"
    while IFS= read -r line || [[ -n $line ]]; do
        line=${line%%#*}; line=${line//[[:space:]]/}
        [[ -n $line ]] && ITEMS+=("$line")
    done < "$ITEMS_FILE"
fi
(( ${#ITEMS[@]} >= 1 && ${#ITEMS[@]} <= 3 )) || die "give 1 to 3 T2Scan items (one user turn backs at most 3 task keys)"

# Each item is ASSIGNMENT:PROJECT:RUN:WORK_ITEM; the task key is derived exactly as the T2Scan adapter derives it,
# so a mistyped key cannot be approved.
TASKS=()
for item in "${ITEMS[@]}"; do
    [[ $item =~ ^(executive|assurance|delivery)-synthesis:prj_[A-Za-z0-9_-]{4,64}:run_[A-Za-z0-9_-]{4,64}:wrk_[A-Za-z0-9_-]{4,64}$ ]] \
        || die "item must be <executive|assurance|delivery>-synthesis:prj_...:run_...:wrk_... (got $item)"
    IFS=: read -r _assignment prj run wrk <<<"$item"
    key=$(python3 -I -c 'import hashlib,json,sys; print("t2scan-audit-" + hashlib.sha256(json.dumps(sys.argv[1:4], separators=(",", ":"), sort_keys=True).encode()).hexdigest()[:32])' "$prj" "$run" "$wrk")
    TASKS+=("$key")
done
say "Task keys: ${TASKS[*]}"

# ---------------------------------------------------------------- 1. receipts
receipt_ok() {  # receipt repo pr head
    python3 -I - "$1" "$2" "$3" "$4" <<'PY'
import re, sys
path, repo, pr, head = sys.argv[1:5]
text = open(path, encoding="utf-8", errors="replace").read()
header, _, body = text.partition("\n\n")
fields = dict(line.split(": ", 1) for line in header.splitlines() if ": " in line)
problems = []
if fields.get("Stage") != "pr": problems.append("Stage is not pr")
if fields.get("Reviewed repository") != repo: problems.append("Reviewed repository is not " + repo)
if fields.get("Reviewed PR") != pr: problems.append("Reviewed PR is not " + pr)
if fields.get("Reviewed HEAD") != head: problems.append("Reviewed HEAD %s is not the PR head %s" % (fields.get("Reviewed HEAD"), head))
verdict = re.search(r"^VERDICT: (PASS-WITH-TICKETS|PASS|BLOCK)\b", text, re.M)
if not verdict or verdict.group(1) == "BLOCK": problems.append("verdict is not PASS")
if problems:
    print("; ".join(problems)); sys.exit(1)
PY
}

pr_field() {  # repo pr jq-field
    gh pr view "$2" --repo "$1" --json state,headRefOid,mergeCommit,baseRefName --jq "$3"
}

check_pr() {  # repo pr receipt -> prints head
    local repo=$1 pr=$2 receipt=$3 state head base why
    state=$(pr_field "$repo" "$pr" .state) || die "cannot read $repo#$pr"
    head=$(pr_field "$repo" "$pr" .headRefOid)
    base=$(pr_field "$repo" "$pr" .baseRefName)
    [[ $base == main ]] || die "$repo#$pr does not target main"
    [[ $state == OPEN || $state == MERGED ]] || die "$repo#$pr is $state"
    why=$(receipt_ok "$receipt" "$repo" "$pr" "$head") || die "$repo#$pr receipt refused: $why"
    printf '%s %s\n' "$state" "$head"
}

read -r H_STATE H_HEAD < <(check_pr "$HARNESS_REPO" "$HARNESS_PR" "$HARNESS_RECEIPT")
say "agent-harness#$HARNESS_PR $H_STATE at $H_HEAD: receipt PASS at that exact HEAD"
if [[ -n $T2SCAN_PR ]]; then
    read -r T_STATE T_HEAD < <(check_pr "$T2SCAN_REPO" "$T2SCAN_PR" "$T2SCAN_RECEIPT")
    say "transition2-scanner#$T2SCAN_PR $T_STATE at $T_HEAD: receipt PASS at that exact HEAD"
fi

# Preconditions that need no change anywhere.
# The hooks run as `python3 <hook>` (user site included); the T2Scan adapter runs as `/usr/bin/python3 -I`.
python3 -c 'import cryptography' 2>/dev/null || die "python3 on this Mac cannot import cryptography (the hooks need it)"
ssh -o BatchMode=yes -o ConnectTimeout=15 "$HOST" 'python3 -c "import cryptography" && /usr/bin/python3 -I -c "import cryptography"' \
    || die "$HOST is unreachable or its python3 (hooks, and /usr/bin/python3 -I for the adapter) cannot import cryptography"
[[ -x $REPAIR ]] || die "$REPAIR is not installed"

if (( CHECK_ONLY )); then
    say "Check only: receipts, keys and both hosts are ready. Nothing was merged, installed or published."
    exit 0
fi

if (( ! ASSUME_YES )); then
    printf 'Merge agent-harness#%s%s, install on %s and this Mac, and publish the approval for %d task(s)? Type yes: ' \
        "$HARNESS_PR" "${T2SCAN_PR:+ and transition2-scanner#$T2SCAN_PR}" "$HOST" "${#TASKS[@]}"
    read -r answer
    [[ $answer == yes ]] || die "not confirmed"
fi

# ---------------------------------------------------------------- 2. merge through the reviewed-PR path
merge_pr() {  # repo pr state head -> prints merge sha
    local repo=$1 pr=$2 state=$3 head=$4 merge parent
    if [[ $state == OPEN ]]; then
        gh pr merge "$pr" --repo "$repo" --merge --match-head-commit "$head" >&2 || die "gh refused to merge $repo#$pr"
    fi
    for _ in 1 2 3 4 5 6; do
        merge=$(pr_field "$repo" "$pr" '.mergeCommit.oid // empty')
        [[ -n $merge ]] && break
        sleep 5
    done
    [[ $merge =~ ^[0-9a-f]{40}$ ]] || die "$repo#$pr has no merge commit"
    parent=$(gh api "repos/$repo/commits/$merge" --jq '.parents[1].sha // empty')
    [[ $parent == "$head" ]] || die "$repo#$pr merge $merge does not have the reviewed head $head as its second parent"
    printf '%s\n' "$merge"
}

H_MERGE=$(merge_pr "$HARNESS_REPO" "$HARNESS_PR" "$H_STATE" "$H_HEAD")
say "agent-harness merged at $H_MERGE"
T_MERGE=''
if [[ -n $T2SCAN_PR ]]; then
    T_MERGE=$(merge_pr "$T2SCAN_REPO" "$T2SCAN_PR" "$T_STATE" "$T_HEAD")
    say "transition2-scanner merged at $T_MERGE"
fi

# ---------------------------------------------------------------- 3. install on both hosts (supported repair flow)
"$REPAIR" --ref "$H_MERGE" --host "$HOST" --check || die "repair-harness preview failed"
"$REPAIR" --ref "$H_MERGE" --host "$HOST" --apply || die "repair-harness apply failed (inspect its logs before retrying)"
for hook in central_decisions.py tier_gate.py provenance_hooks.py escalation.py ticket_adapters.py ah.py; do
    expected=$(gh api "repos/$HARNESS_REPO/contents/harness/hooks/$hook?ref=$H_MERGE" --jq .sha)
    local_blob=$(git hash-object "$HOME/.claude/hooks/$hook")
    remote_blob=$(ssh -o BatchMode=yes "$HOST" "git hash-object \"\$HOME/.claude/hooks/$hook\"")
    [[ -n $expected && $local_blob == "$expected" && $remote_blob == "$expected" ]] || die "installed $hook differs from the merged commit"
done
say "Harness $H_MERGE installed on this Mac and $HOST"

# ---------------------------------------------------------------- 4. key, pin, enable
umask 077
work=$(mktemp -d "$HOME/.agent-harness/work/trust-central-decisions.XXXXXX")
"${AH[@]}" decision keygen >> "$work/keygen.json" || die "keygen failed: $(cat "$work/keygen.json")"
python3 -I -c 'import json,sys; d=json.load(open(sys.argv[1])); json.dump({"public_key": d["public_key"]}, open(sys.argv[2], "w"))' \
    "$work/keygen.json" "$work/pubkey.json"
"${AH[@]}" decision pin --pubkey-file "$work/pubkey.json" >/dev/null || die "pinning the key on this Mac failed"
ssh -o BatchMode=yes "$HOST" 'python3 "$HOME/.claude/hooks/ah.py" decision pin --pubkey-file /dev/stdin' < "$work/pubkey.json" >/dev/null \
    || die "pinning the key on $HOST failed"
"${AH[@]}" decision enable --project "$LEDGER_PROJECT" --number "$LEDGER_NUMBER" --issue-id "$LEDGER_ISSUE" >/dev/null \
    || die "enabling central decisions on this Mac failed"
ssh -o BatchMode=yes "$HOST" "python3 \"\$HOME/.claude/hooks/ah.py\" decision enable --project $LEDGER_PROJECT --number $LEDGER_NUMBER --issue-id $LEDGER_ISSUE" >/dev/null \
    || die "enabling central decisions on $HOST failed"
say "Key $(python3 -I -c 'import json,sys; print(json.load(open(sys.argv[1]))["key_id"])' "$work/keygen.json") pinned on both hosts"

# ---------------------------------------------------------------- 5. approve-top + publish, one task at a time
for task in "${TASKS[@]}"; do
    "${AH[@]}" approve-top --task "$task" --user-msg "$USER_MSG" --wal "$WAL" >> "$work/approve-$task.json" \
        || die "approve-top refused $task: $(cat "$work/approve-$task.json")"
    "${AH[@]}" decision publish --task "$task" >> "$work/publish-$task.json" \
        || die "publish refused $task: $(cat "$work/publish-$task.json")"
    say "Published $task"
done

# ---------------------------------------------------------------- 6. worker T2Scan adapter at the merged commit
if [[ -n $T_MERGE ]]; then
    ssh -o BatchMode=yes "$HOST" bash -s -- "$T_MERGE" <<EOF || die "updating the T2Scan adapter on $HOST failed"
set -euo pipefail
merge=\$1
cd $T2_CHECKOUT
[[ -z \$(git status --porcelain) ]] || { echo "trusted checkout is dirty"; exit 1; }
echo "previous trusted checkout: \$(git rev-parse HEAD)"
git fetch -q origin
git merge-base --is-ancestor "\$merge" origin/main
git checkout -q --detach "\$merge"
install -m 0700 cli/adapters/claude-assessment.py $T2_ADAPTER
cmp -s cli/adapters/claude-assessment.py $T2_ADAPTER
EOF
    say "T2Scan adapter on $HOST reinstalled from $T_MERGE"
fi

# ---------------------------------------------------------------- 7. verify on the worker
for index in "${!TASKS[@]}"; do
    task=${TASKS[$index]}
    ssh -o BatchMode=yes "$HOST" "python3 \"\$HOME/.claude/hooks/ah.py\" decision verify --task $task --family fable" >> "$work/verify-$task.json" \
        || die "$HOST does not accept the decision for $task: $(cat "$work/verify-$task.json")"
    if [[ -n $T_MERGE ]]; then
        IFS=: read -r assignment prj run wrk <<<"${ITEMS[$index]}"
        status=$(ssh -o BatchMode=yes "$HOST" python3 -I - "$assignment" "$prj" "$run" "$wrk" "$task" <<'PY'
import json, os, subprocess, sys, uuid
assignment, prj, run, wrk, task = sys.argv[1:6]
home = os.path.expanduser("~")
profile = json.load(open(home + "/.config/t2/assessment-adapters/claude-assessment.json"))
request = {"schema": "t2-assessment-runtime/1", "action": "authorize", "request_id": str(uuid.uuid4()),
           "project_id": prj, "run_id": run, "work_item_id": wrk, "assignment": assignment, "family": "fable",
           "provider": "claude", "model": profile["models"]["fable"], "approval_task": task, "packet_sha256": "0" * 64}
out = subprocess.run([home + "/.config/t2/assessment-adapters/claude-assessment.py"], input=json.dumps(request).encode(),
                     capture_output=True, timeout=60)
try:
    print(json.loads(out.stdout).get("status"))
except ValueError:
    print("error")
PY
)
        [[ $status == authorized ]] || die "the T2Scan adapter on $HOST answered '$status' for $task"
    fi
    say "$HOST accepts $task${T_MERGE:+ (adapter: authorized)}"
done

say "Done. Central decisions are trusted on this Mac and $HOST. Receipts: $work"
say "Revoke at any time: python3 ~/.claude/hooks/ah.py decision withdraw --all"
say "A retraction typed in another session, or a revoke the hook could not post, needs that command too."
