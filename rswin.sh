#!/bin/bash
# bugtracker ruleset 26509157 (canary-no-force-no-delete): export, bundle+verify the two canary branches to Dropbox, THEN open the shortest possible window:
# disable -> delete only ruleset-canary/dry-20261104T063802Z and ruleset-canary/t1 (lease-guarded) -> ALWAYS restore from the export -> verify field by field.
# Authorised by the user: queue:baab765b-d85c-46b4-b7b9-588eb912c770/2026-11-09T15:46:13.322Z#5c89420971db "yes to bugrtracker.." (asks wf75585ed548).
W=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/rswin
mkdir -p $W; cd $W
R=repos/ericmacdougall/bugtracker/rulesets/26509157
gh api $R > export.json || { echo "EXPORT_FAILED"; exit 1; }
python3 - <<'PY'
import json
a = json.load(open("export.json"))
keep = {k: a[k] for k in ("name", "target", "enforcement", "conditions", "rules", "bypass_actors")}
json.dump(keep, open("enable.json", "w"), indent=1)
d = dict(keep); d["enforcement"] = "disabled"
json.dump(d, open("disable.json", "w"), indent=1)
print("EXPORTED", a["name"], a["enforcement"], [r["type"] for r in a["rules"]], "bypass", a.get("bypass_actors"))
PY
B1=ruleset-canary/dry-20261104T063802Z; B2=ruleset-canary/t1
S1=$(gh api repos/ericmacdougall/bugtracker/git/ref/heads/$B1 -q .object.sha); S2=$(gh api repos/ericmacdougall/bugtracker/git/ref/heads/$B2 -q .object.sha)
echo "TIPS $S1 $S2"
printf '%s %s\n%s %s\n' "$B1" "$S1" "$B2" "$S2" > del-canary.txt
scp -q del-canary.txt t2-dev:gq-branch-clean/r4/del-bugtracker.txt
echo "--- bundle (before the window)"
ssh t2-dev 'cd ~/gq-branch-clean/r4 && ts=$(date -u +%Y%m%dT%H%M%SZ) && git -C bugtracker.git remote update --prune >/dev/null 2>&1; b=bugtracker-canary-$ts.bundle; git -C bugtracker.git bundle create ~/gq-branch-clean/r4/$b ^main refs/heads/ruleset-canary/dry-20261104T063802Z refs/heads/ruleset-canary/t1 2>&1 | tail -1; git -C bugtracker.git bundle verify ~/gq-branch-clean/r4/$b 2>&1 | tail -1; sha256sum $b > $b.sha256; D=dropbox:Backups/repo-archives-private/bugtracker-canary-branches-$ts; rclone copy $b $D/ --tpslimit 2 && rclone copy $b.sha256 $D/ --tpslimit 2; mkdir -p chkc; rm -f chkc/*; cp $b $b.sha256 chkc/; rclone check chkc $D --tpslimit 2 > checkc.log 2>&1; if grep -q " 0 differences found" checkc.log; then echo "CANARY_BACKUP_OK $D"; rm -f $b chkc/$b; else echo CANARY_BACKUP_FAILED; fi' | tee bundle.out
grep -q CANARY_BACKUP_OK bundle.out || { echo "ABORT: backup not verified, ruleset untouched"; exit 2; }
restore() {
  for i in 1 2 3; do gh api -X PUT $R --input enable.json >/dev/null 2>&1 && break; sleep 2; done
  gh api $R > readback.json
  python3 - <<'PY'
import json, sys
a = json.load(open("export.json")); b = json.load(open("readback.json"))
bad = [k for k in ("name", "target", "enforcement", "conditions", "rules", "bypass_actors") if a[k] != b[k]]
print("READBACK_MATCH" if not bad else "READBACK_MISMATCH %s" % bad, "enforcement:", b["enforcement"])
sys.exit(0 if not bad else 1)
PY
  echo "WINDOW_END $(date -u +%T)"
}
trap restore EXIT
echo "WINDOW_START $(date -u +%T)"
gh api -X PUT $R --input disable.json --jq .enforcement
ssh t2-dev 'cd ~/gq-branch-clean/r4 && bash del.sh bugtracker; cat del-bugtracker.log'
