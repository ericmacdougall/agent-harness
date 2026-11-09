#!/usr/bin/env bash
# K2-HANG-CAUSE (goodqa#14903): does a create wait on a lock some other session holds? Local repro stack only.
# Case A: a session holds the global QAC queue lock (2922,3) exclusively for 12s, like a pool lease or the sweep.
# Case B: a session holds the per-user ai-thread advisory lock for 12s, like a stuck earlier create.
set -u
K=$HOME/wt/aab3-repro; API=http://127.0.0.1:4300/v1; DB=$(cat "$K/.dburl")
ORG=$(python3 -I -c 'import json;print(json.load(open("'"$K"'/org.json"))["org"]["id"])')
UID_=$(python3 -I -c 'import json;print(json.load(open("'"$K"'/owner.json"))["userId"])')
TOK=$(python3 -I - "$K/owner.json" "$API" <<'PY'
import json, sys, urllib.request
c = json.load(open(sys.argv[1]))
req = urllib.request.Request(sys.argv[2] + '/auth/login', data=json.dumps({'email': c['email'], 'password': c['password']}).encode(),
                             headers={'content-type': 'application/json'})
print(json.load(urllib.request.urlopen(req, timeout=30))['tokens']['accessToken'])
PY
)
create() { curl -s -o /dev/null -w "$1 http=%{http_code} total=%{time_total}s\n" -m 60 -X POST "$API/orgs/$ORG/ai-threads" \
  -H 'content-type: application/json' -H "authorization: Bearer $TOK" -d "{\"message\":\"K2 stall $1 $(date +%s%N)\"}"; }
hold() { psql "$DB" -XqAtc "begin; select $1; select pg_sleep(12); commit;" > /dev/null 2>&1 & sleep 1; }
create baseline
hold "pg_advisory_xact_lock(2922, 3)"; create queue_lock_held; wait
hold "pg_advisory_xact_lock(hashtextextended('ai-thread:$ORG:$UID_', 0))"; create ai_thread_lock_held; wait
create after
