#!/usr/bin/env bash
# K2-HANG-CAUSE (goodqa#14903 AC-8): time POST /v1/orgs/:org/ai-threads on the local repro stack (t2-dev, disposable
# org), and show where the time goes. Token read from the 0600 credential file; never printed.
set -u
K=$HOME/wt/aab3-repro; API=http://127.0.0.1:4300/v1
ORG=$(python3 -I -c 'import json;print(json.load(open("'"$K"'/org.json"))["org"]["id"])')
TOK=$(python3 -I - "$K/owner.json" "$API" <<'PY'
import json, sys, urllib.request
c = json.load(open(sys.argv[1]))
req = urllib.request.Request(sys.argv[2] + '/auth/login', data=json.dumps({'email': c['email'], 'password': c['password']}).encode(),
                             headers={'content-type': 'application/json'})
print(json.load(urllib.request.urlopen(req, timeout=30))['tokens']['accessToken'])
PY
)
[ -n "$TOK" ] || { echo LOGIN_FAILED; exit 3; }
N=${N:-3}
for i in $(seq 1 "$N"); do
  curl -s -o "$K/k2-create-$i.json" -w "create $i http=%{http_code} total=%{time_total}s\n" -m 330 \
    -X POST "$API/orgs/$ORG/ai-threads" -H 'content-type: application/json' -H "authorization: Bearer $TOK" \
    -d "{\"message\":\"K2 hang measure $i $(date +%s%N)\"}"
done
echo "--- api log lines mentioning admission/commander/persona hook in the last run:"
grep -i -E "admission|commander|persona hook|unadmitted|afterChatMessage" "$K/api.log" | tail -8 | cut -c1-200
echo "--- pg locks held by idle-in-transaction sessions right now:"
psql "$(cat "$K/.dburl")" -XAtc "select state, count(*) from pg_stat_activity where datname=current_database() group by 1"
