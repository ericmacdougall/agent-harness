#!/usr/bin/env bash
# Runs on t2-dev. Local reproduction stack for the Kimi QAC findings at the live code (c6bb4238 = e13e3688 + its
# deploy record), or at a candidate worktree for retest. Usage:
#   repro-kit.sh up   [worktree]   lease a pgpool DB, migrate, start API :4300 and web :3300 on 127.0.0.1
#   repro-kit.sh seed              disposable owner + member + org + project, Commander threads on (creds 0600)
#   repro-kit.sh down              stop the API and web started here, release the lease
# State: ~/wt/aab3-repro/ (mode 0700). Never prod; no secrets printed.
set -eu
K=$HOME/wt/aab3-repro; mkdir -p "$K"; chmod 700 "$K"
WT=${2:-$HOME/wt/q3-main-tsc}
# Web binds to WEB_HOST only (default loopback). t2-dev has a public IP and no firewall: use its tailnet address,
# never 0.0.0.0. The API always stays on 127.0.0.1; the web server proxies to it.
WEB_HOST=${WEB_HOST:-127.0.0.1}
case "$WEB_HOST" in 127.0.0.1|100.*) ;; *) echo "REFUSED: WEB_HOST must be loopback or a tailnet 100.x address"; exit 2;; esac
case "$1" in
up)
  [ -s "$K/lease.pid" ] && kill -0 "$(cat "$K/lease.pid")" 2>/dev/null && { echo "already up"; exit 0; }
  # Hold a pgpool lease for 4h with a sleeper; the leased URL lands in $K/.dburl (0600).
  nohup python3 ~/repos/harness/lanes/pgpool.py run --mode server --job aab3-repro --lane qacq3 --ttl 14400 -- \
    bash -c 'umask 077; echo "$DATABASE_URL" > '"$K"'/.dburl; exec sleep 14000' > "$K/lease.log" 2>&1 < /dev/null &
  echo $! > "$K/lease.pid"
  for i in $(seq 1 60); do [ -s "$K/.dburl" ] && break; sleep 1; done
  [ -s "$K/.dburl" ] || { echo "LEASE_FAILED"; tail -3 "$K/lease.log"; exit 3; }
  export DATABASE_URL="$(cat "$K/.dburl")"
  (cd "$WT" && pnpm --filter @bugtracker/db migrate > "$K/migrate.log" 2>&1) || { echo MIGRATE_FAILED; tail -5 "$K/migrate.log"; exit 4; }
  umask 077; head -c 32 /dev/urandom | base64 | tr -d '=+/\n' > "$K/.jwt"
  ( cd "$WT/apps/api" && PORT=4300 HOST=127.0.0.1 NODE_ENV=development JWT_SECRET="$(cat "$K/.jwt")" \
    WEB_ORIGIN=http://$WEB_HOST:3300 OAUTH_REDIRECT_BASE=http://127.0.0.1:4300 EMAIL_DRIVER=console STORAGE_DRIVER=disk \
    FEDERATION_KEYRING="s1:$(head -c 32 /dev/urandom | base64)" DATABASE_URL="$DATABASE_URL" \
    nohup ./node_modules/.bin/tsx src/server.ts > "$K/api.log" 2>&1 < /dev/null & echo $! > "$K/api.pid" )
  ( cd "$WT/apps/web" && API_PROXY_TARGET=http://127.0.0.1:4300 NEXT_PUBLIC_API_URL= \
    nohup node node_modules/next/dist/bin/next dev --webpack --port 3300 --hostname "$WEB_HOST" > "$K/web.log" 2>&1 < /dev/null & echo $! > "$K/web.pid" )
  for i in $(seq 1 120); do curl -fsS http://127.0.0.1:4300/v1/version >/dev/null 2>&1 && break; sleep 2; done
  curl -fsS http://127.0.0.1:4300/v1/version && echo && echo "UP worktree=$WT api=127.0.0.1:4300 web=http://$WEB_HOST:3300"
  ;;
seed)
  export DATABASE_URL="$(cat "$K/.dburl")"; API=http://127.0.0.1:4300/v1; cd "$K"
  mk() { # $1 label -> writes $1.json {email,password,userId,token}
    local R E P; R=$(head -c 6 /dev/urandom | od -An -tx1 | tr -d ' \n'); E="kimi-repro-$1-$R@e2e.goodqa.app"
    P="Pw-$(head -c 12 /dev/urandom | base64 | tr -d '=+/\n')"
    curl -sS -X POST $API/auth/signup -H 'content-type: application/json' -d "{\"email\":\"$E\",\"password\":\"$P\",\"name\":\"Repro $1\"}" > "$1.signup.json"
    psql "$DATABASE_URL" -qc "update users set email_verified_at=now() where email='$E'"
    python3 -I -c 'import json,sys; s=json.load(open(sys.argv[1])); print(json.dumps({"email":sys.argv[2],"password":sys.argv[3],"userId":s["user"]["id"],"token":s["tokens"]["accessToken"]}))' "$1.signup.json" "$E" "$P" > "$1.json"
    chmod 600 "$1.json" "$1.signup.json"; }
  umask 077; mk owner; mk member
  OT=$(python3 -I -c 'import json;print(json.load(open("owner.json"))["token"])'); OU=$(python3 -I -c 'import json;print(json.load(open("owner.json"))["userId"])')
  curl -sS -X POST $API/orgs -H 'content-type: application/json' -H "authorization: Bearer $OT" -d '{"name":"Kimi Repro Org"}' > org.json
  ORG=$(python3 -I -c 'import json;print(json.load(open("org.json"))["org"]["id"])')
  curl -sS -X POST $API/orgs/$ORG/projects -H 'content-type: application/json' -H "authorization: Bearer $OT" -d '{"name":"Repro Project","key":"REPRO"}' > project.json || true
  MU=$(python3 -I -c 'import json;print(json.load(open("member.json"))["userId"])')
  psql "$DATABASE_URL" -q <<SQL
insert into org_members(org_id,user_id,role) values ('$ORG','$MU','member') on conflict do nothing;
insert into platform_settings(key,value,value_type,updated_by,reason) values
 ('commander.threads','true','boolean','$OU','kimi repro local'),
 ('commander.serviceCustody','true','boolean','$OU','kimi repro local'),
 ('qaCommander.runtime.enabled','true','boolean','$OU','kimi repro local'),
 ('qaCommander.provider','"coordinator_pool"','string','$OU','kimi repro local')
 on conflict (key) do update set value=excluded.value;
update organizations set entitlement_overrides = coalesce(entitlement_overrides,'{}'::jsonb) || jsonb_build_object('qaCommander.aiApprovedAt', now()::text) where id='$ORG';
SQL
  echo "SEEDED org=$ORG (credentials in $K/owner.json, member.json; mode 0600; not printed)"
  ;;
down)
  # Only ah kill (harness rule); a failure leaves the pid file so the owner can see what is still running.
  AH=$(command -v ah || ls ~/.claude/hooks/ah.py 2>/dev/null || true)
  for p in web api lease; do
    [ -s "$K/$p.pid" ] || continue
    if python3 "$AH" kill --pid "$(cat "$K/$p.pid")" --reason "stop my own kimi repro $p"; then rm -f "$K/$p.pid"; else echo "KILL_FAILED $p pid $(cat "$K/$p.pid")"; fi
  done
  echo DOWN
  ;;
esac
