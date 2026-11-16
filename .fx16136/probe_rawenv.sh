#!/bin/bash
# goodqa#16148: how compose `env_file: format: raw` delivers values (fake values only). Run on t2-dev.
set -u
D=$(mktemp -d ~/repos/fx-16136/rawenv.XXXX); cd "$D" || exit 2
printf '%s\n' 'A=plain' 'B=has=equals==' 'C="quoted"' "D='single'" 'F=trail   ' '  G=leading' 'H=a#notcomment' '# I=comment' '' 'J=' > raw.env
printf 'L=crlf\r\n' >> raw.env
printf 'M=tab\tin\n' >> raw.env
printf 'A=second\n' >> raw.env
cat > compose.yaml <<'EOF'
services:
  t:
    image: busybox
    env_file:
      - path: ./raw.env
        format: raw
EOF
docker compose -p rawprobe config --format json 2>&1 | python3 -c "
import sys, json
raw = sys.stdin.read()
try:
    env = json.loads(raw)['services']['t'].get('environment') or {}
except Exception:
    print('compose error:', raw[-600:]); sys.exit(0)
for k in sorted(env): print(repr(k), '->', repr(env[k]))
"
for bad in 'export E=x' 'K = spaced' ' G2=lead' 'N'; do printf '%s\n' "$bad" > raw.env; echo "case [$bad]: $(docker compose -p rawprobe config --format json 2>&1 | grep -o 'failed to parse.*\|"N":[^,}]*' | sed 's|/home[^:]*|ENV|' | head -1)"; done
cd ~ && rm -rf "$D"
