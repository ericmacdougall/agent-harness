#!/bin/sh
# Start the disposable mobile-UI preview on t2-dev (run there: cd ~/mobile-ui && sh preview-start.sh).
# Generates a fresh synthetic password (never printed), wrangler on https 8791 and a loopback auth-injecting proxy on http 8792.
set -e
cd "$HOME/mobile-ui"
umask 077
python3 - <<PY
import secrets, hashlib
pw = secrets.token_urlsafe(18)
open(".pw", "w").write(pw)
open(".dev.vars", "w").write("PASSWORD_SHA256=" + hashlib.sha256(pw.encode()).hexdigest() + "\n")
PY
nohup ./node_modules/.bin/wrangler dev --config wrangler.jsonc --local --local-protocol https --ip 127.0.0.1 --port 8791 > wrangler.log 2>&1 &
echo $! > wrangler.pid
until grep -q "Ready on" wrangler.log; do sleep 1; done
nohup python3 previewproxy.py > proxy.log 2>&1 &
echo $! > proxy.pid
echo "preview ready: http://127.0.0.1:8792/videos.html (wrangler pid $(cat wrangler.pid), proxy pid $(cat proxy.pid))"
