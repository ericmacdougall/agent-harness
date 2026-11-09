#!/bin/bash
# Fresh-clone proof on the Mac (wrangler logged in, GNU tar via shim): clone depth 1 -> npm ci -> media:pull (R2) -> build -> verify. No Dropbox use, no deploy.
set -u
B=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/fresh
mkdir -p $B/shim; ln -sf /opt/homebrew/bin/gtar $B/shim/tar
export PATH=$B/shim:$PATH
cd $B
[ -d t2c ] || git clone -q --depth 1 --branch chore/media-to-r2 https://github.com/ericmacdougall/t2-course.git t2c
cd t2c
echo "HEAD $(git rev-parse --short HEAD) files=$(git ls-files | wc -l)"; df -h /System/Volumes/Data | tail -1
echo "--- verify before pull (must FAIL)"; node scripts/media-sync.mjs verify; echo "rc=$?"
echo "--- npm ci"; npm ci > ../npmci.log 2>&1; echo "rc=$?"
echo "--- media:pull"; npm run media:pull > ../pull.log 2>&1; echo "rc=$?"; tail -3 ../pull.log; df -h /System/Volumes/Data | tail -1
echo "--- build"; npm run build > ../build.log 2>&1; echo "rc=$?"; grep -E "media ok" ../build.log | head -2
echo "--- verify after build"; node scripts/media-sync.mjs verify; echo "rc=$?"
df -h /System/Volumes/Data | tail -1
echo FRESH_DONE
