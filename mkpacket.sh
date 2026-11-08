#!/bin/bash
# on t2-dev: review packet of the real t2-course change (no deletions)
cd /home/eric/gq-branch-clean/tc/work || exit 1
out=/home/eric/gq-branch-clean/tc/packet.txt
{
echo "# t2-course media-to-R2 change packet (head $(git rev-parse --short HEAD), base main $(git rev-parse --short main))"
echo "# 38,218 media files (6.23 GB) deleted from the index are excluded; paths: public/audio, public/engineering-videos, public/data-audio, power-user/public/audio"
git diff main HEAD --stat -- . ':!public/audio' ':!public/engineering-videos' ':!public/data-audio' ':!power-user/public/audio' ':!media-manifest.json'
git diff main HEAD -- .gitignore package.json DEPLOYMENT.md
echo "=== scripts/media-sync.mjs"; cat scripts/media-sync.mjs
echo "=== media-manifest.json (head)"; head -c 1500 media-manifest.json; echo; echo "..."; tail -c 400 media-manifest.json
} > "$out"
wc -c "$out"
