#!/bin/bash
# on t2-dev in tc/work: apply red-team fixes F1-F4,F6,F13,F14 and test them
set -e
cd /home/eric/gq-branch-clean/tc/work
cp ../media-sync.mjs scripts/media-sync.mjs
T=$(node scripts/media-sync.mjs tree)
python3 -I - "$T" <<'EOF'
import json, sys
m = json.load(open('media-manifest.json'))
m['totals']['tree_sha256'] = sys.argv[1]
json.dump(m, open('media-manifest.json', 'w'), indent=1); open('media-manifest.json', 'a').write('\n')
p = json.load(open('package.json'))
p['scripts']['deploy'] = 'env -u MEDIA_SKIP node scripts/media-sync.mjs verify && wrangler deploy --config wrangler.cloudflare.jsonc'
json.dump(p, open('package.json', 'w'), indent=2); open('package.json', 'a').write('\n')
d = open('DEPLOYMENT.md').read()
d = d.replace('2. `npm ci && npm run build`.', '2. `npm ci && npm run media:pull && npm run build`.')
d = d.replace('5. Deploy the exact built output: `npx wrangler deploy --config wrangler.cloudflare.jsonc`.', '5. Deploy the exact built output: `npm run deploy` (re-verifies the media tree, ignores MEDIA_SKIP, then runs `wrangler deploy --config wrangler.cloudflare.jsonc`).')
d = d.replace('so a deploy cannot silently ship a site without audio. `MEDIA_SKIP=1` bypasses it only for builds that must not ship media.', 'and `npm run deploy` checks again, so a deploy cannot silently ship a site without audio. `MEDIA_SKIP=1` only skips the check for local builds that will not be deployed; it is refused when CI or WORKERS_CI is set.')
d = d.replace('Adding or changing media: put the new files under the same prefixes, run `npm run media:push` (uploads a new part and appends it to the manifest), then commit `media-manifest.json`.', 'Adding media: put new files under the same prefixes, run `MEDIA_KEEP_CACHE=1 npm run media:pull` then `npm run media:push` (uploads a new part and appends it to the manifest), then commit `media-manifest.json`. Changing an existing file is refused: give it a new filename. `media:pull` and `push` need GNU tar.')
open('DEPLOYMENT.md', 'w').write(d)
EOF
grep -c "media:pull && npm run build" DEPLOYMENT.md; grep -c "npm run deploy" DEPLOYMENT.md
echo "--- T1 verify clean"; node scripts/media-sync.mjs verify
echo "--- T2 missing mid-file + junk file keeps count"
f=$(ls public/engineering-videos | sed -n 5p); mv public/engineering-videos/$f /tmp/$f; touch public/engineering-videos/.DS_Store
node scripts/media-sync.mjs verify && echo "FAIL: passed" || echo "ok: rejected (rc=$?)"
rm public/engineering-videos/.DS_Store; mv /tmp/$f public/engineering-videos/$f
echo "--- T3 truncated"; g=public/engineering-videos/bc01-080e5fc6c243c528.mp3; cp $g /tmp/bc01.bak; : > $g
node scripts/media-sync.mjs verify && echo "FAIL: passed" || echo "ok: rejected (rc=$?)"
cp /tmp/bc01.bak $g; rm /tmp/bc01.bak
echo "--- T4 MEDIA_SKIP in CI"; MEDIA_SKIP=1 CI=1 node scripts/media-sync.mjs verify && echo "FAIL: allowed" || echo "ok: refused (rc=$?)"
echo "--- T5 deploy ignores MEDIA_SKIP with missing media"; mv public/engineering-videos/$f /tmp/$f
MEDIA_SKIP=1 env -u MEDIA_SKIP node scripts/media-sync.mjs verify && echo "FAIL: passed" || echo "ok: rejected (rc=$?)"
mv /tmp/$f public/engineering-videos/$f
echo "--- T6 final verify"; node scripts/media-sync.mjs verify
