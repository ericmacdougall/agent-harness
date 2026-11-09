#!/bin/bash
# on t2-dev: apply N2 on a fresh shallow clone of chore/media-to-r2-v2 as branch fix/media-deploy-marker (stacked on PR 49). Pushes branch + README rule on v2. No force.
set -eu
W=/home/eric/gq-branch-clean/n2; rm -rf $W; mkdir -p $W; cd $W
git clone -q --depth 1 --branch chore/media-to-r2-v2 git@github.com:ericmacdougall/t2-course.git t2c
cd t2c
git config user.name "Claude Sonnet 5.5"; git config user.email noreply@anthropic.com
echo "--- .npmrc:"; cat .npmrc | sed 's/=.*token.*/=<redacted>/' | head -5
grep -n '"prebuild"\|"postbuild"\|"deploy"\|"build"' package.json
# README manual deploy rule goes on the PR 49 branch first (until N2 merges)
python3 -I - <<'EOF'
r = open('README.md').read().rstrip('\n')
r += """

## Deploying: manual rule until the deploy gate merges (goodqa#15484, N2)

Media is not in git. Deploy ONLY with this exact sequence and never build with MEDIA_SKIP:

    npm ci && npm run media:pull && npm run build && npm run deploy

`npm run deploy` re-checks the media tree, but until the build-marker gate (fix/media-deploy-marker) merges, it cannot tell a build made with MEDIA_SKIP=1 from a verified one. Do not run `npm run media:pull` after a build and then deploy without rebuilding.
"""
open('README.md', 'w').write(r + '\n')
EOF
git add README.md
git commit -q -m "docs(media): manual deploy rule until the deploy gate merges" -m "Why: N2 (goodqa#15484) lets a MEDIA_SKIP build be deployed with no media; the rule keeps humans and agents safe until the gate lands." -m "What: README states the exact deploy sequence and forbids MEDIA_SKIP and pull-after-build." -m "Testing: not run: documentation only." -m "Refs: GoodQA #15484"
git push -q origin chore/media-to-r2-v2 2>&1 | tail -1
echo "V2_HEAD $(git rev-parse --short HEAD)"
# N2 fix branch
git checkout -q -b fix/media-deploy-marker
cp /home/eric/gq-branch-clean/n2/media-sync.mjs scripts/media-sync.mjs
mkdir -p tests; cp /home/eric/gq-branch-clean/n2/media-deploy-gate.test.mjs tests/
python3 -I - <<'EOF'
import json
p = json.load(open('package.json'))
sc = p['scripts']
new = {}
for k, v in sc.items():
    new[k] = v
    if k == 'build':
        new['postbuild'] = 'node scripts/media-sync.mjs mark'
new['deploy'] = 'env -u MEDIA_SKIP node scripts/media-sync.mjs gate && wrangler deploy --config wrangler.cloudflare.jsonc'
new['test:media-gate'] = 'node --test tests/media-deploy-gate.test.mjs'
p['scripts'] = new
json.dump(p, open('package.json', 'w'), indent=2); open('package.json', 'a').write('\n')
g = open('.gitignore').read().rstrip('\n') + '\n/.media-build-state.json\n'
open('.gitignore', 'w').write(g)
d = open('DEPLOYMENT.md').read()
d = d.replace('and `npm run deploy` checks again, so a deploy cannot silently ship a site without audio.', 'and `npm run deploy` runs a gate: the build stamps dist/.media-marker.json (postbuild) with whether it verified the media, and the deploy refuses a dist/ whose build did not (for example one built with MEDIA_SKIP=1 and then given media afterwards), so a deploy cannot silently ship a site without audio.')
open('DEPLOYMENT.md', 'w').write(d)
r = open('README.md').read()
i = r.index('## Deploying: manual rule until the deploy gate merges')
open('README.md', 'w').write(r[:i].rstrip('\n') + '\n')
EOF
node --check scripts/media-sync.mjs
echo "--- tests in the real tree"; node --test tests/media-deploy-gate.test.mjs 2>&1 | grep -E "^ℹ (tests|pass|fail)"
git add -A
git status --short
git commit -q -m "fix(media): deploy gate refuses a build that did not verify media" -m "Why: N2, a MEDIA_SKIP build followed by media:pull and npm run deploy shipped a site with no media because deploy only re-verified the source tree." -m "What: prebuild records the media check, postbuild stamps dist/.media-marker.json, deploy runs media-sync gate which needs an ok marker plus a valid media tree; MEDIA_SKIP is never honored there; README rule removed (the gate replaces it)." -m "Testing: \`node --test tests/media-deploy-gate.test.mjs\` -> 5 pass; the same tests fail 5 of 5 against the previous script." -m "Refs: GoodQA #15484"
git push -q origin fix/media-deploy-marker 2>&1 | tail -1
echo "N2_HEAD $(git rev-parse HEAD)"
