#!/bin/bash
# on the Mac: apply N2 in a shallow clone under the session scratchpad (small, not the owner work dir) and push the branch straight to GitHub. No force.
set -eu
H=/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a
W=/Users/eric/.agent-harness/scratch/claude-501/-Users-eric/baab765b-d85c-46b4-b7b9-588eb912c770/scratchpad/n2
mkdir -p $W; cd $W
[ -d t2c ] || git clone -q --depth 1 --branch chore/media-to-r2-v2 https://github.com/ericmacdougall/t2-course.git t2c
cd t2c
git config user.name "Claude Sonnet 5.5"; git config user.email noreply@anthropic.com
git fetch -q origin chore/media-to-r2-v2 --depth 1
git checkout -q -B fix/media-deploy-marker origin/chore/media-to-r2-v2
echo "base $(git rev-parse --short HEAD)"; du -sh . | cut -f1
cp $H/media-sync.mjs scripts/media-sync.mjs
mkdir -p tests; cp $H/media-deploy-gate.test.mjs tests/
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
i = r.find('## Deploying: manual rule until the deploy gate merges')
if i >= 0:
    open('README.md', 'w').write(r[:i].rstrip('\n') + '\n')
EOF
node --check scripts/media-sync.mjs
echo "--- tests in the real tree"; node --test tests/media-deploy-gate.test.mjs 2>&1 | grep -E "^ℹ (tests|pass|fail)"
git add -A; git status --short
git commit -q -m "fix(media): deploy gate refuses a build that did not verify media" -m "Why: N2, a MEDIA_SKIP build followed by media:pull and npm run deploy shipped a site with no media because deploy only re-verified the source tree." -m "What: prebuild records the media check, postbuild stamps dist/.media-marker.json, deploy runs media-sync gate which needs an ok marker plus a valid media tree; MEDIA_SKIP is never honored there; the README manual rule is removed because the gate replaces it." -m "Testing: \`node --test tests/media-deploy-gate.test.mjs\` -> 5 pass; the same tests fail 5 of 5 against the previous script." -m "Refs: GoodQA #15484"
git push -q origin fix/media-deploy-marker 2>&1 | tail -1
echo "N2_HEAD $(git rev-parse HEAD)"
