#!/bin/bash
# PR 52 follow-up from the independent review: DEPLOYMENT.md no longer claims the deploy manages the zone/domain, and gets a re-attach procedure.
set -eu
exec > /Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/routes_docs.log 2>&1
cd /Users/eric/.agent-harness/scratch/claude-501/-Users-eric/baab765b-d85c-46b4-b7b9-588eb912c770/scratchpad/n2/t2c
git checkout -q fix/wrangler-no-zone-route
python3 -I - <<'EOF'
p = 'DEPLOYMENT.md'
d = open(p).read()
a = 'in the Cloudflare account and zone identified in `wrangler.cloudflare.jsonc`'
assert a in d, 'line 3 text not found'
d = d.replace(a, 'in the Cloudflare account identified in `wrangler.cloudflare.jsonc`')
b = 'The custom-domain route provisions DNS and TLS in the same zone.'
assert b in d, 'route sentence not found'
d = d.replace(b, 'The custom domain `learnai.ericmacdougall.com` is attached to the Worker once, in the Cloudflare account; `npm run deploy` does not manage it (the config has no `routes`, and the deploy token has no zone scope).')
d = d.rstrip('\n') + """

## Re-attaching the custom domain

If `learnai.ericmacdougall.com` is ever detached from the Worker, or the Worker is renamed or recreated, the repo will not re-create it. Re-attach it in the Cloudflare dashboard (Workers & Pages, learnai-field-lab, Settings, Domains & Routes, Add, Custom domain) or with a token that has the zone scope. After any deploy, check the live domain: the home page, one lesson page and a few media URLs must return 200, and `learnai-field-lab.<account-subdomain>.workers.dev` must not serve the app.
"""
open(p, 'w').write(d + '\n')
EOF
git add DEPLOYMENT.md
git commit -q -m "docs(deploy): domain is attached in the account, not managed by deploy" -m "Why: the review of PR 52 found DEPLOYMENT.md still said the deploy manages the zone and the custom-domain route, which is no longer true." -m "What: reword the account and domain sentences and add a re-attach procedure with a post-deploy smoke check." -m "Testing: not run: documentation only." -m "Refs: GoodQA #15484"
git push -q origin fix/wrangler-no-zone-route 2>&1 | tail -1
echo "PR52_HEAD $(git rev-parse HEAD)"
