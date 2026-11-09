H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
out = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/n2-packet.txt'
head = """# N2 review packet: t2-course PR 50, branch fix/media-deploy-marker, commit 9a71aa13d620 (stacked on chore/media-to-r2-v2 = PR 49)
# Bug: `MEDIA_SKIP=1 npm run build` (no media) -> `npm run media:pull` -> `npm run deploy` (no rebuild) shipped dist/ with no media, because deploy only re-verified the SOURCE tree.
# Fix: prebuild (`media-sync.mjs verify`) writes .media-build-state.json; postbuild (`media-sync.mjs mark`) stamps dist/.media-marker.json {ok,tree,skipped}; deploy = `env -u MEDIA_SKIP node scripts/media-sync.mjs gate && wrangler deploy ...`; gate needs an ok marker, marker.tree == manifest tree, and a valid media tree.
# package.json scripts after: "prebuild": "node scripts/media-sync.mjs verify", "postbuild": "node scripts/media-sync.mjs mark", "deploy": "env -u MEDIA_SKIP node scripts/media-sync.mjs gate && wrangler deploy --config wrangler.cloudflare.jsonc", "test:media-gate": "node --test tests/media-deploy-gate.test.mjs"
# Test result: 5 pass; the same tests fail 5 of 5 against the previous script. Note: pull() calls verify() at its end, so media:pull rewrites .media-build-state.json (does not touch dist/).
=== scripts/media-sync.mjs (final)
"""
mid = "\n=== tests/media-deploy-gate.test.mjs\n"
open(out, 'w').write(head + open(H + 'media-sync.mjs').read() + mid + open(H + 'media-deploy-gate.test.mjs').read())
print(len(open(out).read()))
