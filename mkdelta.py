W = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/'
head = """# Delta packet: t2-course chore/media-to-r2 head 91d65011 (fixes for red-team F1-F4, F6, F10, F13, F14)
# Prior findings: F1 verify passed missing/truncated media; F2 push dropped changed files; F3 MEDIA_SKIP shipped no audio; F4 deploy had no pull step; F6 tar members; F13 eager config read; F14 npx auto-install
# Tests run on t2-dev (GNU tar): clean verify ok; missing file + junk file rejected; truncated file rejected; MEDIA_SKIP with CI refused; deploy-mode skip rejected; pull --only=part-0021 extracted 100 files.
# Fresh-clone run on the Mac (GNU tar shim): pull of all 25 parts, npm run build rc 0, verify ok (38,218 files, tree c971d8976dd7).
=== scripts/media-sync.mjs (final)
"""
tail = """
=== package.json scripts added
"media:pull": "node scripts/media-sync.mjs pull", "media:verify": "node scripts/media-sync.mjs verify", "media:push": "node scripts/media-sync.mjs push", "prebuild": "node scripts/media-sync.mjs verify", "deploy": "env -u MEDIA_SKIP node scripts/media-sync.mjs verify && wrangler deploy --config wrangler.cloudflare.jsonc"
=== DEPLOYMENT.md deploy steps now
npm ci && npm run media:pull && npm run build && npm run deploy
"""
src = open(W + 'harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/media-sync.mjs').read()
open(W + 'agent-ab8a7d1bf54ed3c9a/t2course-delta-packet.txt', 'w').write(head + src + tail)
print(len(head + src + tail))
