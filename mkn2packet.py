H = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/'
out = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-ab8a7d1bf54ed3c9a/n2-packet-r2.txt'
head = """# N2 DELTA review packet (round 2): t2-course PR 50, branch fix/media-deploy-marker, commit 89465a9115e4 (round 1 was 9a71aa13d620, verdict BLOCK: F1 pull finishing between build and postbuild gives an ok marker on an empty dist; F2 stale ok marker survives a rebuild that skipped postbuild; F3 marker never tied to what dist/client holds). Round-2 changes: gate() and mark() compare the dist/client public media (paths and sizes) with the verified source tree (vinext copies public/<x> to dist/client/<x>; power-user/public is a separate worker, not in this dist); verify() deletes any old dist/.media-marker.json first; a malformed marker fails closed with a clean message. Tests now simulate the build output: 9 pass; 4 of the 9 fail against the round-1 script; the gate also passes on the real 38,218-file build output (34,083 public files in dist/client).
# Bug: `MEDIA_SKIP=1 npm run build` (no media) -> `npm run media:pull` -> `npm run deploy` (no rebuild) shipped dist/ with no media, because deploy only re-verified the SOURCE tree.
# Fix: prebuild (`media-sync.mjs verify`) writes .media-build-state.json; postbuild (`media-sync.mjs mark`) stamps dist/.media-marker.json {ok,tree,skipped}; deploy = `env -u MEDIA_SKIP node scripts/media-sync.mjs gate && wrangler deploy ...`; gate needs an ok marker, marker.tree == manifest tree, and a valid media tree.
# package.json scripts after: "prebuild": "node scripts/media-sync.mjs verify", "postbuild": "node scripts/media-sync.mjs mark", "deploy": "env -u MEDIA_SKIP node scripts/media-sync.mjs gate && wrangler deploy --config wrangler.cloudflare.jsonc", "test:media-gate": "node --test tests/media-deploy-gate.test.mjs"
# Test result: 5 pass; the same tests fail 5 of 5 against the previous script. Note: pull() calls verify() at its end, so media:pull rewrites .media-build-state.json (does not touch dist/).
=== scripts/media-sync.mjs (final)
"""
mid = "\n=== tests/media-deploy-gate.test.mjs\n"
open(out, 'w').write(head + open(H + 'media-sync.mjs').read() + mid + open(H + 'media-deploy-gate.test.mjs').read())
print(len(open(out).read()))
