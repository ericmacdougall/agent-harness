"""N2 round 2 (review a7f745488a6f486ff, BLOCK F1-F3): the gate must check what is actually in dist/client, not only the source tree and a marker."""
p = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/media-sync.mjs'
s = open(p).read()

# 1) generic tree hash over [name,size] pairs + dist helpers (after treeHash)
a = s.index('// GNU tar -tv:')
helpers = r'''function treeHashOf(entries) {
  const h = createHash("sha256");
  for (const [n, size] of [...entries].sort((x, y) => (x[0] < y[0] ? -1 : x[0] > y[0] ? 1 : 0))) h.update(`${n}\t${size}\n`);
  return h.digest("hex");
}
// vinext copies public/<x> to dist/client/<x>; power-user/public is a separate worker and is not part of this build output.
const publicPrefixes = () => manifest.prefixes.filter((p) => p.startsWith("public/"));
function sourcePublicEntries() {
  return mediaFiles().filter((f) => f.startsWith("public/")).map((f) => [f, statSync(path.join(root, f)).size]);
}
function distPublicEntries() {
  const out = [];
  for (const p of publicPrefixes()) {
    const rel = p.slice("public/".length);
    for (const f of walk(path.join(root, "dist", "client", rel))) {
      const name = path.relative(path.join(root, "dist", "client"), f).split(path.sep).join("/");
      out.push(["public/" + name, statSync(f).size]);
    }
  }
  return out;
}
'''
s = s[:a] + helpers + s[a:]

# 2) verify(): drop any stale marker first (F3.2)
old = '  const { files, problems } = evaluate();\n  // The build step records'
assert old in s
s = s.replace(old, '  rmSync(path.join(root, "dist", ".media-marker.json"), { force: true }); // a new build must earn its own marker\n  const { files, problems } = evaluate();\n  // The build step records')

# 3) mark(): also require the shipped copy to hold the media right now
old = '  const ok = !!state && state.ok === true && state.tree === manifest.totals.tree_sha256;\n'
assert old in s
s = s.replace(old, '  const distOk = treeHashOf(distPublicEntries()) === treeHashOf(sourcePublicEntries());\n  const ok = !!state && state.ok === true && state.tree === manifest.totals.tree_sha256 && distOk;\n')
s = s.replace('JSON.stringify({ ok, tree: state?.tree || null, skipped: !!state?.skipped,', 'JSON.stringify({ ok, tree: state?.tree || null, skipped: !!state?.skipped, distOk,')

# 4) gate(): the shipped dist/client must hold exactly the public media (paths and sizes) the manifest-verified source holds
old = '  const { problems } = evaluate();\n  why.push(...problems);\n  if (why.length) { console.error(`DEPLOY REFUSED'
assert old in s
s = s.replace(old, '''  const { problems } = evaluate();
  why.push(...problems);
  const dist = distPublicEntries();
  const src = sourcePublicEntries();
  if (treeHashOf(dist) !== treeHashOf(src)) why.push(`dist/client holds ${dist.length} public media files but the verified source tree has ${src.length} (or their paths or sizes differ): this build output does not contain the media`);
  if (why.length) { console.error(`DEPLOY REFUSED''')

# 5) malformed marker fails closed with a clean message
s = s.replace('    const m = JSON.parse(readFileSync(markerPath, "utf8"));\n    if (m.ok !== true)', '    let m = {};\n    try { m = JSON.parse(readFileSync(markerPath, "utf8")); } catch { why.push("dist/.media-marker.json is not valid JSON"); }\n    if (m.ok !== true)')
open(p, 'w').write(s)
print('patched')
