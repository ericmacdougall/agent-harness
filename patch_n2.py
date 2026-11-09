"""Patch media-sync.mjs for N2: prebuild records whether the media check really passed, postbuild stamps that into dist/.media-marker.json, deploy gate refuses a dist without an ok marker."""
p = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/harness-delivery/.claude/worktrees/agent-ab8a7d1bf54ed3c9a/media-sync.mjs'
s = open(p).read()
a = s.index('function verify() {')
b = s.index('async function push() {')
new_verify = r'''function evaluate() {
  const files = mediaFiles();
  const problems = [];
  const tracked = existsSync(path.join(root, ".git")) ? run("git", ["ls-files", "--", ...manifest.prefixes], { capture: true }).split("\n").filter(Boolean) : [];
  if (tracked.length) problems.push(`git tracks ${tracked.length} media files (first: ${tracked[0]}); media must stay out of git`);
  if (files.length !== manifest.totals.files) problems.push(`${files.length} files on disk, manifest has ${manifest.totals.files}`);
  else if (manifest.totals.tree_sha256 && treeHash(files) !== manifest.totals.tree_sha256) problems.push("media paths or sizes differ from the manifest (tree hash mismatch)");
  if (!manifest.totals.tree_sha256) problems.push("manifest has no totals.tree_sha256");
  return { files, problems };
}
const statePath = path.join(root, ".media-build-state.json");
function verify() {
  const skip = process.env.MEDIA_SKIP === "1";
  if (skip && (process.env.CI || process.env.WORKERS_CI)) { console.error("MEDIA_SKIP is refused in CI."); process.exit(1); }
  const { files, problems } = evaluate();
  // The build step records whether the media check REALLY passed, so a later deploy can tell a skipped build from a verified one.
  writeFileSync(statePath, JSON.stringify({ ok: problems.length === 0, skipped: skip && problems.length > 0, tree: manifest.totals.tree_sha256 || null, at: new Date().toISOString() }) + "\n");
  if (problems.length) {
    if (skip) { console.warn("MEDIA_SKIP=1: media check skipped. This build must NOT be deployed: the deploy gate will refuse it.\n  " + problems.join("\n  ")); return; }
    console.error(`MEDIA INCOMPLETE OR WRONG:\n  ${problems.join("\n  ")}\nRun: npm run media:pull`);
    process.exit(1);
  }
  console.log(`media ok: ${files.length} files, tree ${manifest.totals.tree_sha256.slice(0, 12)}`);
}
// postbuild: stamp the prebuild result into the build output.
function mark() {
  const dist = path.join(root, "dist");
  if (!existsSync(dist)) { console.error("mark: dist/ does not exist; run the build first."); process.exit(1); }
  const state = existsSync(statePath) ? JSON.parse(readFileSync(statePath, "utf8")) : null;
  const ok = !!state && state.ok === true && state.tree === manifest.totals.tree_sha256;
  writeFileSync(path.join(dist, ".media-marker.json"), JSON.stringify({ ok, tree: state?.tree || null, skipped: !!state?.skipped, builtAt: new Date().toISOString() }) + "\n");
  console.log(ok ? "media marker written: build verified media" : "media marker written: build did NOT verify media (deploy will be refused)");
}
// deploy gate: never honors MEDIA_SKIP; needs an ok marker in dist/ from a build that verified the media, plus a still-valid media tree.
function gate() {
  const why = [];
  const markerPath = path.join(root, "dist", ".media-marker.json");
  if (!existsSync(markerPath)) why.push("dist/.media-marker.json is missing: the build did not run the media check (or dist/ is not from `npm run build`)");
  else {
    const m = JSON.parse(readFileSync(markerPath, "utf8"));
    if (m.ok !== true) why.push(`the build in dist/ did not verify media${m.skipped ? " (it was built with MEDIA_SKIP=1)" : ""}`);
    if (m.tree !== manifest.totals.tree_sha256) why.push("dist/ was built against a different media manifest");
  }
  const { problems } = evaluate();
  why.push(...problems);
  if (why.length) { console.error(`DEPLOY REFUSED:\n  ${why.join("\n  ")}\nRebuild with: npm run media:pull && npm run build`); process.exit(1); }
  console.log("deploy gate ok: dist/ was built with verified media");
}
'''
s = s[:a] + new_verify + s[b:]
s = s.replace('else if (cmd === "verify") verify();', 'else if (cmd === "verify") verify();\nelse if (cmd === "mark") mark();\nelse if (cmd === "gate") gate();')
s = s.replace('usage: media-sync.mjs pull|verify|push|tree', 'usage: media-sync.mjs pull|verify|mark|gate|push|tree')
s = s.replace('//   node scripts/media-sync.mjs push ', '//   node scripts/media-sync.mjs mark    postbuild: stamp whether the build verified media into dist/.media-marker.json\n//   node scripts/media-sync.mjs gate    deploy gate: refuse a dist/ whose build did not verify media (never honors MEDIA_SKIP)\n//   node scripts/media-sync.mjs push ', 1)
open(p, 'w').write(s)
print('patched')
