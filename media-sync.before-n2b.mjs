#!/usr/bin/env node
// Course media lives in Cloudflare R2 (bucket learnai-field-lab-media), not in git.
// media-manifest.json lists deterministic tar parts (key, sha256, size) and totals.tree_sha256, a hash of every media path and size.
//   node scripts/media-sync.mjs pull    download missing parts into .media-cache/, verify sha256, check members, extract into the repo
//   node scripts/media-sync.mjs verify  fail unless the media tree on disk matches the manifest exactly (paths and sizes), and git tracks none of it
//   node scripts/media-sync.mjs mark    postbuild: stamp whether the build verified media into dist/.media-marker.json
//   node scripts/media-sync.mjs gate    deploy gate: refuse a dist/ whose build did not verify media (never honors MEDIA_SKIP)
//   node scripts/media-sync.mjs push    add NEW media paths as a new part, upload it, append it to the manifest (changing an existing file is refused)
//   node scripts/media-sync.mjs tree    print the tree hash of the media on disk (use after packing to fill totals.tree_sha256)
// R2 access goes through the logged-in wrangler (account from wrangler.cloudflare.jsonc). GNU tar is required (Linux; on macOS use gtar).
// MEDIA_SKIP=1 skips verify for local non-shipping builds only; it is refused when CI or WORKERS_CI is set, and `npm run deploy` ignores it.
import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, writeFileSync, statSync, readdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = path.join(root, "media-manifest.json");
const cacheDir = path.join(root, ".media-cache");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const accountId = () => /"account_id"\s*:\s*"([0-9a-f]+)"/.exec(readFileSync(path.join(root, "wrangler.cloudflare.jsonc"), "utf8"))?.[1];

function run(cmd, args, opts = {}) {
  const env = { ...process.env, CLOUDFLARE_ACCOUNT_ID: process.env.CLOUDFLARE_ACCOUNT_ID || (opts.r2 ? accountId() : undefined) };
  const r = spawnSync(cmd, args, { cwd: root, env, stdio: opts.capture ? ["ignore", "pipe", "inherit"] : "inherit", maxBuffer: 1 << 30, encoding: opts.capture ? "utf8" : undefined });
  if (r.status !== 0) throw new Error(`${cmd} ${args.slice(0, 4).join(" ")} failed (${r.status})`);
  return r.stdout;
}
function sha256(file) {
  return new Promise((res, rej) => { const h = createHash("sha256"); createReadStream(file).on("data", (d) => h.update(d)).on("end", () => res(h.digest("hex"))).on("error", rej); });
}
function walk(dir, out = []) {
  if (!existsSync(dir)) return out;
  for (const e of readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name);
    if (e.isDirectory()) walk(p, out); else out.push(p);
  }
  return out;
}
const mediaFiles = () => manifest.prefixes.flatMap((p) => walk(path.join(root, p))).map((f) => path.relative(root, f).split(path.sep).join("/")).sort();
function treeHash(files = mediaFiles()) {
  const h = createHash("sha256");
  for (const f of files) h.update(`${f}\t${statSync(path.join(root, f)).size}\n`);
  return h.digest("hex");
}
// GNU tar -tv: "-rw-r--r-- 0/0 12345 1970-01-01 00:00 path"; returns [{type, size, name}]
function listPart(file) {
  return run("tar", ["--quoting-style=literal", "-tvf", file], { capture: true }).split("\n").filter(Boolean).map((l) => {
    const m = /^(\S)\S+\s+\S+\s+(\d+)\s+\S+\s+\S+\s+(.*)$/.exec(l);
    if (!m) throw new Error(`unparseable tar listing line: ${l}`);
    return { type: m[1], size: Number(m[2]), name: m[3] };
  });
}
function checkMembers(entries, key) {
  for (const e of entries) {
    if (e.type !== "-") throw new Error(`${key}: member ${e.name} is not a regular file`);
    if (e.name.startsWith("/") || e.name.split("/").includes("..") || !manifest.prefixes.some((p) => e.name.startsWith(p.replace(/\/?$/, "/")))) throw new Error(`${key}: member ${e.name} is outside the media prefixes`);
  }
}

async function pull() {
  mkdirSync(cacheDir, { recursive: true });
  // --only=part-0001,part-0010 restores a subset (proof runs); a subset never runs the completeness check.
  const onlyArg = process.argv.find((a) => a.startsWith("--only="))?.slice(7);
  const only = onlyArg ? onlyArg.split(",") : null;
  const dest = process.env.MEDIA_DEST ? path.resolve(process.env.MEDIA_DEST) : root;
  mkdirSync(dest, { recursive: true });
  const keepCache = process.env.MEDIA_KEEP_CACHE === "1";
  for (const part of manifest.parts) {
    if (only && !only.some((o) => path.basename(part.key).startsWith(o))) continue;
    const file = path.join(cacheDir, path.basename(part.key));
    if (!(existsSync(file) && statSync(file).size === part.bytes && (await sha256(file)) === part.sha256)) {
      console.log("downloading", part.key);
      run("npx", ["--no-install", "wrangler", "r2", "object", "get", `${manifest.bucket}/${part.key}`, "--file", file, "--remote"], { r2: true });
      const got = await sha256(file);
      if (got !== part.sha256) { rmSync(file); throw new Error(`sha256 mismatch for ${part.key}`); }
    }
    checkMembers(listPart(file), part.key);
    run("tar", ["-xf", file, "-C", dest, "--no-same-owner"]);
    console.log("extracted", part.key, part.files, "files");
    if (!keepCache && !only) rmSync(file);
  }
  if (!only) verify();
}
function evaluate() {
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
async function push() {
  mkdirSync(cacheDir, { recursive: true });
  const known = new Map();
  for (const part of manifest.parts) {
    const file = path.join(cacheDir, path.basename(part.key));
    if (!existsSync(file)) throw new Error(`run media:pull first with MEDIA_KEEP_CACHE=1 (missing ${file})`);
    for (const e of listPart(file)) known.set(e.name, e.size);
  }
  const files = mediaFiles();
  const changed = files.filter((f) => known.has(f) && known.get(f) !== statSync(path.join(root, f)).size);
  const missing = [...known.keys()].filter((f) => !files.includes(f));
  if (changed.length || missing.length) throw new Error(`push only adds new paths. Changed: ${changed.slice(0, 3).join(", ") || "none"}; missing: ${missing.slice(0, 3).join(", ") || "none"}. Use a new filename for changed media.`);
  const fresh = files.filter((f) => !known.has(f));
  if (!fresh.length) return console.log("nothing new to push");
  const idx = manifest.parts.length + 1;
  const tmp = path.join(cacheDir, `new-${idx}.tar`);
  const list = path.join(cacheDir, `new-${idx}.list`);
  writeFileSync(list, fresh.join("\n") + "\n");
  run("tar", ["--format=pax", "--numeric-owner", "--owner=0", "--group=0", "--mtime=@0", "-cf", tmp, "-T", list]);
  const sha = await sha256(tmp);
  const key = `media/v1/part-${String(idx).padStart(4, "0")}-${sha.slice(0, 12)}.tar`;
  if (manifest.parts.some((p) => p.key === key)) throw new Error("duplicate part key");
  run("npx", ["--no-install", "wrangler", "r2", "object", "put", `${manifest.bucket}/${key}`, "--file", tmp, "--remote"], { r2: true });
  const final = path.join(cacheDir, path.basename(key));
  run("mv", [tmp, final]);
  rmSync(list);
  const size = fresh.reduce((s, f) => s + statSync(path.join(root, f)).size, 0);
  manifest.parts.push({ key, sha256: sha, bytes: statSync(final).size, files: fresh.length, content_bytes: size, first: fresh[0], last: fresh.at(-1) });
  manifest.totals = { files: files.length, content_bytes: manifest.parts.reduce((s, p) => s + p.content_bytes, 0), parts: manifest.parts.length, tree_sha256: treeHash(files) };
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 1) + "\n");
  console.log("pushed", key, fresh.length, "files; commit media-manifest.json");
}

const cmd = process.argv[2];
if (cmd === "pull") await pull();
else if (cmd === "verify") verify();
else if (cmd === "mark") mark();
else if (cmd === "gate") gate();
else if (cmd === "push") await push();
else if (cmd === "tree") console.log(treeHash());
else { console.error("usage: media-sync.mjs pull|verify|mark|gate|push|tree"); process.exit(2); }
