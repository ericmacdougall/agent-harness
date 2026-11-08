#!/usr/bin/env node
// Course media lives in Cloudflare R2 (bucket learnai-field-lab-media), not in git.
// media-manifest.json lists deterministic tar parts (key, sha256, size). Commands:
//   node scripts/media-sync.mjs pull    download missing parts into .media-cache/, verify sha256, extract into the repo
//   node scripts/media-sync.mjs verify  fail unless every manifest part's first/last file exists and the file count is complete (used by prebuild)
//   node scripts/media-sync.mjs push    pack media files not yet in any part into a new part, upload it, append it to the manifest
// R2 access goes through the logged-in wrangler (account from wrangler.cloudflare.jsonc). MEDIA_SKIP=1 skips verify (never for a production deploy).
import { createHash } from "node:crypto";
import { createReadStream, existsSync, mkdirSync, readFileSync, writeFileSync, statSync, readdirSync, rmSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const manifestPath = path.join(root, "media-manifest.json");
const cacheDir = path.join(root, ".media-cache");
const manifest = JSON.parse(readFileSync(manifestPath, "utf8"));
const accountId = /"account_id"\s*:\s*"([0-9a-f]+)"/.exec(readFileSync(path.join(root, "wrangler.cloudflare.jsonc"), "utf8"))?.[1];
const env = { ...process.env, CLOUDFLARE_ACCOUNT_ID: process.env.CLOUDFLARE_ACCOUNT_ID || accountId };

function run(cmd, args, opts = {}) {
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

async function pull() {
  mkdirSync(cacheDir, { recursive: true });
  // --only part-0001,part-0010 restores a subset (proof runs); a subset never runs the completeness check.
  const onlyArg = process.argv.find((a) => a.startsWith("--only="))?.slice(7);
  const only = onlyArg ? onlyArg.split(",") : null;
  const dest = process.env.MEDIA_DEST ? path.resolve(process.env.MEDIA_DEST) : root;
  mkdirSync(dest, { recursive: true });
  for (const part of manifest.parts) {
    if (only && !only.some((o) => path.basename(part.key).startsWith(o))) continue;
    const file = path.join(cacheDir, path.basename(part.key));
    if (!(existsSync(file) && statSync(file).size === part.bytes && (await sha256(file)) === part.sha256)) {
      console.log("downloading", part.key);
      run("npx", ["wrangler", "r2", "object", "get", `${manifest.bucket}/${part.key}`, "--file", file, "--remote"]);
      const got = await sha256(file);
      if (got !== part.sha256) { rmSync(file); throw new Error(`sha256 mismatch for ${part.key}`); }
    }
    run("tar", ["-xf", file, "-C", dest]);
    console.log("extracted", part.key, part.files, "files");
  }
  if (!only) verify();
}
function verify() {
  const missing = [];
  for (const part of manifest.parts) for (const f of [part.first, part.last]) if (!existsSync(path.join(root, f))) missing.push(f);
  const have = mediaFiles().length;
  if (missing.length || have < manifest.totals.files) {
    console.error(`MEDIA INCOMPLETE: ${have}/${manifest.totals.files} files present; missing sentinels: ${missing.slice(0, 3).join(", ") || "none"}.\nRun: npm run media:pull   (set MEDIA_SKIP=1 only for builds that must not ship media)`);
    process.exit(process.env.MEDIA_SKIP === "1" ? 0 : 1);
  }
  console.log(`media ok: ${have} files (manifest ${manifest.totals.files})`);
}
async function push() {
  const known = new Set();
  for (const part of manifest.parts) {
    const file = path.join(cacheDir, path.basename(part.key));
    if (!existsSync(file)) throw new Error(`run media:pull first (missing ${file})`);
    for (const l of run("tar", ["-tf", file], { capture: true }).split("\n")) if (l) known.add(l);
  }
  const fresh = mediaFiles().filter((f) => !known.has(f));
  if (!fresh.length) return console.log("nothing new to push");
  const idx = manifest.parts.length + 1;
  const tmp = path.join(cacheDir, `new-${idx}.tar`);
  const list = path.join(cacheDir, `new-${idx}.list`);
  writeFileSync(list, fresh.join("\n") + "\n");
  run("tar", ["--format=pax", "--numeric-owner", "--owner=0", "--group=0", "--mtime=@0", "-cf", tmp, "-T", list]);
  const sha = await sha256(tmp);
  const key = `media/v1/part-${String(idx).padStart(4, "0")}-${sha.slice(0, 12)}.tar`;
  run("npx", ["wrangler", "r2", "object", "put", `${manifest.bucket}/${key}`, "--file", tmp, "--remote"]);
  const bytes = statSync(tmp).size;
  rmSync(tmp); rmSync(list);
  const size = fresh.reduce((s, f) => s + statSync(path.join(root, f)).size, 0);
  manifest.parts.push({ key, sha256: sha, bytes, files: fresh.length, content_bytes: size, first: fresh[0], last: fresh.at(-1) });
  manifest.totals = { files: manifest.totals.files + fresh.length, content_bytes: manifest.totals.content_bytes + size, parts: manifest.parts.length };
  writeFileSync(manifestPath, JSON.stringify(manifest, null, 1) + "\n");
  console.log("pushed", key, fresh.length, "files; commit media-manifest.json");
}

const cmd = process.argv[2];
if (cmd === "pull") await pull();
else if (cmd === "verify") verify();
else if (cmd === "push") await push();
else { console.error("usage: media-sync.mjs pull|verify|push"); process.exit(2); }
