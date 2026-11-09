// Deploy gate for course media (N2, goodqa#15484). Run: node --test tests/media-deploy-gate.test.mjs
// Scenario that used to ship a site with no media: build with MEDIA_SKIP=1, then restore media, then deploy without rebuilding.
import test from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdirSync, mkdtempSync, rmSync, writeFileSync, existsSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const script = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "scripts", "media-sync.mjs");
const FILES = { "public/audio/a.mp3": "aaaaaaaa", "public/audio/b.mp3": "bbbb" };

function treeHash(files) {
  const h = createHash("sha256");
  for (const f of Object.keys(files).sort()) h.update(`${f}\t${Buffer.byteLength(files[f])}\n`);
  return h.digest("hex");
}
function makeRepo() {
  const dir = mkdtempSync(path.join(tmpdir(), "media-gate-"));
  mkdirSync(path.join(dir, "scripts"));
  cpSync(script, path.join(dir, "scripts", "media-sync.mjs"));
  writeFileSync(path.join(dir, "media-manifest.json"), JSON.stringify({ version: 1, bucket: "b", prefixes: ["public/audio/"], parts: [], totals: { files: 2, content_bytes: 12, parts: 0, tree_sha256: treeHash(FILES) } }));
  return dir;
}
function putMedia(dir) {
  for (const [f, c] of Object.entries(FILES)) { mkdirSync(path.dirname(path.join(dir, f)), { recursive: true }); writeFileSync(path.join(dir, f), c); }
}
function run(dir, cmd, env = {}) {
  const e = { ...process.env, ...env };
  delete e.CI; delete e.WORKERS_CI;
  if (!("MEDIA_SKIP" in env)) delete e.MEDIA_SKIP;
  return spawnSync("node", [path.join(dir, "scripts", "media-sync.mjs"), cmd], { cwd: dir, env: e, encoding: "utf8" });
}
const build = (dir, env) => { const v = run(dir, "verify", env); mkdirSync(path.join(dir, "dist"), { recursive: true }); const m = run(dir, "mark", env); return { v, m }; };

test("a MEDIA_SKIP build followed by media:pull is refused by the deploy gate", () => {
  const dir = makeRepo();
  try {
    const { v } = build(dir, { MEDIA_SKIP: "1" });
    assert.equal(v.status, 0, "MEDIA_SKIP build itself must still complete locally");
    putMedia(dir); // media:pull afterwards, no rebuild
    assert.equal(run(dir, "verify").status, 0, "REGRESSION GUARD: verify alone passes here, so it cannot be the deploy gate");
    const g = run(dir, "gate", { MEDIA_SKIP: "1" });
    assert.equal(g.status, 1, g.stdout + g.stderr);
    assert.match(g.stderr, /did not verify media|MEDIA_SKIP/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a build with verified media passes the deploy gate", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    const { v, m } = build(dir, {});
    assert.equal(v.status, 0); assert.equal(m.status, 0);
    const g = run(dir, "gate");
    assert.equal(g.status, 0, g.stdout + g.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("deploy gate refuses when dist has no marker", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    mkdirSync(path.join(dir, "dist"));
    const g = run(dir, "gate");
    assert.equal(g.status, 1);
    assert.match(g.stderr, /media-marker.json is missing/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("deploy gate refuses when media is damaged after a verified build", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    build(dir, {});
    writeFileSync(path.join(dir, "public/audio/a.mp3"), ""); // truncated
    const g = run(dir, "gate");
    assert.equal(g.status, 1);
    assert.match(g.stderr, /tree hash mismatch/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("deploy gate refuses a dist built against a different manifest", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    build(dir, {});
    const mp = path.join(dir, "dist", ".media-marker.json");
    const m = JSON.parse(readFileSync(mp, "utf8")); m.tree = "0".repeat(64);
    writeFileSync(mp, JSON.stringify(m));
    const g = run(dir, "gate");
    assert.equal(g.status, 1);
    assert.match(g.stderr, /different media manifest/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
