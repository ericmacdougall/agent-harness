// Deploy gate for course media (N2, goodqa#15484). Run: node --test tests/media-deploy-gate.test.mjs
// Scenario that used to ship a site with no media: build with MEDIA_SKIP=1, then restore media, then deploy without rebuilding.
// The stand-in build copies public/ to dist/client like vinext does, so the tests can tell a dist with media from one without.
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
// stand-in for `npm run build`: prebuild (verify), the build itself (public/ -> dist/client), postbuild (mark)
function build(dir, env = {}) {
  const v = run(dir, "verify", env);
  rmSync(path.join(dir, "dist"), { recursive: true, force: true });
  mkdirSync(path.join(dir, "dist", "client"), { recursive: true });
  if (existsSync(path.join(dir, "public"))) cpSync(path.join(dir, "public"), path.join(dir, "dist", "client"), { recursive: true });
  const m = run(dir, "mark", env);
  return { v, m };
}

test("a MEDIA_SKIP build followed by media:pull is refused by the deploy gate", () => {
  const dir = makeRepo();
  try {
    const { v } = build(dir, { MEDIA_SKIP: "1" });
    assert.equal(v.status, 0, "MEDIA_SKIP build itself must still complete locally");
    putMedia(dir); // media:pull afterwards, no rebuild
    assert.equal(run(dir, "verify").status, 0, "REGRESSION GUARD: verify alone passes here, so it cannot be the deploy gate");
    const g = run(dir, "gate", { MEDIA_SKIP: "1" });
    assert.equal(g.status, 1, g.stdout + g.stderr);
    assert.match(g.stderr, /did not verify media|MEDIA_SKIP|does not contain the media/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("F1: media:pull finishing between the build and postbuild cannot produce an ok marker on an empty dist", () => {
  const dir = makeRepo();
  try {
    run(dir, "verify", { MEDIA_SKIP: "1" });                      // prebuild of a skip build: state = skipped
    rmSync(path.join(dir, "dist"), { recursive: true, force: true });
    mkdirSync(path.join(dir, "dist", "client"), { recursive: true }); // build output without media
    putMedia(dir);
    assert.equal(run(dir, "verify").status, 0);                    // media:pull's final verify rewrites the state to ok
    run(dir, "mark");                                              // postbuild now sees ok state
    const g = run(dir, "gate");
    assert.equal(g.status, 1, g.stdout + g.stderr);
    assert.match(g.stderr, /does not contain the media/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("F2: a stale ok marker does not let a later media-less dist through", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    build(dir);                                                    // good build, ok marker
    rmSync(path.join(dir, "dist", "client", "audio"), { recursive: true, force: true }); // dist rebuilt without media, postbuild never ran
    const g = run(dir, "gate");
    assert.equal(g.status, 1, g.stdout + g.stderr);
    assert.match(g.stderr, /does not contain the media/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a new verify removes an old marker (a build must earn its own)", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    build(dir);
    assert.ok(existsSync(path.join(dir, "dist", ".media-marker.json")));
    run(dir, "verify");
    assert.ok(!existsSync(path.join(dir, "dist", ".media-marker.json")));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("a build with verified media passes the deploy gate", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    const { v, m } = build(dir);
    assert.equal(v.status, 0); assert.equal(m.status, 0);
    const g = run(dir, "gate");
    assert.equal(g.status, 0, g.stdout + g.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("deploy gate refuses when dist has no marker", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    mkdirSync(path.join(dir, "dist", "client"), { recursive: true });
    const g = run(dir, "gate");
    assert.equal(g.status, 1);
    assert.match(g.stderr, /media-marker.json is missing/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("deploy gate refuses a malformed marker with a clean message", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    build(dir);
    writeFileSync(path.join(dir, "dist", ".media-marker.json"), "{not json");
    const g = run(dir, "gate");
    assert.equal(g.status, 1);
    assert.match(g.stderr, /not valid JSON/);
    assert.doesNotMatch(g.stderr, /SyntaxError/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("deploy gate refuses when media is damaged after a verified build", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    build(dir);
    writeFileSync(path.join(dir, "public/audio/a.mp3"), ""); // truncated
    const g = run(dir, "gate");
    assert.equal(g.status, 1);
    assert.match(g.stderr, /tree hash mismatch/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("deploy gate checks sizes and names in dist, not only the file count", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    build(dir);
    const a = path.join(dir, "dist", "client", "audio", "a.mp3");
    writeFileSync(a, "x");                                         // same count, wrong size
    let g = run(dir, "gate");
    assert.equal(g.status, 1, g.stdout + g.stderr);
    assert.match(g.stderr, /does not contain the media/);
    writeFileSync(a, FILES["public/audio/a.mp3"]);                 // restore
    assert.equal(run(dir, "gate").status, 0);
    cpSync(a, path.join(dir, "dist", "client", "audio", "renamed.mp3")); // same size, wrong name: a.mp3 now missing
    rmSync(a);
    g = run(dir, "gate");
    assert.equal(g.status, 1, g.stdout + g.stderr);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test("deploy gate refuses a dist built against a different manifest", () => {
  const dir = makeRepo();
  try {
    putMedia(dir);
    build(dir);
    const mp = path.join(dir, "dist", ".media-marker.json");
    const m = JSON.parse(readFileSync(mp, "utf8")); m.tree = "0".repeat(64);
    writeFileSync(mp, JSON.stringify(m));
    const g = run(dir, "gate");
    assert.equal(g.status, 1);
    assert.match(g.stderr, /different media manifest/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
