// Layout measurements through headless Chrome (supporting evidence, not part of `node --test`; the independent click-test
// on the real install is the gate). usage: node fold.cdp.mjs <launch-url>
// Asserts: at 1280x800 and 360x640 the page has no horizontal scroll, and the above-the-fold content named in the spec.
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

const launch = process.argv[2];
const port = 9700 + Math.floor(Math.random() * 200);
const profile = mkdtempSync(`${tmpdir()}/mc-fold-`);
const chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', ['--headless=new', `--remote-debugging-port=${port}`, `--user-data-dir=${profile}`, '--no-first-run', 'about:blank'], { stdio: 'ignore' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let targets;
for (let i = 0; i < 50 && !targets; i++) { try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); } catch { await sleep(200); } }
const ws = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
await new Promise(r => ws.addEventListener('open', r));
let id = 0; const waiting = new Map();
ws.addEventListener('message', ev => { const m = JSON.parse(ev.data); if (m.id && waiting.has(m.id)) { waiting.get(m.id)(m); waiting.delete(m.id); } });
const send = (method, params = {}) => new Promise(r => { const n = ++id; waiting.set(n, r); ws.send(JSON.stringify({ id: n, method, params })); });
const run = async expression => (await send('Runtime.evaluate', { expression, returnByValue: true })).result?.result?.value;
await send('Page.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 800, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: launch });
await sleep(7000);
const probe = `(() => { const r = s => { const e = document.querySelector(s); if (!e) return null; const b = e.getBoundingClientRect(); return { top: Math.round(b.top), bottom: Math.round(b.bottom) }; };
  return { width: innerWidth, height: innerHeight, scrollW: document.documentElement.scrollWidth, tiles: r('#mission-tiles'), goal1: r('.goal'), goal2: r('.goal:nth-child(2)'),
  ownersHeading: r('#owners-heading'), needsHeading: r('#needs-heading'), deploysHeading: r('#deploys-heading'),
  goals: document.querySelectorAll('#goals-list .goal').length, deals: document.querySelectorAll('#deploys-list .deal').length, blockers: document.querySelectorAll('#blockers-list .blocker').length,
  owners: document.querySelectorAll('#owners-list .owner-row').length, asks: document.querySelectorAll('#needs-list > .needs-item').length, openDetails: document.querySelectorAll('#view-overview details[open]').length }; })()`;
const results = {}; const failures = [];
for (const [name, w, h] of [['1280x800', 1280, 800], ['360x640', 360, 640]]) {
  await send('Emulation.setDeviceMetricsOverride', { width: w, height: h, deviceScaleFactor: 1, mobile: w < 500 });
  await run("document.getElementById('tab-overview').click()");
  await sleep(800);
  const m = results[name] = await run(probe);
  if (m.scrollW > m.width) failures.push(`${name}: horizontal scroll (${m.scrollW} > ${m.width})`);
  if (!(m.tiles && m.tiles.bottom <= h)) failures.push(`${name}: summary tiles not above the fold`);
  if (!(m.goal1 && m.goal1.bottom <= h) && m.goals) failures.push(`${name}: first goal not above the fold`);
  if (w >= 1000 && !(m.ownersHeading && m.ownersHeading.top < h + 400)) failures.push(`${name}: owners panel too far down`);
  if (m.goals > 5 || m.deals > 5 || m.blockers > 5 || m.owners > 8 || m.asks > 5) failures.push(`${name}: a section shows more than its default rows`);
  if (m.openDetails > 0) failures.push(`${name}: a details element starts open`);
}
console.log(JSON.stringify({ results, failures }, null, 1));
ws.close(); chrome.kill();
process.exit(failures.length ? 1 : 0);
