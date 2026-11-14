// Owner panel keyboard and focus check through headless Chrome (goodqa#15920 AC-5; supporting evidence, not part of
// `node --test`; the independent click-test is the gate). usage: node owners.cdp.mjs <launch-url> [expected-live] [rerender-wait-s]
// Asserts: headline equals expected live owners; each fold is a button with aria-expanded and an aria-controls target
// that exists; Enter opens and Space closes it with focus kept on it; the open state and focus survive an owners
// re-render (the collector refreshes every 60 s while a page is attached); helpers render as nested rows; no
// horizontal scroll at 360 px.
import { spawn } from 'node:child_process';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';

const [launch, expected = '', waitS = '70'] = process.argv.slice(2);
const port = 9700 + Math.floor(Math.random() * 200);
const profile = mkdtempSync(`${tmpdir()}/mc-owners-`);
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
const key = async (keyName, code, keyCode, text) => {
  await send('Input.dispatchKeyEvent', { type: 'keyDown', key: keyName, code, windowsVirtualKeyCode: keyCode, text });
  await send('Input.dispatchKeyEvent', { type: 'keyUp', key: keyName, code, windowsVirtualKeyCode: keyCode });
  await sleep(300);
};
const failures = [];
await send('Page.enable');
await send('Emulation.setDeviceMetricsOverride', { width: 1280, height: 900, deviceScaleFactor: 1, mobile: false });
await send('Page.navigate', { url: launch });
await sleep(7000);
await run("document.getElementById('tab-overview')?.click()");
await sleep(800);
const probe = `(() => { const f = document.querySelector('#owners-list .owner-fold:not([hidden])');
  const target = f && document.getElementById(f.getAttribute('aria-controls'));
  return { count: document.getElementById('owner-count').textContent, summary: document.getElementById('owner-summary')?.textContent,
    groups: document.querySelectorAll('#owners-list .owner-group').length, owners: document.querySelectorAll('#owners-list .owner-group-live .owner-row').length,
    helpers: document.querySelectorAll('#owners-list .owner-group-live .helper-row').length,
    fold: f ? { tag: f.tagName, type: f.type, expanded: f.getAttribute('aria-expanded'), label: f.textContent, controls: !!target, targetHidden: target?.hidden, inside: target ? target.querySelectorAll('.owner-row, .helper-row').length : -1 } : null,
    focused: document.activeElement === f }; })()`;
const before = await run(probe);
if (expected && before.count !== expected.padStart(2, '0')) failures.push(`headline ${before.count} != ${expected}`);
if (!before.fold) failures.push('no visible fold button');
else {
  if (before.fold.tag !== 'BUTTON' || before.fold.type !== 'button') failures.push('fold is not a native button');
  if (before.fold.expanded !== 'false' || !before.fold.controls || before.fold.targetHidden !== true) failures.push('fold does not start collapsed with a hidden aria-controls target');
}
await run("document.querySelector('#owners-list .owner-fold:not([hidden])').focus()");
await key('Enter', 'Enter', 13, '\r');
const opened = await run(probe);
if (opened.fold?.expanded !== 'true' || opened.fold.targetHidden !== false || opened.fold.inside < 1) failures.push('Enter did not open the fold');
if (!opened.focused) failures.push('focus left the fold after Enter');
let rerender = null;
if (Number(waitS) > 0) {
  await run("window.__ownersMark = document.getElementById('owner-count').title; window.__ownersRenders = 0; new MutationObserver(() => window.__ownersRenders++).observe(document.getElementById('owners-list'), { subtree: true, childList: true, characterData: true, attributes: true })");
  await sleep(Number(waitS) * 1000);
  // and one forced owners render through the page's own store module (same URL, same instance), so the check never
  // depends on the collector having pushed during the wait
  const forced = (await send('Runtime.evaluate', { expression: "import('./js/store.js').then(m => { m.update({ owners: m.getState().owners.map(o => ({ ...o })) }, 'owners'); return true; })", awaitPromise: true, returnByValue: true })).result?.result?.value;
  if (forced !== true) failures.push('could not force an owners re-render');
  await sleep(300);
  rerender = await run(`(() => ({ ...${probe}, renders: window.__ownersRenders }))()`);
  if (rerender.fold?.expanded !== 'true' || !rerender.focused) failures.push('open state or focus lost across a re-render');
}
await key(' ', 'Space', 32, ' ');
const closed = await run(probe);
if (closed.fold?.expanded !== 'false' || closed.fold.targetHidden !== true) failures.push('Space did not close the fold');
if (!closed.focused) failures.push('focus left the fold after Space');
// Focus follows rows through re-renders (code inspection F2), driven through the page's own store module.
const storeCall = async body => (await send('Runtime.evaluate', { expression: `import('./js/store.js').then(m => { ${body} })`, awaitPromise: true, returnByValue: true })).result?.result?.value;
const active = () => run("(() => { const a = document.activeElement; return { id: a?.dataset?.id || null, fold: !!a?.classList?.contains('owner-fold'), panel: a?.id === 'owners-panel', body: a === document.body }; })()");
const firstLive = await run("document.querySelector('#owners-list .owner-group-live .owner-row')?.dataset.id || null");
const focusRow = id => run(`(() => { const r = document.querySelector('#owners-list [data-id="${id}"]'); r?.focus(); return document.activeElement === r; })()`);
const focus = { reorder: null, parked: null, removed: null };
if (firstLive && await focusRow(firstLive)) {
  await storeCall("m.update({ owners: m.getState().owners.slice().reverse().map(o => ({ ...o })) }, 'owners'); return true;");
  await sleep(200);
  focus.reorder = await active();
  if (focus.reorder.id !== firstLive) failures.push('focus left a row that only moved');
  await storeCall(`m.update({ ownerFolds: {}, owners: m.getState().owners.map(o => o.agent_id === '${firstLive}' ? { ...o, role: 'parked', severe: false, decision_required: false } : { ...o }) }, 'owners'); return true;`);
  await sleep(200);
  focus.parked = await active();
  if (!focus.parked.fold) failures.push('a row that folded away did not hand focus to its fold');
  await storeCall("m.update({ owners: [] }, 'owners'); return true;");
  await sleep(200);
  focus.removed = await active();
  if (focus.removed.body || !(focus.removed.fold || focus.removed.panel)) failures.push('focus fell to the page body when every group went away');
} else failures.push('no live owner row to focus');
await send('Emulation.setDeviceMetricsOverride', { width: 360, height: 640, deviceScaleFactor: 1, mobile: true });
await sleep(800);
const narrow = await run('({ width: innerWidth, scrollW: document.documentElement.scrollWidth })');
if (narrow.scrollW > narrow.width) failures.push(`horizontal scroll at 360 px (${narrow.scrollW})`);
console.log(JSON.stringify({ before, opened, rerender, closed, focus, narrow, failures }, null, 1));
ws.close(); chrome.kill();
process.exit(failures.length ? 1 : 0);
