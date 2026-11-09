'use strict';
// goodqa#15477 F1: real Electron, the real AgentBrowserHost (dist), a fake camera. A visible agent tab captures the
// camera and holds staged input (typed text and a file on a file input); then the consent is revoked for that tab
// (stopTab, stop or a renew that drops capture) while the page resists replacement (beforeunload handler, 204,
// attachment, a GET that never answers). Prints one JSON line to RC_RESULT. Local 127.0.0.1 servers only.
const { app, dialog } = require('electron');
const { createServer } = require('node:http');
const { writeFileSync } = require('node:fs');

app.commandLine.appendSwitch('use-fake-device-for-media-stream');
app.commandLine.appendSwitch('use-fake-ui-for-media-stream');
const { RC_HOST: hostPath, RC_MODE: mode, RC_PATH: path, RC_RESULT: resultPath, RC_PROFILE: profilePath } = process.env;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function probe() {
  // The host asks the person before granting a device; this fixture is the person and says yes.
  dialog.showMessageBox = async () => ({ response: 1, checkboxChecked: false });
  const logs = [];
  const error = console.error;
  console.error = (...a) => { logs.push(a.map(String).join(' ')); error(...a); };
  const { AgentBrowserHost } = require(hostPath);
  let armed = false, hits = 0;
  const hung = [];
  const server = createServer((q, r) => {
    if (q.url === '/favicon.ico') { r.statusCode = 404; return r.end(); }
    if (armed) {
      hits++;
      if (mode === 'nocontent') { r.statusCode = 204; return r.end(); }
      if (mode === 'download') { r.setHeader('content-type', 'application/octet-stream'); r.setHeader('content-disposition', 'attachment; filename=x.bin'); return r.end('x'); }
      if (mode === 'hang') { hung.push(r); return; }
    }
    r.setHeader('content-type', 'text/html');
    const bu = mode === 'beforeunload' ? '<script>addEventListener("beforeunload", (e) => { e.preventDefault(); e.returnValue = "x"; });</script>' : '';
    r.end('<!doctype html><title>t</title>' + bu + '<input id=t><input id=f type=file><p>page</p>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const orgId = '11111111-1111-1111-1111-111111111111', userId = '22222222-2222-2222-2222-222222222222';
  const host = new AgentBrowserHost(() => {}, () => ({ orgId, userId }));
  const consent = (generation) => ({ orgId, userId, agentId: 'a', agentLabel: 'Synthetic', sessionId: 's', generation, expiresAt: Date.now() + 120000, permissions: { origins: [base], localNetwork: true, camera: true, uploads: true } });
  host.grant(consent(1));
  const out = await host.execute({ id: '1', seq: 1, kind: 'browser_open', args: { surface: 'desktop_visible', url: base + '/', scope: { orgId, userId, remoteSessionId: 's', consentGeneration: 1 } }, expiresAt: Date.now() + 60000, lease: { mode: 'control', expiresAt: Date.now() + 60000 }, principal: { id: 'a', label: 'Synthetic' } });
  if (out.status !== 'ok') throw new Error('open failed: ' + JSON.stringify(out.error));
  const tabId = out.result.data.tabId;
  const wc = host.tabs.get(tabId).view.webContents;
  const tabState = () => host.state().tabs.find((t) => t.id === tabId) || null;
  // Sticky user activation (a click), so a beforeunload handler is allowed to prompt.
  wc.sendInputEvent({ type: 'mouseDown', x: 10, y: 10, button: 'left', clickCount: 1 });
  wc.sendInputEvent({ type: 'mouseUp', x: 10, y: 10, button: 'left', clickCount: 1 });
  const before = await wc.executeJavaScript(`(async () => {
    window.__doc = 'old';
    document.getElementById('t').value = 'typed by person';
    const dt = new DataTransfer(); dt.items.add(new File(['secret'], 'staged.txt', { type: 'text/plain' }));
    document.getElementById('f').files = dt.files;
    try { window.__s = await navigator.mediaDevices.getUserMedia({ video: true }); } catch (e) { return { error: e.name }; }
    return { track: window.__s.getVideoTracks()[0].readyState, files: document.getElementById('f').files.length };
  })()`, true);
  const mediaBefore = tabState() && tabState().media;
  armed = true;
  const started = Date.now();
  if (path === 'stop') host.stop();
  else if (path === 'renew') host.grant(consent(2));
  else host.stopTab(tabId);
  const immediately = tabState();
  // Observe the indicator while the replacement is pending, then the final page.
  const timeline = [];
  for (let i = 0; i < 14; i++) { await sleep(400); const s = tabState(); timeline.push({ ms: Date.now() - started, media: s && s.media, revocation: s ? s.revocation : 'closed' }); }
  if (!wc.debugger.isAttached()) wc.debugger.attach('1.3');
  const ev = await wc.debugger.sendCommand('Runtime.evaluate', {
    expression: `JSON.stringify({ doc: window.__doc || null, hasStream: typeof window.__s, state: window.__s ? window.__s.getVideoTracks()[0].readyState : null, input: document.getElementById('t') ? document.getElementById('t').value : null, files: document.getElementById('f') ? document.getElementById('f').files.length : null })`,
    returnByValue: true,
  }).catch((e) => ({ result: { value: JSON.stringify({ cdpError: String(e.message).slice(0, 80) }) } }));
  const after = JSON.parse(ev.result.value);
  const result = { mode, path, before, mediaBefore, immediately: immediately && { media: immediately.media, revocation: immediately.revocation }, timeline, after, hits, urlAfter: wc.getURL(), final: tabState(), logs: logs.filter((l) => l.includes('revoke_failed')) };
  for (const r of hung) r.destroy();
  host.stop();
  server.close();
  return result;
}

(async () => {
  app.on('window-all-closed', () => {});
  app.setPath('userData', profilePath);
  await app.whenReady();
  writeFileSync(resultPath, JSON.stringify(await probe()));
  app.exit(0);
})().catch((e) => { console.error(e); app.exit(1); });
