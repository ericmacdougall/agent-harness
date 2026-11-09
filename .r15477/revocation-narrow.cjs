'use strict';
// goodqa#15477 final delta F1: real Electron, the real host (dist). A visible agent tab holds a staged 4 KB file in a
// multipart form; the renew turns uploads off (narrowing keeps the tab under the agent and replaces the document). The
// page's beforeunload busy-loops 6 s, so the replacement cannot commit within its bounds. An agent click on submit,
// during the revocation and after it, must not land, and no multipart POST may reach the server. Local 127.0.0.1 only.
// After the red-team probe rc6.cjs (agent abe43bbd).
const { app } = require('electron');
const { createServer } = require('node:http');
const { writeFileSync } = require('node:fs');
const { RC_HOST: hostPath, RC_RESULT: resultPath, RC_PROFILE: profilePath } = process.env;
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function probe() {
  const logs = [];
  const error = console.error;
  console.error = (...a) => { logs.push(a.map(String).join(' ')); error(...a); };
  const { AgentBrowserHost } = require(hostPath);
  const posts = [];
  let started = 0;
  const server = createServer((q, r) => {
    if (q.url === '/favicon.ico') { r.statusCode = 404; return r.end(); }
    if (q.method === 'POST') { let n = 0; q.on('data', (c) => { n += c.length; }); q.on('end', () => { posts.push({ ms: Date.now() - started, bytes: n }); r.end('ok'); }); return; }
    r.setHeader('content-type', 'text/html');
    r.end('<!doctype html><title>t</title><script>addEventListener("beforeunload", () => { const t = Date.now(); while (Date.now() - t < 6000) {} });</script><form id=fm method=post enctype=multipart/form-data action=/up target=sink><input id=f name=f type=file><button id=b style="position:fixed;left:0;top:0;width:300px;height:200px">send</button></form><iframe name=sink></iframe>');
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const base = 'http://127.0.0.1:' + server.address().port;
  const orgId = '11111111-1111-1111-1111-111111111111', userId = '22222222-2222-2222-2222-222222222222';
  const host = new AgentBrowserHost(() => {}, () => ({ orgId, userId }));
  const consent = (generation, extra) => ({ orgId, userId, agentId: 'a', agentLabel: 'Synthetic', sessionId: 's', generation, expiresAt: Date.now() + 120000, permissions: { origins: [base], localNetwork: true, uploads: true, ...extra } });
  host.grant(consent(1));
  const out = await host.execute({ id: '1', seq: 1, kind: 'browser_open', args: { surface: 'desktop_visible', url: base + '/', scope: { orgId, userId, remoteSessionId: 's', consentGeneration: 1 } }, expiresAt: Date.now() + 60000, lease: { mode: 'control', expiresAt: Date.now() + 60000 }, principal: { id: 'a', label: 'Synthetic' } });
  if (out.status !== 'ok') throw new Error('open failed: ' + JSON.stringify(out.error));
  const tabId = out.result.data.tabId;
  const wc = host.tabs.get(tabId).view.webContents;
  const staged = await wc.executeJavaScript(`(() => { const dt = new DataTransfer(); dt.items.add(new File(["x".repeat(4096)], "staged.txt", { type: "text/plain" })); document.getElementById("f").files = dt.files; return document.getElementById("f").files.length; })()`, true);
  const tabState = () => { const s = host.state().tabs.find((t) => t.id === tabId); return s ? { revocation: s.revocation ?? null, controller: s.controller, stopped: s.stopped } : null; };
  const cmd = (seq, kind, args) => host.execute({ id: String(seq), seq, kind, args: { tabId, surface: 'desktop_visible', ...args, scope: { orgId, userId, remoteSessionId: 's', consentGeneration: 2 } }, expiresAt: Date.now() + 30000, lease: { mode: 'control', expiresAt: Date.now() + 30000 }, principal: { id: 'a', label: 'Synthetic' } });
  const brief = (o) => ({ status: o.status, error: o.error ? { message: o.error.message } : undefined, thrown: o.thrown });
  started = Date.now();
  host.grant(consent(2, { uploads: false }));
  const atRenew = tabState();
  await sleep(300);
  const early = brief(await cmd(10, 'browser_click', { x: 50, y: 50 }).catch((e) => ({ thrown: String(e.message).slice(0, 80) })));
  await sleep(Math.max(0, 9000 - (Date.now() - started)));
  const late = brief(await cmd(11, 'browser_click', { x: 50, y: 50 }).catch((e) => ({ thrown: String(e.message).slice(0, 80) })));
  await sleep(4000);
  const result = { mode: 'busy', path: 'narrow', staged, atRenew, early, late, posts, final: tabState(), logs: logs.filter((l) => l.includes('revoke_failed') || l.includes('tab_closed')) };
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
