// goodqa#15561 click-test helper (LOCAL, disposable, tailnet-bound). Sets the bt_access cookie for the disposable accounts so a
// browser can open the web as: the owner (/s/owner), the CRM-ability bound desktop session (/s/crm), the no-crm bound session
// (/s/nocrm), or signed out (/s/clear), then redirects to the CRM page. Cookies are not port-scoped, so a cookie set on this
// host's port applies to the web on the sibling port. It reads the 0600 secret files server side and never prints a value.
const http = require('node:http');
const fs = require('node:fs');
const KIT = process.env.KIT, HOST = process.env.HOST_IP, PORT = Number(process.env.HELPER_PORT), WEB = process.env.WEB_PORT, API = process.env.API_URL;
const S = JSON.parse(fs.readFileSync(`${KIT}/run/summary.json`, 'utf8'));
const read = (f) => fs.readFileSync(f, 'utf8').trim();
async function ownerAccess() {
  const r = await fetch(`${API}/v1/auth/login`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ email: S.ownerEmail, password: read(S.files.ownerPasswordFile) }) });
  const j = await r.json();
  return j.tokens.accessToken;
}
// A RELATIVE redirect: the helper and the web share one https origin (the helper is mounted under /__ct by tailscale serve).
const target = (path) => path;
// A bound desktop session's access token lives 15 minutes: start a fresh session from the token file on every hit (what ctl sign-in does).
async function freshSession(tokenFile) {
  const r = await fetch(`${API}/v1/me/desktop-session`, { method: 'POST', headers: { 'content-type': 'application/json', authorization: `Bearer ${read(tokenFile)}` }, body: JSON.stringify({ client: 'desktop-ctl' }) });
  const j = await r.json();
  return j.tokens.accessToken;
}
http.createServer(async (req, res) => {
  try {
    const u = new URL(req.url, `http://${HOST}`);
    const who = u.pathname.replace(/^\/s\//, '');
    let value = null;
    if (who === 'owner') value = await ownerAccess();
    else if (who === 'crm') value = await freshSession(S.files.crmTokenFile);
    else if (who === 'nocrm') value = await freshSession(S.files.nocrmTokenFile);
    else if (who === 'clear') value = '';
    else { res.writeHead(404).end('unknown'); return; }
    const to = u.searchParams.get('to') || `/o/${S.orgSlug}/crm`;
    const cookie = value === '' ? 'bt_access=; Path=/; Max-Age=0' : `bt_access=${value}; Path=/; HttpOnly; SameSite=Lax; Max-Age=900`;
    res.writeHead(302, { 'set-cookie': cookie, location: target(to) }).end();
  } catch (e) { res.writeHead(500).end('helper error'); }
}).listen(PORT, HOST, () => console.log(`cookie helper on http://${HOST}:${PORT} (tailnet only)`));
