import subprocess


def fetch(remote, local):
    subprocess.run(['scp', '-q', f't2-dev:wt-15561/apps/api/test/{remote}', local], check=True)


def patch(path, edits):
    s = open(path).read()
    for old, new in edits:
        assert s.count(old) == 1, (path, s.count(old), old[:80])
        s = s.replace(old, new)
    open(path, 'w').write(s)


fetch('user-token-desktop-session-delegation.test.ts', 'user-token-desktop-session-delegation.test.ts')
fetch('user-token-desktop-surface-inventory.test.ts', 'user-token-desktop-surface-inventory.test.ts')
fetch('user-token-parity-fixtures.ts', 'user-token-parity-fixtures.ts')

patch('user-token-desktop-session-delegation.test.ts', [
    ("""    for (const u of [crmUrl('/contacts/00000000-0000-4000-8000-000000000000'), crmUrl('/contacts/export'), crmUrl('/contacts/00000000-0000-4000-8000-000000000000/timeline')]) {
      const res = await inj('GET', u, session.headers);""",
     """    // S1e-a (W4) opened contact detail and the contact timeline for the bound door only (see user-token-contact-timeline-default.test.ts).
    for (const u of [crmUrl('/contacts/export'), crmUrl('/contacts/00000000-0000-4000-8000-000000000000/meetings')]) {
      const res = await inj('GET', u, session.headers);"""),
    ("""        if (WAIVED.test(r.url)) continue;""",
     """        if (WAIVED.test(r.url)) continue;
        // W4 (goodqa#15561 S1e-a): the one deliberate exception pair, named by exact key and pinned in user-token-contact-timeline-default.test.ts.
        if (r.method === 'GET' && W4_PAIR.includes(r.url)) continue;"""),
])
patch('user-token-desktop-session-delegation.test.ts', [
    ("  const WAIVED = /", "  const W4_PAIR = ['/v1/orgs/:org/crm/contacts/00000000-0000-4000-8000-000000000000', '/v1/orgs/:org/crm/contacts/00000000-0000-4000-8000-000000000000/timeline'];\n  const WAIVED = /"),
])
patch('user-token-desktop-surface-inventory.test.ts', [
    ("import { DESKTOP_DELEGATED_SURFACES, HOST_APPROVAL_WAIVED_ROUTES,", "import { DESKTOP_DELEGATED_SURFACES, DESKTOP_SESSION_ONLY_OPENED, HOST_APPROVAL_WAIVED_ROUTES,"),
    ("      expect(p.signedInPersonOnly, entry.route).toBe(false);", "      // W4 (goodqa#15561 S1e-a): exactly the named pair is session-only for bearer and opened for the bound door only.\n      if (!DESKTOP_SESSION_ONLY_OPENED.has(entry.route)) expect(p.signedInPersonOnly, entry.route).toBe(false);"),
])
print('ok')
