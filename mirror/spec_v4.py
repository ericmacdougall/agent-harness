import re
p = '../spec-15561-v4.md'
s = open(p).read()
lines = s.split('\n')

# 1. nit: AC-12 and the Outcome count is the view's current count, not a fixed number
n = 0
for i, l in enumerate(lines):
    if '1,415' in l:
        l = l.replace('(saved view 757da781, 1,415 people)', "(saved view 757da781, showing the view's current count, 1,415 at 2026-11-09)")
        l = l.replace('shows saved view 757da781 with 1,415 people in the real app window', "shows saved view 757da781 with the saved view's current count (1,415 at 2026-11-09) in the real app window")
        l = l.replace('can render 1,415 people while', "can render the saved view's current count (1,415 at 2026-11-09) while")
        lines[i] = l
        n += 1
assert n == 3 and not any('1,415 people' in l for l in lines), n

# 2. nit: NEG ordering (NEG-28 after NEG-27, before NEG-29)
neg = [i for i, l in enumerate(lines) if l.startswith('- NEG-')]
block = [lines[i] for i in neg]
assert neg == list(range(neg[0], neg[-1] + 1))
block.sort(key=lambda l: int(re.match(r'- NEG-(\d+)', l).group(1)))
lines[neg[0]:neg[-1] + 1] = block

# 3. nit: Q ordering, the Q6 condition folded into Q6
q = [i for i, l in enumerate(lines) if re.match(r'- Q\d', l) or l.startswith('- Q6 is conditional')]
qblock = [lines[i] for i in q]
cond = [l for l in qblock if l.startswith('- Q6 is conditional')]
qs = [l for l in qblock if not l.startswith('- Q6 is conditional')]
qs.sort(key=lambda l: int(re.match(r'- Q(\d+)', l).group(1)))
qs = [l + ' Conditional on NEG-29 (token facts carried into enrollment): without it W3 is not accepted.' if l.startswith('- Q6 ') else l for l in qs]
assert q == list(range(q[0], q[-1] + 1)) and len(cond) == 1
lines[q[0]:q[-1] + 1] = qs

s = '\n'.join(lines)

# 4. nit: S1b names NEG-21 and the API half of NEG-25
old = "NEG-1..NEG-5, NEG-9..NEG-12, NEG-16, NEG-18, NEG-19, NEG-24"
assert old in s
s = s.replace(old, "NEG-1..NEG-5, NEG-9..NEG-12, NEG-16, NEG-18, NEG-19, NEG-21, NEG-24, the API half of NEG-25 (the session-only CRM routes answer `user_token_non_delegable`; the UI half is S4)")

# 5. record main's binding decisions and the corrections found while building (header block after Outcome)
decisions = """
## Decisions recorded at build start (main, binding) and corrections found in S0

Source: ticket:GoodQA goodqa#15561 (main's decisions to the owner, session baab765b)

- Q1 yes: delegate CRM (not outreach) and Messages. Q2 yes: D6 (drop `machines`, `write`, `tokens.create_other_keys` from the sign-in requirement). Q3 yes: `write` is not split; documented in the copy. Q4 accepted: approval-required writes show an honest "approve this on the web" message. Q5 keep. Q6 yes, conditional on NEG-29 shipping in the SAME release. Q7 partly: EXPORT stays refused to every token in v1; contact detail and timeline follow the S0 finding (below). Q8: wording is the owner's call but the copy must say plainly that the `crm` ability also covers outreach; Messages v1 = read routes, plus send only with `write`. Q9 accepted: the S0 check below.
- S0 correction to F6(a): `crm.api.enabled` is DEFAULT ON for every plan since batch4 (`entitlements.ts`, the FULL_ACCESS spread; Eric 2026-10-03); only an explicit org override of `false` turns it off. The live value for the org behind saved view 757da781 is production data and not determinable from code: AC-12's click-test records it (or the org's overrides are read by an operator).
- S0 Q7 finding: contact detail `GET .../crm/contacts/:id` and timeline `GET .../crm/contacts/:id/timeline` are `SESSION_ONLY_ROUTES` for every credential ("authenticated human workflow with no API-key consumer"). A bound session cannot reach a route its token cannot reach by bearer (AC-6), so promoting them for the desktop would promote them for EVERY `crm` token and agent: a PII and mail-content class beyond this ticket. They stay refused with the honest "not available in a desktop session started from a token" message; detail + timeline are the very next slice (a per-route policy change with its own review). Direction: HOLD, not IN v1.
- S0 Q9 finding: `POST /v1/me/desktop-session` (what `ctl sign-in --key-file` calls) has no `created_via` check; it admits any bearer token holding `desktop_signin`. `oauth` and `pairing` tokens are minted only through `assertOAuthGrant` whose ability set cannot hold `desktop_signin`; `operator` is not produced by any code path (operator tokens are written as `session`); `commander_turn` cannot hold it either. The user-token page and a token-minted child produce `session` and `user_token`. So the mini's token is `session` or `user_token`; the bound door allows exactly those two, refusing `oauth`, `commander_turn`, `operator`, `pairing` (nothing that can start a session today is refused).
- S0 `GET /v1/orgs` honors the token's org list (`userTokenAllowsOrg`, `orgs/routes.ts:402`); `GET /v1/me`, machines lists and notifications are S1d's check.
- D6 is pulled into S1b (a token cannot be narrowed below the five abilities in any test otherwise); S2's remaining part is the web/preset and policy pins.
"""
marker = '\n## Findings (where the refusal comes from)'
assert marker in s
s = s.replace(marker, decisions + marker, 1)
open(p, 'w').write(s)
print('ok')
