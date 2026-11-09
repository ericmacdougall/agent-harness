import re
p = '../spec-15561-v4.md'
s = open(p).read()
lines = s.split('\n')


def find(prefix):
    idx = [i for i, l in enumerate(lines) if l.startswith(prefix)]
    assert len(idx) == 1, (prefix, idx)
    return idx[0]


SRC = "answer:baab765b-d85c-46b4-b7b9-588eb912c770/c75dac6b-ba47-4287-a1c2-f448c1ad3a4d (the user chose \"Open it now\"; requirement w5a0692ecf0a)"

# provenance line: Q7 is now decided by the user
i = find('Source: ticket:GoodQA goodqa#15561 (main')
lines[i] = re.sub(r"PENDING OWNER CONFIRMATION, registered as ask wa0befe0e2d1 with a recommended option: Q7 \(hold contact detail and timeline\) and the S1b/S1c split \(CRM list first, Messages after\)\. Nothing below treats those two as decided by the user\.",
                  "Q7 is DECIDED BY THE USER, Source: " + SRC + ": contact detail and timeline become reachable from token-started desktop sessions, and by crm-ability tokens and agents. #1319 (S0, S1a, S1b) still ships them refused; they are the next slice S1e, specified below (AC-14, NEG-31..NEG-35), after #1319 merges or as a stacked PR. The S1b/S1c split (CRM list first, Messages after) remains pending the owner's confirmation.", lines[i])
assert 'DECIDED BY THE USER' in lines[i]
i = find('- S0 Q7 finding')
lines[i] = lines[i].replace("Direction: HOLD, not IN v1 (recommended; PENDING the user, ask wa0befe0e2d1: HOLD keeps a person clickable only after a separate per-route review; the alternative gives every `crm` token and agent the full contact PII and mail timeline).",
                            "Finding: holding them was the recommendation; the USER DECIDED the other way (Source: " + SRC + "): they open to every `crm` token and agent, as slice S1e (AC-14). Until S1e ships, #1319 answers them `user_token_non_delegable` with the honest copy.")
assert 'USER DECIDED' in lines[i]
i = find('- Q7')
lines[i] = ("- Q7 (DECIDED BY THE USER, Source: " + SRC + "): contact detail and timeline become reachable from token-started desktop sessions, and by `crm`-ability user tokens and agents (not by org API keys). Export stays refused to every token (main). "
            "Meetings, call, SMS, AI briefing and suggestions, import, files, issue-links and timeline writes stay refused (not asked). Slice S1e, AC-14, NEG-31..NEG-35.")
# AC-14 after AC-13, NEGs after NEG-30
i = find('- AC-13')
lines.insert(i + 1, "- AC-14 (slice S1e, after #1319): `GET /v1/orgs/:orgId/crm/contacts/:contactId` and `GET /v1/orgs/:orgId/crm/contacts/:contactId/timeline` are reachable by a user token holding `crm` + `read` (by bearer, and through a bound desktop session on the delegated door), and by no org API key and no other credential change; the owner's `crm:read` RBAC, the org of the contact and the token's org list all still apply, and each request is ledgered. Verify by: new `apps/api/test/user-token-contact-detail.test.ts`, red first on #1319's head (both routes answer `user_token_non_delegable`), covering AC-14's NEG-31..NEG-35; an independent security red-team before any deploy. Source: " + SRC)
i = find('- NEG-30')
lines[i + 1:i + 1] = [
    "- NEG-31 (AC-14): deny without `crm`: a token holding `read` but not `crm` is `user_token_ability_missing` (`missing: ['crm']`) on both routes, by bearer and through a session. Source: " + SRC,
    "- NEG-32 (AC-14): a token whose org list excludes the contact's org gets 404 `not_found` on both routes (tenancy-hiding), and the org lists never name it. Source: " + SRC,
    "- NEG-33 (AC-14): per-request ledgering: every allowed or refused request on both routes writes a token ledger row (`request` or `refused`) carrying the token id and, for a session, `via: desktop_session`; no row holds the contact payload, a body or a token value; these two routes are NOT on `DESKTOP_POLL_ROUTES`. Source: " + SRC,
    "- NEG-34 (AC-14): no cross-org leakage: a contact id of org B requested under org A's route is 404 even for a token that reaches both orgs; a token reaching all orgs cannot read a contact in an org its owner is not a member of; an owner without `crm:read` in the org is refused by the handler even with `crm` + `read`. Source: " + SRC,
    "- NEG-35 (AC-14): the opening is exactly these two routes and exactly user tokens: an org API key with every scope is still refused both routes; contact export, meetings, files, call, SMS, AI briefing and suggestions, issue-links, timeline writes and import stay `user_token_non_delegable` for tokens and sessions; the route-inventory snapshot changes by exactly these two entries, and the bearer parity test is re-pinned deliberately. Source: " + SRC,
]
# slice plan
i = find('- S5')
lines.insert(i + 1, "- S1e (API, contact detail and timeline, AFTER #1319 merges or as a stacked PR, user decision Q7): move exactly the two GET routes from session-only into `USER_TOKEN_BEYOND_API_KEY_ROUTES` (user tokens only, not org API keys), add them to `DESKTOP_DELEGATED_SURFACES` with `crm` + `read`; `user-token-contact-detail.test.ts` written first and red; independent security red-team before any deploy; the web copy for these two routes (S4) drops the honest not-available message once S1e ships.")
s = '\n'.join(lines)
# reviews table: no stale verdicts
a = s.index('## Reviews')
s = s[:a] + """## Reviews

Reviews of THIS text are recorded in the ticket by `spec_flow.py review` (the core sha is computed there). Earlier ACCEPT rows for v3 are superseded by the delta reviews of v4 (adversarial agent a0e0378fdb6d0d338 and acceptance agent a21164a6600b681bf, both ACCEPT after one revision).
"""
open(p, 'w').write(s)
print('ok')
