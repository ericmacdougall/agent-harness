p = '../spec-15561-v4.md'
s = open(p).read()
lines = s.split('\n')
SRC = 'answer:baab765b-d85c-46b4-b7b9-588eb912c770/c75dac6b-ba47-4287-a1c2-f448c1ad3a4d "Open it now"'


def find(prefix):
    idx = [i for i, l in enumerate(lines) if l.startswith(prefix)]
    assert len(idx) == 1, (prefix, idx)
    return idx[0]


def sub(prefix, old, new):
    i = find(prefix)
    assert lines[i].count(old) == 1, (prefix, old[:70], lines[i].count(old))
    lines[i] = lines[i].replace(old, new)


# stale statements: true only on the #1319 build
sub('- S0 Q7 finding', 'as slice S1e (AC-14).', 'as slice S1e (AC-14, AC-15, AC-16); on the #1319 build only they stay refused.')
lines[find('- NEG-25')] += ' On the #1319 build this includes contact detail and timeline; after S1e only export, import, meetings, files, call, SMS, AI briefing and suggestions, issue-links and timeline writes keep this copy.'
lines[find('D10.')] += ' After S1e (AC-14, AC-15) contact detail and timeline no longer show the not-available copy.'
sub('- AC-12', 'while clicking a person shows the honest "not available in a desktop session started from a token" copy (Q7)', 'while, ON THE #1319 BUILD ONLY, clicking a person shows the honest "not available in a desktop session started from a token" copy (Q7; the S1e live proof is AC-16)')

# AC-14 narrowed to contact detail, timeline in AC-15 (the existing session-action control, adversarial B1)
i = find('- AC-14')
lines[i] = ("- AC-14: (slice S1e, after #1319) `GET /v1/orgs/:orgId/crm/contacts/:contactId` (contact detail) is reachable by a user token holding `crm` + `read` (by bearer, and through a bound desktop session on the delegated door), and by no org API key; the owner's `crm:read` RBAC, the org of the contact and the token's org list all still apply, each request is ledgered, and the handler's rule that hides other members' `personal` timeline entries still holds. "
            "Verify by: new `apps/api/test/user-token-contact-detail.test.ts`, red first on #1319's head (the route answers `user_token_non_delegable`), covering NEG-31..NEG-35 and NEG-37; an independent security red-team before any deploy. Source: " + SRC)
lines.insert(i + 1, "- AC-15: (slice S1e) `GET /v1/orgs/:orgId/crm/contacts/:contactId/timeline` is ALREADY a session action: it needs the explicit human-granted token ability `session:crm_timeline`, the platform switch `userTokens.sessionActions` (default OFF) and the org owner's opt-in (`session-actions.ts`), and the gate refuses every session action to a bound session. S1e KEEPS that control (recommended; the user's answer did not say the org owner's opt-in goes away): by bearer the answer is exactly as today, and a bound desktop session reaches the timeline only when its token holds the grant and the switch and the org opt-in are on, which needs one deliberate change to the bound door's session-action refusal for this one route. Whether to REMOVE the org owner's opt-in so that `crm` + `read` alone opens the timeline is a separate choice for the user (ask registered; until answered the opt-in stays). Verify by: the same test file, the NEG-36 matrix; independent security red-team before any deploy. Source: " + SRC)
lines.insert(i + 2, "- AC-16: (slice S1e live proof) on the deployed S1e build the desktop opens contact detail (and the timeline where AC-15 allows it) for a `crm` + `read` token, and shows the refusal for a token without `crm`, recorded by an independent click-tester with real-pixel screenshots. Verify by: `spec_flow.py click-test`. Source: " + SRC)
j = find('- NEG-35')
lines[j + 1:j + 1] = [
    "- NEG-36 (AC-15): the timeline route answers by the existing control, pinned for every combination: `userTokens.sessionActions` off (refused `user_token_non_delegable` rule `session_actions_disabled`, as today); on but the org has not opted in (refused `session_actions_disabled`); on and opted in but the token lacks `session:crm_timeline` (`user_token_ability_missing`); all three present (allowed, ledgered), by bearer, and through a bound session only with all three. Turning the switch on never widens access and never narrows it below what it was. Source: " + SRC,
    "- NEG-37 (AC-14): a token or session acting for member X never receives member Y's `personal` timeline entries on the detail or the timeline route, and gets 404, not 403, for one requested by id; an agent holding the token reads the owner's own personal entries, and the token page and refusal copy say so. Source: " + SRC,
]
sub('- NEG-35', 'the opening is exactly these two routes and exactly user tokens', 'the opening is exactly contact detail (AC-14) and the existing timeline control (AC-15), and exactly user tokens')
sub('- NEG-35', 'the route-inventory snapshot changes by exactly these two entries', 'the route-inventory snapshot changes by exactly these entries')
sub('- NEG-33', 'on both routes', 'on both routes (the timeline subject to AC-15)')
i = find('- S1e')
lines[i] = lines[i].replace("move exactly the two GET routes from session-only into `USER_TOKEN_BEYOND_API_KEY_ROUTES` (user tokens only, not org API keys), add them to `DESKTOP_DELEGATED_SURFACES` with `crm` + `read`;",
                            "move contact detail from session-only into `USER_TOKEN_BEYOND_API_KEY_ROUTES` (user tokens only, not org API keys) and add it to `DESKTOP_DELEGATED_SURFACES` with `crm` + `read`; keep the timeline behind its existing session-action control (AC-15) and let a bound session use it only with the grant, the switch and the org opt-in;")
assert 'keep the timeline behind' in lines[i]
s = '\n'.join(lines)
s = s.replace("Q7 is DECIDED BY THE USER", "Q7 is DECIDED BY THE USER")
open(p, 'w').write(s)
print('ok')
