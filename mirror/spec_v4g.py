import re
p = '../spec-15561-v4.md'
s = open(p).read()
lines = s.split('\n')


def find(prefix):
    idx = [i for i, l in enumerate(lines) if l.startswith(prefix)]
    assert len(idx) == 1, (prefix, idx)
    return idx[0]


def sub(prefix, old, new):
    i = find(prefix)
    assert lines[i].count(old) == 1, (prefix, old[:60], lines[i].count(old))
    lines[i] = lines[i].replace(old, new)


# adversarial B1: the detail response embeds the timeline; (a) omit it unless the AC-15 conditions hold
sub('- AC-14', 'the handler\'s rule that hides other members\' `personal` timeline entries still holds.',
    "the handler's rule that hides other members' `personal` timeline entries still holds. The detail response also embeds the 50 most recent timeline entries, `timelineNextCursor`, `openFollowUpCount` and `reportedIssues`: for a token or a bound session the embedded `timeline` and `timelineNextCursor` are EMPTY (with a flag saying why) unless the AC-15 conditions hold, so contact detail never serves the timeline around the control; `openFollowUpCount` and `reportedIssues` are disclosed by detail and are named here as part of what `crm` + `read` now opens. Gmail mailbox-read entries stay withheld from every token and bound session (`isAgentCredential`), so the desktop's human user does not see them either; AC-16 and the copy say so.")
sub('- AC-16', 'Verify by:', 'The click-tester does not report the withheld Gmail mailbox entries as a bug. Verify by:')
# NEG-36 pinned codes
sub('- NEG-36', '`userTokens.sessionActions` off (refused `user_token_non_delegable` rule `session_actions_disabled`, as today); on but the org has not opted in (refused `session_actions_disabled`);',
    '`userTokens.sessionActions` off (refused `user_token_non_delegable`, rule `signed_in_person`, as today: the platform switch off leaves the route session-only); on but the org has not opted in (refused `user_token_non_delegable`, rule `session_actions_disabled`);')
# new NEG for the embedded timeline
j = find('- NEG-37')
lines.insert(j + 1, "- NEG-38 (AC-14): contact detail through a token or a bound session without the AC-15 conditions returns no timeline entries and no `timelineNextCursor` (empty plus the flag); with all three conditions it returns them; detail never serves a Gmail mailbox-read entry to a token or session. Source: " + 'answer:baab765b-d85c-46b4-b7b9-588eb912c770/c75dac6b-ba47-4287-a1c2-f448c1ad3a4d "Open it now"')
# NEG-31..33 wording: both routes
for pre in ('- NEG-31', '- NEG-32'):
    lines[find(pre)] = lines[find(pre)].replace('on both routes', 'on the detail route and, subject to AC-15, the timeline route')
sub('- NEG-31', 'a token holding `read` but not `crm` is `user_token_ability_missing` (`missing: [\'crm\']`) on both routes', "a token holding `read` but not `crm` is `user_token_ability_missing` (`missing: ['crm']`) on the detail route and, subject to AC-15, the timeline route") if "on both routes" in lines[find('- NEG-31')] else None
# Q7 body and refs
i = find('- Q7')
lines[i] = lines[i].replace('Slice S1e, AC-14, NEG-31..NEG-35.', 'Slice S1e: AC-14, AC-15, AC-16, NEG-31..NEG-38. The timeline stays behind its existing control (AC-15) unless the user also removes the org owner opt-in (separate registered ask, default keep).')
assert 'AC-16, NEG-31..NEG-38' in lines[i]
# D4 and the S0 finding: until S1e
i = find('D4.')
lines[i] = lines[i].replace('Q7 asks whether promoting any of them is in v1.', 'Q7 was decided by the user (open them as slice S1e, AC-14..AC-16); on the #1319 build they stay refused.')
assert 'decided by the user' in lines[i]
i = find('- S0 Q7 finding')
lines[i] = lines[i].replace('are `SESSION_ONLY_ROUTES` for every credential', 'are `SESSION_ONLY_ROUTES` for every credential (on the #1319 build they stay refused until S1e)')
assert 'until S1e' in lines[i]
s = '\n'.join(lines)
# Reviews section: no verdict wording
a = s.index('## Reviews')
s = s[:a] + """## Reviews

Reviews of THIS text are recorded in the ticket by `spec_flow.py review` against the core sha computed there; nothing in this section states a verdict.
"""
open(p, 'w').write(s)
print('ok')
