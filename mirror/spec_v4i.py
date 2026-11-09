import re
p = '../spec-15561-v4.md'
s = open(p).read()
lines = s.split('\n')
TK = 'ticket:GoodQA goodqa#15561'
MAIN_DEC = 'ticket:GoodQA goodqa#15561 comment 59a46886-1b3e-4771-8ea9-a3bd355788e5'
failed = []


def find(prefix):
    idx = [i for i, l in enumerate(lines) if l.startswith(prefix)]
    if len(idx) != 1:
        raise KeyError((prefix, idx))
    return idx[0]


def sub(prefix, old, new):
    try:
        i = find(prefix)
        assert lines[i].count(old) == 1, lines[i].count(old)
        lines[i] = lines[i].replace(old, new)
    except Exception as e:  # report and continue
        failed.append((prefix, old[:60], str(e)))


def before_source(prefix, text):
    try:
        i = find(prefix)
        k = lines[i].rindex(' Source: ')
        lines[i] = lines[i][:k] + ' ' + text + lines[i][k:]
    except Exception as e:
        failed.append((prefix, 'before_source', str(e)))


def setsource(prefix, src):
    try:
        i = find(prefix)
        k = lines[i].rindex(' Source: ')
        lines[i] = lines[i][:k] + ' Source: ' + src
    except Exception as e:
        failed.append((prefix, 'setsource', str(e)))


# B1: AC-12 scoped to what #1319 contains; refusal copy and Messages move to their own ACs
i = find('- AC-12')
lines[i] = ("- AC-12: Live proof for the build that ships S1b (#1319): on the mini, a desktop session started from a user-minted CRM-view token shows saved view 757da781 with the saved view's current count (1,415 at 2026-11-09) in the real app window (real-pixel screenshot), equal to the count the owner's signed-in web session shows for the same view at the same time (both screenshots in the evidence), and the click-test records the org's `crm.api.enabled` value (read by an operator from the org's entitlement overrides, not from the UI). "
            "An independent click-tester (not the author or a spec reviewer) records it on the deployed build under the 'Live-proof prerequisites' below. Verify by: `spec_flow.py click-test`; real window screenshot; no production password typed by an agent. Source: " + TK)
j = find('- AC-16')
lines.insert(j + 1, "- AC-17: Live proof after S4 ships: a token without `crm` shows the new token-specific refusal (names the missing ability and the page to fix it), and clicking a person on a build before S1e shows the honest \"not available in a desktop session started from a token\" copy, never the role copy. Verify by: `spec_flow.py click-test` by an independent click-tester on the build that contains S4. Source: " + TK)
lines.insert(j + 2, "- AC-18: Live proof after S1c ships: the Messages page loads the sidebar and one conversation, and sends and reads a message with a `read`+`write` token; each Messages route outside the v1 table is listed in or out in the S0 inventory. Verify by: `spec_flow.py click-test` by an independent click-tester on the build that contains S1c. Source: " + TK)

# B2: live-proof prerequisites
a = '## Resource budget'
assert a in '\n'.join(lines)
txt = '\n'.join(lines)
txt = txt.replace(a, """## Live-proof prerequisites (AC-12, AC-16, AC-17, AC-18)

- Tokens are minted by the signed-in human owner on /account/user-tokens with a fresh step-up (no agent mints, no token can mint: rule `token_mint`); an agent never types a production password. Authentication of the click-tester to an owner account goes through the approve-link or device path of the hard rules, or a disposable staging org the tester owns. Any human step is registered as an ask.
- The click-test runs first on STAGING with disposable accounts and orgs, through the GoodQA agent browser; the production live proof reuses an existing token the owner supplies.
- `crm.api.enabled` for the org behind view 757da781 is read by an operator from the org's entitlement overrides (an admin read), because the UI cannot show it.
- AC-16 with the platform switch `userTokens.sessionActions` OFF (its default) expects the honest refusal on the timeline (`signed_in_person`) and a working contact detail with an empty embedded timeline; flipping the switch on staging for the timeline case is allowed, flipping it in production needs main.

""" + a, 1)
lines = txt.split('\n')

# B3: D2, D5, AC-6 amended by S1e for exactly one route
sub('D2.', "asserted unreachable for `via='desktop_session'`)", "asserted unreachable for `via='desktop_session'`; slice S1e amends the session-action assertion for exactly `GET /v1/orgs/:p/crm/contacts/:p/timeline` (AC-15) and nothing else)")
sub('D5.', 'session-action grants) stays refused to a bound session', 'session-action grants) stays refused to a bound session (S1e, AC-15, lets the contact timeline through only with its grant, the platform switch and the org opt-in)')
before_source('- AC-6', 'Until S1e, no delegated route is a session action; S1e (AC-15) amends that for exactly the contact timeline route.')
sub('- AC-6', '; no host or delegated route has a handler that requires a session-only proof (step-up, recent auth)', '')

# B4: sources for what main decided or the owner derived
for pre in ('- AC-15', '- NEG-36', '- NEG-37', '- NEG-38'):
    setsource(pre, MAIN_DEC)
sub('Source: ticket:GoodQA goodqa#15561 (main', 'Q7 is DECIDED BY THE USER', 'Q7 is DECIDED BY THE USER for contact detail and the timeline in principle; the timeline stays behind its existing control by main\'s decision (comment 59a46886-1b3e-4771-8ea9-a3bd355788e5, the recommended option) and the user has not been asked to remove it; Q7 is DECIDED BY THE USER')
sub('Source: ticket:GoodQA goodqa#15561 (main', 'specified below (AC-14, NEG-31..NEG-35)', 'specified below (AC-14..AC-16, NEG-31..NEG-38)')
sub('Source: ticket:GoodQA goodqa#15561 (main', 'The S1b/S1c split (CRM list first, Messages after) remains pending the owner\'s confirmation.', 'S1b is built (#1319); Messages is slice S1c, next.')
sub('- Q1 yes:', 'contact detail and timeline follow the S0 finding', 'contact detail and timeline: superseded by the user\'s later answer (see the Q7 line below)')
sub('- Q1 yes:', 'Q8: wording is your call', 'Q8: wording is the owner\'s draft, main approves the exact strings before S5')
sub('- S0 Q9 finding', 'DEVIATION FROM THE Q9 DEFAULT, for main to confirm:', 'DEVIATION FROM THE Q9 DEFAULT, decided by main (decision w212679a04a0, admit operator):')
sub('- Q9', 'Main confirms or flips it after reading the mini\'s token kind.', 'Decided by main (w212679a04a0): admit operator, with no host waivers for it (NEG-39). Consequence: if the live desktop is bound to an operator token, its machine and remote-session routes need a re-sign-in with a non-operator token after deploy.')
sub('D11.', 'need main\'s wording approval (Q8)', 'need main\'s wording approval (Q8, main approves before S5)')
sub('D10.', 'Desktop CRM preset', 'Desktop app: view CRM preset')

# M1: NEG-39
j = find('- NEG-38')
lines.insert(j + 1, "- NEG-39 (AC-6): a session bound to an operator-kind token is refused the W1-W3 routes exactly as the same token by bearer: the catalog, remote-sessions, org machines and machine enrollment answer the same through the session and by bearer (no host waiver for operator); the base reads and the delegated CRM door still work. Source: " + TK)

# M2: polling gaps
sub('- NEG-12', 'follows the same observation policy as the bearer path', 'on the listed zero-write observation routes (ZERO_WRITE_READ_ROUTES) follows the same observation policy as the bearer path; a desktop poll is governed only by the throttle rule of D9')
sub('- AC-8', 'Verify by:', 'Poll cases pinned in the delegation test: first poll written, repeat inside the window quiet, new user agent written, non-2xx written, refused poll written. The "already wrote" state is a per-process map (a multi-instance deployment writes more rows, never fewer); the volume figures are an estimate from the desktop and web-shell timer constants (60 s polls), not live traffic. Verify by:')
sub('D9.', 'a REFUSED poll is always written;', 'a REFUSED poll is always written; the per-token rate check runs before a route-class refusal is ledgered, so a looping session meets 429 instead of unbounded refused rows;')

# M3: sequencing statement
j = find('- S1b')
lines[j] += ' #1319 claims only the doors, D6, W1-W3 and their tests: NEG-8 (route sample) and the W2 pin (NEG-30) are built in S1b; the org-boundary ACs (AC-5, NEG-4, NEG-7) are S1d and the full route-inventory ACs (AC-6 snapshot, NEG-22) are S3, so #1319 does not claim them and an org-scoped narrowing of the host lists is S1d.'

# M4
sub('- AC-1:', 'Verify by:', 'The route set is the constant CRM_LIST_PAGE_SET of the test (contacts, companies, segments, one segment, its preview, records, entitlements, members: the eight reads the page hooks call), and the inventory test asserts each of those is a `delegated` entry. Verify by:')
sub('- AC-3', 'Verify by:', 'A token without `read` or `write` cannot start a session (AC-9), so the missing-ability cases are made by a PATCH after the session starts. Verify by:')
sub('- AC-11', 'Verify by:', 'The web vitest config has no DOM, so the dialog interaction is tested through the exported pure preset model plus static markup of the dialog, and the live click-test covers the real interaction. Verify by:')
sub('- NEG-4', 'refused by the handler', 'refused by the handler; on the delegated door a non-member or non-existent org answers the same 404 `not_found` as bearer (never `crm_api_disabled`)')

# L1 resource budget host
sub('Host:', 'dev2 (the t2-dev host, T2 after Nov 9)', 't2-dev (the T2 host)')

open(p, 'w').write('\n'.join(lines))
print('failed:', failed)
