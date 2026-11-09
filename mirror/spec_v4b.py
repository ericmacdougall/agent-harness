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


def setline(prefix, text):
    lines[find(prefix)] = text


# provenance and pending choices (review B1 and provenance finding)
sub('Source: ticket:GoodQA goodqa#15561 (main', "(main's decisions to the owner, session baab765b)",
    "(main's decisions as relayed to the owner by the coordinator; these are not the user's own words, and every decision is open to the user's override). PENDING OWNER CONFIRMATION, registered as ask wa0befe0e2d1 with a recommended option: Q7 (hold contact detail and timeline) and the S1b/S1c split (CRM list first, Messages after). Nothing below treats those two as decided by the user.")
sub('- S0 Q7 finding', 'Direction: HOLD, not IN v1.', 'Direction: HOLD, not IN v1 (recommended; PENDING the user, ask wa0befe0e2d1: HOLD keeps a person clickable only after a separate per-route review; the alternative gives every `crm` token and agent the full contact PII and mail timeline).')
# F1 of the adversarial delta review: the Q9 claim was wrong
i = find('- S0 Q9 finding')
lines[i] = ("- S0 Q9 finding (corrected): `POST /v1/me/desktop-session` (what `ctl sign-in --key-file` calls) has no `created_via` check; it admits any bearer token holding `desktop_signin`. "
            "`oauth` and `pairing` tokens are minted only through `assertOAuthGrant`, whose ability set cannot hold `desktop_signin`; `commander_turn` cannot hold it either. "
            "`operator` tokens ARE produced: `apps/api/scripts/operator-mint-user-token.ts` mints the orchestrator token with every ability, so it holds `desktop_signin`. "
            "The mini's token kind cannot be read from code (it is production data: `select created_via from user_tokens where id = <bound id>` is non-secret metadata for an operator to read). "
            "DEVIATION FROM THE Q9 DEFAULT, for main to confirm: the bound door admits `session`, `user_token` and `operator` and refuses `oauth`, `commander_turn`, `pairing`. "
            "Reason: refusing `operator` could end the live desktop's session on deploy, and a session bound to an operator token can do nothing the token cannot do by bearer; the kind list is defense in depth, the token gate is the boundary "
            "(a legacy child minted by a parent token is `user_token` whatever its root, while `userTokens.sessionActions` is off). Flipping it is one word in `BOUND_ALLOWED_CREATED_VIA`.")
sub('- D6 is pulled into S1b', "S2's remaining part is the web/preset and policy pins.",
    "S1b now owns D6 end to end: `desktopBindingState`, the `POST /v1/me/desktop-session` policy line, AC-9 and NEG-13. S2 is therefore closed; the presets and copy are S5.")
# F6(a)
sub('F6.', "(default off; `plugins/auth.ts` around 1034 and the token switch near 6235 answer 404); once the session goes through the token gate it inherits that switch, so the live org behind saved view 757da781 must have it on (S0 records the evidence, otherwise the desktop CRM answers 404)",
    "(DEFAULT ON for every plan since batch4, off only by an explicit org override of `false`; `plugins/auth.ts` around 1034 and the token switch near 6235 answer 404); once the session goes through the token gate it inherits that switch, so the live org behind saved view 757da781 must not carry a `false` override (the click-test records the value; the delegated door answers `crm_api_disabled`)")
# D3 route class text (F4)
sub('D3.', "or refuse `403 desktop_token_session_scope`.", "or refuse. A route on neither door is `403 desktop_token_session_scope`, except on a surface the app has pages for (CRM): a route NO credential can reach (session-only, non-delegable, governance sign-off) answers the policy's own `user_token_non_delegable`, so the app can say \"not available in a desktop session started from a token\" (NEG-25; this is deliberate and must not be \"fixed\" back).")
# D6 gating
sub('D6.', 'Host-door abilities (gated on Q2).', 'Host-door abilities (Q2 answered yes by main).')
sub('D6.', 'If Q2 is answered "keep all five"', 'Had Q2 been answered "keep all five"')
sub('D11.', '(D11a is gated on Q2)', '(Q2 is answered yes)')
# D9 polling
sub('D9.', "writes the ledger row the bearer path writes", "writes the ledger row the bearer path writes (exception, ledger-load measurement: an ALLOWED polling read of the app, `DESKTOP_POLL_ROUTES` in `lib/desktop-token-session.ts`, takes the zero-write observation policy; a REFUSED poll is still written; the chat unread polls join the list when Messages is delegated)")
sub('- AC-8', 'Every delegated request writes', 'Every delegated or host request writes')
sub('- AC-8', 'Verify by:', 'Exception: an allowed read on `DESKTOP_POLL_ROUTES` writes no row and no last-use update (measured: about 8 to 10 polls a minute per open desktop, about 16 to 20 writes a minute, 12k rows a day per desktop, before the exception). Verify by:')
sub('- NEG-12', 'no ledger row is skipped on a refusal', 'no ledger row is skipped on a refusal (a refused desktop poll is written; only an ALLOWED poll on `DESKTOP_POLL_ROUTES` is quiet)')
# AC-9 / gating
i = find('- AC-9')
lines[i] = lines[i].replace('(applies only if Q2 is answered yes; otherwise AC-9 becomes "mint requirement unchanged, presets tick all five") ', '(Q2 answered yes by main; implemented in S1b) ')
sub('- NEG-13', 'cannot start a session;', 'cannot start a session (403 `user_token_ability_missing`, code pinned in the test);')
# AC-1 carries the API half of NEG-25
sub('- AC-1:', 'Verify by:', 'The API half of NEG-25 is verified here too (the session-only CRM routes answer `user_token_non_delegable`). Verify by:')
# NEG-19 kinds
sub('- NEG-19', 'an `oauth` or `commander_turn` token can never be the bound token.', 'an `oauth`, `commander_turn` or `pairing` token can never be the bound token (401 and the session row revoked `user_token_ended`, asserted); `operator` is admitted (Q9 deviation above) and asserted to work.')
# AC-12
sub('- AC-12', "in the real app window (real-pixel screenshot)", "in the real app window (real-pixel screenshot), equal to the count the owner's signed-in web session shows for the same view at the same time (both screenshots in the evidence), and the click-test records the org's `crm.api.enabled` value")
# Q bodies
i = find('- Q2')
lines[i] = re.sub(r'^- Q2 \(main, GATES S2 and D11a; answer at spec sign-off, not mid-build\)', '- Q2 (ANSWERED YES by main; D6 is built in S1b)', lines[i])
sub('- Q6', 'Conditional on NEG-29', 'To ship in the SAME release as NEG-29. Conditional on NEG-29')
i = find('- Q7')
lines[i] = ("- Q7 (PENDING THE USER, ask wa0befe0e2d1): contact detail, timeline, export and other CRM routes that are session-only for every token. Export stays refused to every token in v1 (main). "
            "Recommended for v1 (HOLD): list, saved views and record reads work; clicking a person shows the honest \"not available in a desktop session started from a token\" copy; detail and timeline are the very next slice with their own review. "
            "Tradeoff: opening them in the desktop opens them to every `crm`-ability token and agent (a desktop session cannot reach what its token cannot reach by bearer), a PII and mail-content class beyond this ticket. Promoting any such route is a per-route decision with its own security review.")
i = find('- Q9')
lines[i] = ("- Q9 (main accepted the check; deviation open): the bound door admits `session`, `user_token` and `operator` and refuses `oauth`, `commander_turn`, `pairing` (see the S0 Q9 finding: `operator` is admitted because refusing it could end the live desktop's session). Main confirms or flips it after reading the mini's token kind.")
# slice plan
i = find('- S1b')
lines[i] = lines[i] + ' It also carries D6 end to end (`desktopBindingState`, the `POST /v1/me/desktop-session` policy line, AC-9, NEG-13), the polling-read ledger exception, and the three red-team fixes.'
i = find('- S2')
lines[i] = '- S2 (closed: D6, AC-9 and NEG-13 are built in S1b because no narrowing test is possible while the mint demands five abilities).'
sub('- S5', 'only if Q2 is yes and Q8 strings approved', 'Q2 is yes; Q8 strings still to be approved')
open(p, 'w').write('\n'.join(lines))
print('ok')
