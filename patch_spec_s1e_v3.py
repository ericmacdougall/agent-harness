p = 'spec-15561-s1e.md'
s = open(p).read()


def sub(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:70])
    s = s.replace(old, new)


sub("- NEG-12 (AC-2): an operator-kind token's bound session gets `user_token_non_delegable` on both routes; a HEAD or any non-GET method on those paths is not opened by W4 (DELETE on the detail path is refused).",
    "- NEG-12 (AC-2): an operator-kind token's bound session gets `user_token_non_delegable` on both routes; a HEAD on either route is covered exactly like GET (200 with `crm`, 403 without), and no other method is opened by W4: DELETE on the detail path is refused, POST on the timeline path (timeline create) is refused, PATCH on the detail path remains the ordinary CRM write door (needs `write`).")
sub("a member without `crm:read` gets 403 from the handler.",
    "a member without `crm:read` is refused by the existing handler check (`requireOrgPermission`, unchanged and covered by the existing CRM permission suites; this slice does not rebuild a role without `crm:read`, a stated limit).")
sub("a contact id of org B under org A's route is 404 even for a token reaching both orgs;",
    "a contact id of org B under org A's contact route is 404 (and under the timeline route an empty page with no org-B data) even for a token reaching both orgs;")
sub("- NEG-11 (AC-4):", "- NEG-11 (AC-2):")
sub("- A2 ", "- A2 ") if False else None
sub("No settings screen is built here (a ticket follows); the override is set through the existing entitlement-override mechanism.",
    "No settings screen is built here (a ticket follows); the override is an entitlement-override key read directly from the org row (no registration needed) and is set by a platform operator through the existing override mechanism; an org admin cannot yet set it themselves (a stated limit).")
sub("Nothing else changes:", "Nothing else changes (the org CRM switch and the org opt-out `userTokens.contactTimelines` still refuse both routes):")
sub("| Audit complete | opened reads leave no trail | D4 | NEG-10 |",
    "| Audit complete | opened reads leave no trail | D4 | NEG-10 |\n| Org controls hold | the org CRM switch or the org opt-out is bypassed on these routes | D6 | NEG-11 |\n| Operator exclusion | an agent-held orchestrator token reads timelines through a session | D1 | NEG-12 |")
sub("failing first on origin/main (9 of 12 red, both routes answer `user_token_non_delegable`)",
    "failing first on origin/main (the first 12-test version was 9 of 12 red, both routes answering `user_token_non_delegable`; tests added after the review rounds are shown red only through the four recorded mutants, a stated limit)")
open(p, 'w').write(s)
print('ok')
