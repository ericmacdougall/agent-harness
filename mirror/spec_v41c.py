p = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-aaef3bc78b40c0c22/spec-15561-v4.1.md'
s = open(p).read()
failed = []


def rep(old, new):
    global s
    if s.count(old) != 1:
        failed.append((old[:70], s.count(old)))
        return
    s = s.replace(old, new)


# R1
rep("a user-token actor can never mint (policy rule `token_mint`).",
    "a bound desktop session can never mint (policy rule `token_mint`), and a bearer token cannot mint once the platform switch `userTokens.sessionActions` is on; while that switch is off (its default) a bearer token can still mint a legacy child (`created_via = user_token`), which is what the live-proof check `created_via = session, no parent` guards against.")
# R2
rep("otherwise the owner mints a fresh \"Desktop app: view CRM\" token.",
    "otherwise the owner mints a fresh token with exactly `desktop_signin` + `read` + `crm` (the \"Desktop app: view CRM\" preset once S5 has shipped; the three checkboxes by hand before, they exist today).")
# N1
rep("and the click-test records the org's `crm.api.enabled` value (read by an operator from the org's entitlement overrides, not from the UI) and the token's abilities, `created_via` and `created_by_token_id` (metadata only) so the evidence shows it is the least-privilege token.",
    "and the evidence records the org's `crm.api.enabled` value and the token's abilities, `created_via` and `created_by_token_id` (metadata only), read by an operator who is not the author (the click-tester cannot read them from the UI) so the evidence shows it is the least-privilege token and stays independent.")
# N2 and limitation
rep("registered as an ask before the deploy; #1319 is rolled back rather than leaving the mini without remote routes if that re-sign-in is not done.",
    "registered as an ask (Source: ticket:GoodQA goodqa#15561) before the deploy. The operator read of the metadata happens BEFORE the deploy; the re-sign-in must be done within the same release window, otherwise #1319 is rolled back rather than leaving the mini without remote routes. Known limitation: the replacement token today is an Everything token, the over-privileged token D6 argues against, until the `machines` checkbox is approved.")
# N3
rep("(it joins ask wc27c825f054).",
    "(it joins ask wc27c825f054), and the mini's previous sign-in is restored after the proof; the Ask-me-first mint approval (`approval: 'desktop_signin'`) is a further human step.")
# N4 / F6(c)
rep("non-CRM routes (`/v1/orgs/:p/entitlements`, `/v1/orgs/:p/members`) that the v1 table does not delegate; the S0 inventory decides each.",
    "non-CRM routes (`/v1/orgs/:p/entitlements`, `/v1/orgs/:p/members`) which the S0 inventory decided to delegate as read-only page-support entries (D4).")
open(p, 'w').write(s)
print('failed:', failed)
