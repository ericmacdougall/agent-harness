import shutil
base = '/Users/eric/.agent-harness/work/baab765b-d85c-46b4-b7b9-588eb912c770/agent-aaef3bc78b40c0c22/'
shutil.copy(base + 'spec-15561-v4.md', base + 'spec-15561-v4.1.md')
p = base + 'spec-15561-v4.1.md'
s = open(p).read()
failed = []


def rep(old, new):
    global s
    if s.count(old) != 1:
        failed.append((old[:70], s.count(old)))
        return
    s = s.replace(old, new)


# L3: one Q7 sentence carrying the timeline qualifier
a = s.index('Q7 is DECIDED BY THE USER for contact detail')
b = s.index('#1319 (S0, S1a, S1b) still ships them refused')
s = s[:a] + ("Q7 is DECIDED BY THE USER, Source: answer:baab765b-d85c-46b4-b7b9-588eb912c770/c75dac6b-ba47-4287-a1c2-f448c1ad3a4d \"Open it now\" (requirement w5a0692ecf0a): contact detail becomes reachable from token-started desktop sessions and by `crm`-ability tokens and agents; the contact TIMELINE stays behind its existing session-action control (the platform switch, the org owner opt-in and the token grant) by main's decision (comment 59a46886-1b3e-4771-8ea9-a3bd355788e5, the recommended option), and the user has not been asked to remove that control. ") + s[b:]

# M1
rep("(no agent mints, no token can mint: rule `token_mint`)",
    "(no agent mints; while the platform switch `userTokens.sessionActions` is off, its default, a token CAN mint a legacy child, so the live token's `created_via` and `created_by_token_id` are read from metadata and the proof requires `created_via = session` with no parent)")
# M2
rep("the production live proof reuses an existing token the owner supplies as a token file on the mini (never pasted into chat, a ticket or a log).",
    "the production live proof may reuse an existing token only if an operator reads its metadata and it is EXACTLY the abilities `desktop_signin` + `read` + `crm`, `created_via = session`, no parent (a token file on the mini, never pasted into chat, a ticket or a log); otherwise the owner mints a fresh \"Desktop app: view CRM\" token. An operator or Everything token would pass the oracle without proving the least-privilege path, so it is not an acceptable live-proof token.")
rep("and the click-test records the org's `crm.api.enabled` value (read by an operator from the org's entitlement overrides, not from the UI).",
    "and the click-test records the org's `crm.api.enabled` value (read by an operator from the org's entitlement overrides, not from the UI) and the token's abilities, `created_via` and `created_by_token_id` (metadata only) so the evidence shows it is the least-privilege token.")
# L1
rep("A token without `read` or `write` cannot start a session (AC-9), so the missing-ability cases are made by a PATCH after the session starts.",
    "A token without `read` cannot start a session (AC-9; `write` is not required to start one, D6), so the missing-ability cases are made by a PATCH after the session starts.")
# L2
rep("- AC-16 with the platform switch",
    "- Registered human step and rollback criterion (Q9): if an operator reads the mini's bound token as `created_via = operator`, its machine and remote-session routes stop at the #1319 deploy (an operator-bound session gets no host waivers, NEG-39). The owner then signs the mini in again with a non-operator token (today an Everything token, because the `machines` checkbox is hidden in the token UI), registered as an ask before the deploy; #1319 is rolled back rather than leaving the mini without remote routes if that re-sign-in is not done.\n- AC-16 with the platform switch")
open(p, 'w').write(s)
print('failed:', failed)
