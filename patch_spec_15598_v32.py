import re

s = open('spec-15598-v31.md').read()


def sub(old, new, count=1):
    global s
    assert s.count(old) == count, (s.count(old), old[:80])
    s = s.replace(old, new)


sub("D7. Rate limit (ASSUMPTION A4, numbers are a proposal):", "D7. Rate limit (ASSUMPTION A4, numbers accepted by main):")
sub("| Only the grantee and a signed-in person can open it |", "| Only the grantee can open it (no human reveal either) |")
sub("; numbers in D7 are a proposal pending main.", "; the numbers in D7 were accepted by main.")
sub("- Migration: additive table with cascading FKs;", "- Migration: additive (one new table with cascading FKs, plus `created_via` columns with default `unknown` on `api_keys` and the personas table, and a `minted_via_user_token_id` column);")
s = re.sub(r"the migration is additive \(new table\)", "the migration is additive (a new table and defaulted columns)", s)

# AC-4: environment order and member-floor read
a = s.index("- AC-4:")
b = s.index("- AC-5:")
ac4 = s[a:b]
ac4 = ac4.replace("Live proof after deploy, with `vaultEnv.enabled` on for a disposable org (a platform-operator entitlement override, recorded as a precondition) and `apiKeys.mintToVault` on:",
    "Live proof after deploy, in this order of environment (main decision 2026-11-10; no disposable production org and no production `vaultEnv` override): (1) an existing org the user owns where `vaultEnv.enabled` is already on, checked read-only; (2) otherwise staging for the full proof, with the production proof limited to what works with the flag as it is; (3) otherwise a disclosed limitation, the flag decision being put to the user by main. The platform flag `apiKeys.mintToVault` is on for the proof (a platform setting, not an org or account creation), and the minted key has scopes `read` and org role `member`:")
ac4 = ac4.replace("https://goodqa.app/v1/orgs/ORGID/api-keys'` expecting 200", "https://goodqa.app/v1/me'` expecting 200 (a member-floor read; the org api-keys list needs `org:manage_api_keys` and would be refused)")
s = s[:a] + ac4 + s[b:]

# P1: no audit-based upgrade
sub("backfilled `unknown`, except rows whose creation audit row proves a signed-in session.", "backfilled `unknown` with NO audit-based upgrade (the creation audit row records actorKind user for a session, a user token and an org API key alike, so it cannot prove a session).")
sub("backfilled `unknown` (never eligible) except where the creation audit row proves a signed-in session; a key", "backfilled `unknown` (never eligible; no audit-based upgrade); a key")
sub("an existing human-created key whose creation audit row proves a signed-in session and is over an hour old; if none qualifies the tester creates one through a signed-in session and waits an hour, recorded as a limitation, not an ask to the user)", "a key the tester creates through a signed-in session after the migration is deployed, then waits 60 minutes; this is the only path because every pre-migration key is `unknown`, recorded as a limitation, not an ask to the user)")
sub("a runner key and a user-scoped key are all refused", "a pre-migration key or persona whose creation audit row shows actorKind user (backfilled `unknown`), a runner key and a user-scoped key are all refused")
sub("- Rotation: every host key", "- The grantee host's operator is trusted with the key; this design does not protect against that operator.\n- Rotation: every host key")
sub("a repo-wide census test fails if any non-test file calls the raw opener outside the wrapper (the user-token policy census pattern).", "a repo-wide census test fails if any non-test file calls the raw opener outside the wrapper (the user-token policy census pattern), and a second census fails if any insert into `api_keys` or the personas table leaves `created_via` unset.") if False else None
open('spec-15598-v32.md', 'w').write(s)
print('ok')
