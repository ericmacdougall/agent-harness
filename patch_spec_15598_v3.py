s = open('spec-15598-v2.md').read()


def sub(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:80])
    s = s.replace(old, new)


sub(" (paths relative to that tree; origin/main later moved only by deploy records)", " (paths relative to that tree)")

# A2 provenance (M1)
sub("- ASSUMPTION A2 (review-driven): grantee eligibility is the human-bootstrap control: the grantee must be a principal that no agent credential could have received in plaintext and that existed before the mint: created by a signed-in person's session (not by any user token, not by MCP pairing, not by an automation), at least 60 minutes old, same org, not revoked, not a runner key, not user-scoped, not the key being minted. This moves the one human act to when the grantee was created, not to mint time.",
    "- ASSUMPTION A2 (review-driven): grantee eligibility is the human-bootstrap control: the grantee must be a principal that no agent credential could have received in plaintext and that existed before the mint: recorded as created by a signed-in person's session (a new provenance column, see D13; not any user token, not MCP pairing, not an automation, not another API key), at least 60 minutes old, same org, not revoked, not a runner key, not user-scoped, not the key being minted. This moves the one human act to when the grantee was created, not to mint time. Existing keys and personas have no provenance today: they are backfilled `unknown` (never eligible) except where the creation audit row proves a signed-in session; a key that does not qualify is not eligible, and that is a recorded limitation, not an ask.")
sub("- ASSUMPTION A3 (review-driven)", "- ASSUMPTION A4 (numbers and codes, a proposal accepted by main 2026-11-10): 5 mints per hour per token, 20 per day per org, `expiresAt` required and at most 90 days, replay of a revoked key answers 410 `mint_replay_revoked`, 409 `idempotency_key_reused`, 429 `api_key_mint_rate_limited`. Source: main decision 2026-11-10 \"The numbers are fine.\"\n- ASSUMPTION A3 (review-driven)")

# M3: human reveal refused
sub("a signed-in person's session (AuthContext without `userTokenId`, `apiKeyId`, MCP dispatch marker or desktop-session binding; the field tested is named in the test). A repo-wide census",
    "nobody else: no signed-in session, no admin, no owner (a browser agent signed in as the person would otherwise defeat \"never obtains\"; a person who needs a new value deletes the secret and mints again). A repo-wide census")
sub("a desktop session bound to a token; a signed-in person's session can.", "a desktop session bound to a token, and a signed-in person's session (delete and re-mint is the human path).")
sub("a desktop session bound to a token; a signed-in person's session can.", "a desktop session bound to a token, and a signed-in person's session.") if False else None

# D4 human integrity
sub("D4. Integrity paths: `PATCH /vault/secrets/:id` (value, rename, description), grant PUT/DELETE, delete and any move or convert refuse a blind secret for every agent credential; human-session only.",
    "D4. Integrity paths: `PATCH /vault/secrets/:id` (value, rename, description), grant PUT/DELETE and any move or convert refuse a blind secret for every caller, human sessions included (the value must not be swappable or re-readable); only DELETE is allowed, and only to a signed-in person's session with `org:manage_vault` (an agent credential cannot delete it either, so an agent cannot force a swap).")

# D2 rule for both abilities (NEG-8 pick)
sub("D2. Token gate: new ability rule", "D2. Token gate: a token that holds BOTH `tokens.mint_to_vault` and `tokens.create_other_keys` is refused by the new route (`user_token_ability_conflict`), so the minting token can never also receive a plaintext key; new ability rule")

# D10 rewrite
sub("Revoking the key, deleting the secret, or revoking the grantee ends the host's read.", "Revoking the key, deleting the secret, or revoking the grantee ends the host's read.")
a = s.index("D10. Revoke and rotation:")
b = s.index("D11.")
s = s[:a] + "D10. Revoke and rotation: `vault_blind_mints` has FKs with ON DELETE CASCADE to `vault_secrets` and `api_keys`. The host can read only while all of these hold, checked by join at read time (no cleanup job): the minted key is not revoked, the secret exists, and the grantee is still eligible and not revoked. Revoking the MINTING token does not end the host's read (a host key outliving its minting token is intended; coupling them would break hosts), stated here on purpose. Rotation: a blind value is never rotated in place; to rotate (and every 90 days at the latest) mint again under a new vault name (for example `name-v2`), switch the host, then delete the old secret; a vault name that already exists answers 409 `vault_name_taken`.\n" + s[b:]

# D13 provenance column
sub("D11. Rollout and rollback:", "D13. Provenance (A2): migration adds `created_via` text (`session`, `user_token`, `mcp_pairing`, `automation`, `api_key`, `unknown`; default `unknown`) to `api_keys` and `api_key_personas`, set by every creation path from the authenticated context (a creation from an org API key is `api_key`, so a key minted by an agent holding a key never looks human-created), backfilled `unknown`, except rows whose creation audit row proves a signed-in session. Eligibility requires exactly `session`; an unknown or unreadable value is not eligible (fail closed).\nD11. Rollout and rollback:")

# AC-4 concrete (M2)
a = s.index("- AC-4:")
b = s.index("- AC-5:")
s = s[:a] + "- AC-4: Live proof after deploy, with `vaultEnv.enabled` on for a disposable org (a platform-operator entitlement override, recorded as a precondition) and `apiKeys.mintToVault` on: the independent click-tester (not the author) uses a token with `tokens.mint_to_vault` and without `tokens.create_other_keys`, and a grantee that qualifies under A2 (an existing human-created key whose creation audit row proves a signed-in session and is over an hour old; if none qualifies the tester creates one through a signed-in session and waits an hour, recorded as a limitation, not an ask to the user). Steps: mint through the route; on the grantee host run `goodqa run --secrets MINTED=VAULTNAME -- sh -c 'umask 077; printf %s \"$MINTED\" > KEYFILE'` with `GOODQA_API_KEY_FILE` pointing at the grantee key file and `GOODQA_ORG_ID` set (no value in argv or output), then `stat -c '%a %U' KEYFILE` shows 600; the authenticated call is `goodqa run --secrets MINTED=VAULTNAME -- sh -c 'printf \"header = \\\"Authorization: Bearer %s\\\"\\n\" \"$MINTED\" | curl -sS -K - -o /dev/null -w %{http_code} https://goodqa.app/v1/orgs/ORGID/api-keys'` expecting 200 (the value only in the shell builtin and curl stdin, never argv); refusals proven live with a NON-grantee org API key and an org owner through a user token on `vault-env/reveal`, the vault reveal route, and an automation http step-test using the blind secret as credential; then the key is revoked and the same call is refused live (post-revoke 401), and the secret is deleted. Verify by: `spec_flow.py click-test` by the independent tester. Source: ticket:GoodQA goodqa#15598\n" + s[b:]
sub("Verify by: reading `POST /v1/me/desktop-session` policy and recording the answer", "Verify by: reading the `POST /v1/me/desktop-session` rule in `lib/user-token-policy.ts` and the session-start check in `modules/user-tokens/desktop-session` and recording the answer")

# NEG-8
sub("- NEG-8 (AC-3): a token with `tokens.mint_to_vault` and also `tokens.create_other_keys` is refused by the new route (or the proof token is shown to lack it and plain `POST /api-keys` with that token is refused);", "- NEG-8 (AC-3): a token with `tokens.mint_to_vault` and also `tokens.create_other_keys` is refused by the new route with `user_token_ability_conflict`;")
# NEG-6 add provenance cases
sub("a principal younger than 60 minutes, a runner key and a user-scoped key are all refused", "a principal younger than 60 minutes, a principal whose `created_via` is anything but `session` (including `unknown` and a key minted by an agent holding an org API key), a runner key and a user-scoped key are all refused")
# NEG-4 human
sub("- NEG-9 (AC-2): PATCH value, rename, description, grant PUT and DELETE, delete and move on a blind secret are refused for every agent credential;", "- NEG-9 (AC-2): PATCH value, rename, description, grant PUT and DELETE and move on a blind secret are refused for every caller, a signed-in person included, and a signed-in person's reveal is refused; DELETE is allowed only to a signed-in session with `org:manage_vault`;")
# NEG sources for assumption-based
for n in ('NEG-6', 'NEG-8', 'NEG-13'):
    i = s.index(f"- {n} (AC-3):")
    j = s.index("Source: ticket:GoodQA goodqa#15598", i)
    s = s[:j] + "Source: inferred: from ticket:GoodQA goodqa#15598 -- rests on assumptions A1, A2 and A4 labelled above" + s[j + len("Source: ticket:GoodQA goodqa#15598"):]
# NEG-3 etc unchanged. Add NEG-17 human reveal & name collision
sub("## Resource budget", "- NEG-17 (AC-3): a vault name that already exists answers 409 `vault_name_taken` and mints nothing; a replay that returned early (valid idempotent replay) is counted before the rate limiter and does not consume the hourly allowance. Source: inferred: from ticket:GoodQA goodqa#15598 -- rests on assumption A4\n\n## Resource budget")
# risks: rotation
sub("- Migration: additive table with cascading FKs;", "- Rotation: every host key expires within 90 days and a blind value is never rotated in place; the rotation flow is re-mint under a new vault name, switch the host, delete the old secret (D10); people-watch needs that on a schedule, disclosed.\n- Human session cannot read a blind secret either (a browser agent signed in as the person must not defeat the purpose); the person recovers by delete and re-mint.\n- Migration: additive table with cascading FKs;")
open('spec-15598-v3.md', 'w').write(s)
print('ok')
