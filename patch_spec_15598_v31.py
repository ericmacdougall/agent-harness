s = open('spec-15598-v3.md').read()


def sub(old, new):
    global s
    assert s.count(old) == 1, (s.count(old), old[:80])
    s = s.replace(old, new)


# N1: typed caller, only the grantee passes, background refuses
sub("goes through one wrapper `openSecretPlaintextFor(db, row, caller)` that refuses a secret with a `vault_blind_mints` row unless the caller is the grantee on `vault-env/reveal`",
    "goes through one wrapper `openSecretPlaintextFor(db, row, caller)` with a typed caller (`{ kind: 'grantee_reveal' | 'session' | 'user_token' | 'api_key' | 'system', ... }`; background and worker sites such as the saved-workflow reconciler pass `system`, which always refuses a blind secret) that refuses a secret with a `vault_blind_mints` row unless the caller kind is `grantee_reveal`, produced only by `vault-env/reveal` for the authenticated grantee principal")
sub("(by the authenticated principal id, in the same org, grantee still eligible) or", "(by the authenticated principal id, in the same org, grantee still eligible, re-checked on every reveal) or") if "(by the authenticated principal id, in the same org, grantee still eligible) or" in s else None

# N2: persona and key provenance, applied to both
sub("D13. Provenance (A2): migration adds `created_via` text", "D13. Provenance (A2): for a persona grantee A2 applies to BOTH the persona and the key it speaks through (vault-env resolves a persona by its key): the key must be `session`-created, with `created_by_user_token_id` NULL, never tied to a token later (extend or re-scope by a token makes it ineligible), and at least 60 minutes old; re-checked on every reveal, not only at mint. The migration adds `created_via` text")
sub("to `api_keys` and `api_key_personas`,", "to `api_keys` and the personas table (with `created_via_id`),")
sub("a key that does not qualify is not eligible, and that is a recorded limitation, not an ask.", "a key that does not qualify is not eligible, and that is a recorded limitation, not an ask (a session-only confirmation route for an existing key is out of scope here).")

# N3: D10 tie decision
sub("Revoking the MINTING token does not end the host's read (a host key outliving its minting token is intended; coupling them would break hosts), stated here on purpose.",
    "Revoking the MINTING token does not end the host's read (ASSUMPTION A5, needs main's confirmation: a host key outliving its minting token is intended; the alternative keeps the existing tie so the key dies with the token and hosts must re-mint). To keep the existing protections, the minted key does not set `created_by_user_token_id` (that is the lifetime tie) but a separate marker `minted_via_user_token_id` on the blind row and the key, which the personal-principal rules treat exactly like `created_by_user_token_id` (a minted key never acts as an owner-mode personal principal); the 90-day `expiresAt` stays mandatory; revoking the minting token emails the owner the list of keys it minted to vaults.")
sub("- ASSUMPTION A4", "- ASSUMPTION A5 (needs main's confirmation): the minted key outlives its minting token (D10). Source: inferred: from ticket:GoodQA goodqa#15598 -- a host key must survive the agent token that minted it; main to confirm or choose the existing tie.\n- ASSUMPTION A4")

# N4
sub("is refused by the new route with `user_token_ability_conflict`;", "or `all` is refused by the new route with `user_token_ability_conflict` (A1: `all` does not include `tokens.mint_to_vault`, and `all` together with it is refused); the live-proof token additionally lacks `tokens.create_other_keys`;")
sub("a token that holds BOTH `tokens.mint_to_vault` and `tokens.create_other_keys` is refused", "a token that holds `tokens.mint_to_vault` together with `tokens.create_other_keys` or `all` is refused")

# NEG for system/background and bound desktop session
sub("## Resource budget", "- NEG-18 (AC-2): a saved automation workflow whose http_request credential is a blind secret, run by the background reconciler as the creating user, is refused (caller kind `system`); a desktop session bound to the same token is refused on every opener; a persona grantee whose key was token-minted, a session-created key later extended or re-scoped by a token, and a retired persona are all refused, also at reveal time. Source: inferred: from ticket:GoodQA goodqa#15598 -- from the adversarial delta review (N1, N2)\n\n## Resource budget")
open('spec-15598-v31.md', 'w').write(s)
print('ok')
