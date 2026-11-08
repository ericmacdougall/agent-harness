# codex-pool

Budget-aware rotation of OpenAI API keys for Codex runs (`harness/hooks/codex_pool.py`, policy in
`harness/hooks/codex_pool_policy.json`, installed wrapper `~/.agent-harness/bin/codex-pool`; create it with
`python3 -I ~/.claude/hooks/codex_pool.py install`).

## Order of preference

1. The ChatGPT subscription login (default `CODEX_HOME`), unless it is recorded as quota-blocked
   (`codex-pool subscription-block --until <iso>`; set automatically on a usage-limit failure or a trusted
   Codex QUOTA result from `peer_review.py`).
2. API keys from Secret Manager (`goodqa-28dd3`, `openai-codex-key-<alias>`, always `latest`), least spent today
   first. Skipped: disabled, `401`, `insufficient_quota`, `codex-restricted` (key works for the API but its org may
   not use Codex), rate-limited within the cooldown. `codex-pool enable --alias A` clears a stuck failure mark.

## Caps (confirmed by the user 2026-11-08)

`$5` per run, `$15` per key per day, `$40` total per day, `$300` total per month (UTC days). A run first writes a
reserve row (`reserve_usd` per model family) under an flock; it is refused if the reserve would pass any cap, so
concurrent runs cannot overspend. The reserve is settled to the priced usage afterwards. Unknown usage (crash,
timeout, kill) stays at the full reserve. Prices are estimates; OpenAI has no balance API, so the ledger
(`~/.agent-harness/codex-pool/ledger.jsonl`) is the only spend record. The cap is enforced at reservation, and a
single `codex exec` turn that costs more than its reserve is recorded in full (`*_over_reserve`) but not interrupted.

## Models

Terra/Sol follow `model_tiers.json`. `gpt-*-astra` is refused unless `escalation.py approve-top` recorded permission
for `--task`. Daybreak models run only for `--purpose redteam` on a key whose `probe` shows access. Unpriced models
are refused.

## Key handling

The key is read inside the process (`gcloud` directly, else `ssh <ssh_host> gcloud ...`) and handed to the single
`codex exec` child as `CODEX_API_KEY` (verified live: commands the model runs see no `CODEX_API_KEY`, because
Codex strips `*KEY*` variables and the pool also excludes it explicitly). No key file is written; `CODEX_HOME` is a
fresh empty mode-0700 directory under `~/.agent-harness/codex-pool/homes`, deleted afterwards (also on SIGTERM).
Child stdout/stderr are scrubbed for the key, its base64/hex/reversed forms and any `sk-` token. The codex
executable must be a regular file owned by you or root and not group/world-writable. Caller arguments after `--`
must start with `exec` (no subcommands) and may not set the model, effort, profile, provider, base URL, sandbox
escalation (`danger-full-access`, `--add-dir`, `--full-auto`, bypass flags), network, MCP or shell-environment config.

Failure handling: a key is marked unhealthy and the next key tried only when a structured JSON error record
(`--json`) arrives before any model work. Anything else (stderr prose, failure after work, timeout, no `--json`)
keeps the full reserve in the ledger and is not retried. A refused or unusable pool prints a prose "usage limit
reached" error record so `peer_review.py` may use its one independent fallback without placing a cooldown.

Known limits: caps are per host (the Mac and t2-dev keep separate ledgers) and are enforced at reservation, not
mid-run; set a hard monthly limit on each OpenAI project as the real backstop. `CODEX_POOL_STATE_DIR` and
`CODEX_POOL_POLICY` can redirect the ledger and policy, so the caps guard budget, not a hostile local user.

## Commands

`status [--json]`, `probe [--alias A]`, `run --purpose build|review|redteam --model M --effort E [--task T] -- exec ...`,
`enable|disable --alias A`, `subscription-block --until ISO|--clear`, `install`. Test with
`python3 tests/test_codex_pool.py`; `CODEX_POOL_UNDER_TEST` points the suite at a mutated copy.
