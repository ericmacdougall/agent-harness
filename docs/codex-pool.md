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

The key is read inside the process (`gcloud` directly, else `ssh <ssh_host> gcloud ...`), written only to the
stdin of `codex login --with-api-key` in a fresh mode-0700 `CODEX_HOME` under `~/.agent-harness/codex-pool/homes`,
and the directory is deleted afterwards (also on SIGTERM). Child stdout/stderr are scrubbed for the key and any
`sk-` token. Caller arguments after `--` must start with `exec` and may not set the model, profile, provider or base
URL.

## Commands

`status [--json]`, `probe [--alias A]`, `run --purpose build|review|redteam --model M --effort E [--task T] -- exec ...`,
`enable|disable --alias A`, `subscription-block --until ISO|--clear`, `install`. Test with
`python3 tests/test_codex_pool.py`; `CODEX_POOL_UNDER_TEST` points the suite at a mutated copy.
