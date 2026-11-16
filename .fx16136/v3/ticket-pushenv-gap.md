push-env.sh regeneration drops six dispatcher keys the VM carries

Found while fixing receipt bugtracker-pr1377-gate-v3 F8 (goodqa#16148, PR #1377).

infra/selfhost/app/push-env.sh regenerates /etc/goodqa/dispatcher.env whole (the installer replaces the file). infra/selfhost/app/env-keys.json (the key-name baseline read from the live VM 2026-10-15, checked by the selfhost-topology-drift gate) lists dispatcher keys that push-env.sh never emits:

- AI_DEFAULT_PROVIDER
- AI_SPEND_GLOBAL_DAILY_MICROS
- AI_SPEND_SDK_PRICES_JSON
- GOOGLE_APPLICATION_CREDENTIALS_JSON
- VERTEX_AI_LOCATION
- VERTEX_AI_SUMMARY_MODEL

No other producer in the repo writes them (grep of infra/selfhost, infra/release-harness, infra/do), so they were set by hand on the VM. A regeneration with push-env.sh removes them silently. The two VERTEX_AI_* keys may be obsolete (no Vertex providers are used); that is a product decision for the owner, not something to restore blindly.

The F8 fix (the JOB_ENVFILE_INTELLIGENCE_WORKER__GITHUB_APP_PRIVATE_KEY line) is in PR #1377. test_rw_ship_jobsecret_gate.py::test_dispatcher_env_keys_without_a_producer_are_exactly_the_known_gap pins this exact set, so a new gap fails and closing this ticket means shrinking that set.

Acceptance:
- For each key: either push-env.sh produces it from a named source (Secret Manager or the live spec), or env-keys.json drops it in the same change that removes it from the VM.
- The pinned gap set in the test is empty.

Scope note: api.env and web.env keys come from the live DO spec at run time, so their producer coverage cannot be checked statically; not covered here.
