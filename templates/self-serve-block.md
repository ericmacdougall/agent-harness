<!-- self-serve:begin -->
## Agent self-serve (mine; no expiry; written by ah_enable_self_serve.py, which I ran myself)

Policy `{{POLICY_ID}}`, signing key `{{KEY_ID}}`. The signed policy file is `~/.agent-harness/policy/self-serve.json`; the main agent (Claude) or a Codex Desktop root may use only the capabilities it lists. Helper subagents never receive a grant. Check with `python3 ~/.agent-harness/bin/ah_enable_self_serve.py --status`.

Capabilities (a closed list; an unknown name is refused):

{{CAPABILITIES}}

- **What this gives an agent:** run the journaled `ah ops` and `ah install-files` recipes, repair the harness from a canonical-main commit, clean up this session's own pool reservations, run the merge and central-decision steps that need no words of mine, and, when the other harness is out of quota, accept a same-harness exact-HEAD review for non-sensitive paths under the written limits.
- **What it never gives:** accounts, passwords, production credentials, payments, CAPTCHA, the gated model tier (that needs my own words), `merge_gate.py waive` outside the quota-fallback class, key creation or pinning, `--undo`, `--disable`, and Codex `/hooks` trust clicks. Hard rules 1 to 4 have no capability and no schema field.
- **Trust limit (stated, not oversold):** the signature and the protected paths stop careless agents, not a malicious local process running as me. The enabler's own human-step checks (a terminal, a code shown in a dialog) stop accidental self-enable only; `command_guard` is the control that blocks an agent from running the enabler, and a deliberate evasion is a rule 3 violation either way.
- **Fail safe:** a missing, expired, revoked, tampered or kill-switched policy means no grant and today's behavior. Anyone may revoke at once; only I re-enable.
- **If an allow rule is refused:** report it as a limitation, file a P0 GoodQA ticket, and keep working around it. Never re-encode a command to get past a guard.
- **Roll back:** I run `ah_enable_self_serve.py --undo` (restores these files and removes the key pin on both hosts) or create `~/.agent-harness/policy/disabled`.
<!-- self-serve:end -->
