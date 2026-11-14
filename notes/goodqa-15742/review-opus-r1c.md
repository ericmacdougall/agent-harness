# Opus adversarial review, receipt r1c delta (agent a0c568dfa08e7eb86)

Head 10c0c35c. Read-only review of the AC-4, AC-5 and AC-8 changes against the code.
- F1 unfinished-run clearing: correct. F2 total deadline and automatic rollback of a lost after-test: correct. F3 real post-restore state: correct.
- H1 (found at 309ab43b): a rollback with unusable backups wedged the host. Fixed at 10c0c35c by checking backups before the start row; no new race (the host re-checks the sha256 of the payload).
- Accepted as a stated AC-5 limit: a host that can neither resume nor roll back; follow-up ticket for a main-only --resolve.
- Low: the H1 mutant models "skip the check" rather than "check after the start row".
Verdict: ACCEPT
