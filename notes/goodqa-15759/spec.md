# Spec: command_guard refuses scp and rsync to a remote harness path

Ticket: GoodQA goodqa#15759
Author: agent:af9e33704216a1ea1 (Sonnet 5.5)
Click-test: required
Sign-off: main
Review-policy: standard

## Outcome

The command guard refuses an `scp` or `rsync` whose DESTINATION is a remote path that names a protected harness location (a hook file such as `~/.claude/hooks/command_guard.py`, a WAL), with the same rule and tiers as a local `cp` and an ssh-wrapped `cp`, and a refusal text that names the sanctioned route `ah install-files` (goodqa#15742). This closes the route of the 2026-11-11 t2-dev install: the remote `cp` was blocked, the owner then used `scp`, and the guard allowed it (measured on 2026-11-12: `scp x t2-dev:~/.claude/hooks/command_guard.py` returned allow while `cp x ~/.claude/hooks/command_guard.py` and `ssh t2-dev "cp x ~/.claude/hooks/command_guard.py"` returned block).

## Scope

- In: a `remote_copy_dest` check in `harness/hooks/command_guard.py`, called from the `scp` and `rsync` branches of the destructive-command analysis (`scp` joins the dispatch list); the destination is read as `host:path`, `user@host:path`, `host:relative` (a path relative to the remote home is read as `~/relative`) and `scp://host/path`; the destination itself and, for a directory destination, each source file name placed inside it are judged exactly like a local `cp` destination (tiers `log` and `unknown`, `need_existing` false because the file lives on the other host); the refusal names `ah install-files`.
- Out: `sftp` batch commands and `ssh`-borne copies by other tools (stated limit: the guard sees command text only); a directory SOURCE is not expanded (stated limit); any change to the refusal text or the semantics of the existing `cp` rule; downloads (a remote source, a local destination).
- Narrowing of the ticket, labelled (ASSUMPTION D3): the ticket asks to refuse an scp, rsync or sftp; sftp is NOT covered, because its commands arrive on stdin or in a batch file the guard does not parse (`sftp host <<< "put x .claude/hooks/command_guard.py"` is allowed); the same holds for `tar | ssh` and any other program that speaks ssh itself; a follow-up ticket may scan visible here-string and heredoc bodies. D4: the recursive-copy and `--delete` refusal into a protected CONTAINER directory is added for REMOTE destinations only; the same gap exists locally today (`cp -r hooks/. ~/.claude/hooks/` and `rsync -av ./hooks/ ~/.claude/hooks/` are allowed) and is tracked as goodqa#15767 because changing the local rule affects every session. Stated limits: a directory SOURCE is not expanded; a variable in the file position (`host:~/.claude/hooks/$F`) is judged like the local `cp` (not caught); the module root of an rsync daemon is unknown so its path is judged as given; a remote WAL or hooks DIRECTORY destination is judged by name even when no local file exists, so a copy into a remote WAL directory is refused where the local copy into an existing log directory is allowed (a safe-direction difference); `~/.claude/settings.json` is not protected by the existing classes, remotely or locally.
- Decisions (owner assumptions, none is a user decision): D1 same tiers and rule id as `cp` (`log_delete/log-delete`) so one policy decides; D2 a hook file name placed into a directory destination is judged because `cp` of an existing hook file into its directory is the overwrite that matters, while a directory destination with no protected file name stays allowed exactly as `cp x ~/.claude/hooks/` is today.

## Acceptance criteria

- AC-1: `scp` and `rsync` to a remote destination naming a protected harness path are blocked with the `log_delete/log-delete` rule for each of these spellings: `host:~/path`, `user@host:/absolute/home/path`, `host:relative/path` (home-relative), `scp://host/path`, a directory destination with a protected source file name (`scp command_guard.py host:~/.claude/hooks/`), and with option values in the way, before OR after the destination (`-P 22`, `-i key`, `-o BatchMode=yes`, `rsync -e 'ssh -p 22'`, `--chmod 644`: the operands are read with option values skipped), IPv6 hosts (`[::1]:path`, `user@[fe80::1]:path`), `scp://` urls (absolute and home-relative, with a user, a port, `/~/` and url escapes like `%2E`), rsync daemon forms (`rsync://host/module/path`, `host::module/path`, judged on the path after the module), and a RECURSIVE copy (`scp -r`, `rsync -r`, `-a`, a trailing-slash rsync source) or an rsync `--delete`, `--del*` or `--remove-*` whose remote destination is a directory that CONTAINS protected files (the hooks directory, the WAL directory, `~/.claude`), because one such command overwrites or removes every hook; the container rule is judged on the EFFECTIVE write root (`dest/basename(src)` for `scp -r` and for an rsync source without a trailing slash, `dest` for a trailing-slash source, `.` and any `--del*`), so `scp -r proj host:~/` and `rsync -a proj host:~/` are allowed while `rsync -a ./ host:~/` and `rsync -a --delete proj host:~/` are refused; an empty remote path (`host:`) is the remote home; a short flag cluster ending in a value flag (`-avze ssh`, `-rP 22`) takes the NEXT word as its value, and every remote operand that follows a local operand is judged as an upload target, so an unknown option value after the destination (`--some-future-opt 1G`) cannot hide it; `rsync -R`, `--relative` and `--files-from` rebuild the SOURCE PATH under the destination, so `dest + source path` (cut at a `/./` marker, a leading `/` and `./` stripped) is judged as both a named target and a write root (`rsync -R .claude/hooks/command_guard.py t2-dev:` is refused, `rsync -R src/app.py host:~/proj/` is allowed), and `--files-from` (the sources are in a file the guard cannot read) is refused when the destination is a harness location or its ancestor; `sshpass` is looked through like `sudo` (its `-p`, `-P`, `-f` and `-d` values are skipped). Verify by: `python3 -B -m unittest tests.test_command_guard_scp_dest`. Source: ticket:GoodQA goodqa#15759
- AC-2: The refusal text names the sanctioned route `ah install-files`. Verify by: the same suite. Source: ticket:GoodQA goodqa#15759
- AC-3: Downloads and ordinary remote destinations stay allowed: a remote source with a local destination, `/tmp` and project paths, a home directory without a protected name, a hook-directory name that is not a protected file, and `scp x host:` (the remote home). Verify by: the same suite. Source: ticket:GoodQA goodqa#15759
- AC-4: The hook entry (`hook_main`) blocks the same commands (exit 2) and lets a download pass. Verify by: the same suite. Source: ticket:GoodQA goodqa#15759
- AC-5: The existing `cp` and ssh-wrapped `cp` and `mv` refusals are unchanged, `cp x ~/.claude/hooks/` stays allowed, the sanctioned `ah install-files` command is not blocked by this rule, and the existing command guard suite passes. Verify by: the same suite and `python3 -B -m unittest tests.test_command_guard`. Source: ticket:GoodQA goodqa#15759
- AC-6: Failing-first: the new tests FAIL against `origin/main` without the fix and against each broken variant (scp not dispatched, the scp branch doing nothing, the rsync destination not checked, a home-relative remote path not read as home, a directory destination ignoring its sources, an `scp://` url not read). Verify by: `python3 -B tests/mutants_scp_dest.py`. Source: ticket:GoodQA goodqa#15759

## Negative cases

- NEG-1 (AC-3): `scp t2-dev:~/.claude/hooks/command_guard.py /tmp/x`, `scp -r t2-dev:~/.claude/hooks /tmp/copy`, `rsync -av t2-dev:~/.claude/hooks/ /tmp/copy/`, `scp x t2-dev:/tmp/x`, `rsync -av x t2-dev:~/project/`, `scp -P 2222 report.txt user@host:reports/` and `scp a.txt b.txt t2-dev:/tmp/` are all allowed. Source: ticket:GoodQA goodqa#15759
- NEG-2 (AC-1): none of these may be allowed: the same copy through `user@host:` and an absolute path, through a home-relative path, through an `scp://` url, with several sources where one is a hook file name, and with a leading option value. Source: ticket:GoodQA goodqa#15759
- NEG-3 (AC-5): the existing `cp x ~/.claude/hooks/command_guard.py` and `ssh t2-dev "cp x ~/.claude/hooks/command_guard.py"` and the mv form stay blocked, and `cp x ~/.claude/hooks/` stays allowed. Source: ticket:GoodQA goodqa#15759

Domain-gate: backup-before-delete waived (no data is deleted; the guard only refuses a copy over a protected file, and refusing is the safe direction)
Domain-gate: unpushed-work-detection waived (no checkout or branch is removed)
Domain-gate: dry-run-diff waived (the change is a command-text refusal; nothing is removed or replaced)
Domain-gate: scope-pinning waived (the rule judges the literal destination path against the existing protected-path classes of the guard; it adds no path list of its own)
Domain-gate: cross-host-approval-portability waived (no approval is involved; a copy to another host is refused by the same rule whichever host it names)
Domain-gate: idempotent-retry waived (a refusal changes nothing, so a retry is the same decision)
Domain-gate: pre-account-hijack waived (no authentication or account flow is involved)
Domain-gate: lookalike-identifier waived (no accounts are involved; host names are not matched, only the path after the colon)
Domain-gate: request-device-binding waived (no login or approval link is involved)
Domain-gate: link-expiry-single-use waived (no emailed link or token is involved)
Domain-gate: session-fixation waived (no sessions are involved)
Domain-gate: rate-limit-enumeration waived (no account lookup is involved)
Domain-gate: store-billing-exposure waived (no billing or entitlement is involved)
Domain-gate: device-identity-binding waived (the guard reads command text; it enrols nothing and binds nothing to a device)
Domain-gate: unattended-recovery waived (a one-shot refusal in a hook with no resident agent)
Domain-gate: grant-durability waived (no grants or approvals are involved)
Domain-gate: remote-exec-audit waived (the guard refuses a command before it runs; the sanctioned route ah install-files audits both ends, goodqa#15742)
Domain-gate: factory-reset-guard waived (no device wipe or unenroll is involved)
Domain-gate: idempotency-key waived (no money movement is involved)
Domain-gate: double-submit waived (no money movement or form is involved)
Domain-gate: currency-precision waived (no amounts are involved)
Domain-gate: refund-reversal-path waived (no money movement is involved)
Domain-gate: ledger-reconciliation waived (no ledger is involved)
Domain-gate: authorization-vs-capture waived (no payments are involved)
Domain-gate: derived-gate-floor-with-ratchet waived (no release gate or count floor is involved)
Domain-gate: artifact-inventory-mirrored waived (no signed artifact is built)
Domain-gate: self-update-e2e waived (no updater is involved; the rule takes effect when the installer puts command_guard.py on a host)
Domain-gate: transport-proof waived (the guard analyses text; no transport is used by this change)
Domain-gate: rollback-not-blocked waived (reverting this change is a plain revert; the rule refuses a copy, it gates no rollback)
Domain-gate: staging-exists waived (the change is verified by the tests against the real guard and by the broken variants; main checks it on the live guard after install)

## Resource budget

Host: mac
Fan-out: agents=2 jobs=1 processes=2 browser_pages=0 test_workers=1
Peak memory: 0.3 GB (method: unit tests calling the guard in process)
CPU: 1 core (method: the new suite takes under a second, the guard suite a few minutes)
Disk: 0.01 GB (method: temporary copies of the hooks directory for the broken variants)
Network: 0 MB (method: the guard reads command text only)
Wall time: 60 min
Cap and kill: foreground; no external command is run
Checkpoint: not required (under 10 min per step); every step is idempotent and a run resumes by being rerun (tests only read the guard)

## Risks

- A rule used by every session can block a legitimate copy: mitigation, only the tiers `log` and `unknown` that already refuse a local `cp`, downloads and ordinary destinations pass, and the tests pin the allowed forms.
- A directory source hides a hook file inside it: stated limit, as with the existing `cp` rule; the guard sees command text only and the sanctioned route is the one that is audited.
- A single-letter host alias followed by a slash or backslash (`C:/x`) is read as a Windows drive path, not a remote operand: stated limit (L7).
- sftp batch commands and any other program that speaks ssh itself stay invisible to a command-text guard: stated limit, accident prevention and not an access control.

## Reviews

Spec core sha256: `a8afeb831a128b0afdd62558f6383f581086312ab25fd05245fbe0de6996d090`

| Role | Verdict | Reviewer | Kind | Source | Bound to |
|---|---|---|---|---|---|
| adversarial | ACCEPT | a0c568dfa08e7eb86 (red-team) | agent | WAL-verified red-team agent | stale |
| acceptance | ACCEPT | a5d878417503c1093 (red-team) | agent | WAL-verified red-team agent | stale |
| adversarial | ACCEPT | a0c568dfa08e7eb86 (red-team) | agent | WAL-verified red-team agent | current |
| acceptance | ACCEPT | a5d878417503c1093 (red-team) | agent | WAL-verified red-team agent | current |
