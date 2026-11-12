# PR review packet: the guard blocks shell reads of the GoodQA user token and gq-browser lease keys (agent-harness PR 221, GoodQA goodqa#15785)

Base: 617cfed675c5f66e0ec8a892f69a11cfa8209b84 (merge base with origin/main, which is now 6e31891193407f3b152209ec11e56a63fa47ebba; use `--snapshot-base 617cfed675c5f66e0ec8a892f69a11cfa8209b84`). Head: a65fdcbd331382437f77fe73cfd1707b89901869 (branch af9e-gq-credential-paths). Claude-authored: `--author-harness claude`.
Changed code paths: harness/hooks/command_guard.py (two entries in credential_path_regexes, two in credential_samples), tests/test_command_guard_gq_credentials.py (new), notes/goodqa-15785/ (spec.md, review-opus.md, review-sonnet.md). The last commit adds only review reports.

## Outcome
An agent shell can no longer print `~/.config/goodqa/user-token` (the user's GoodQA token, which acts as the user) or `~/.agent-harness/gq-browser/<16 hex>/key` (a minted agent key, valid up to 24 hours) with cat, head, base64 and the other readers the guard already treats as secret reads, nor with a glob that expands to either file. The gq-browser client reads the files in-process and is unaffected (the guard only sees shell command text). This is accident prevention, not an access control.

## Design
Two path regexes (`(^|/)\.config/goodqa/user-token$`, `(^|/)\.agent-harness/gq-browser/[0-9a-f]{16}/key$`) in `credential_path_regexes` judge literal paths; the guard judges a glob only against `credential_samples`, so a sample for each path (`{home}/.config/goodqa/user-token`, `{home}/.agent-harness/gq-browser/0000000000000000/key`) was added too. The `~/.config/goodqa` directory is NOT a credential directory: `config.json` and `ls` stay allowed.

## Spec, reviews, decisions
Spec attached to goodqa#15785 (comment 2305636d); the ticket (routed to this owner by Main, filed by agent af5c4fdee8ff981f2 while building PR 220) asked for the two regex entries. Owner addition, labelled: the credential_samples entries (needed for globs). Reviews (Opus adversarial, Sonnet acceptance): at 94fef137 both BLOCK for the glob gap (`cat ~/.agent-harness/gq-browser/*/key` was allowed); fixed at 475a8295; both ACCEPT at 475a8295. Stage acceptances, not PR signoff. Not a user decision; no unconfirmed product choice.

## Failing-first and risk table
`python3 -B -m unittest tests.test_command_guard_gq_credentials`: three tests. On the unchanged code (origin/main) 26 literal forms FAIL (13 reader spellings for each of the two paths: cat, head -c, base64, tail, strings, less, xxd, `$HOME`, absolute and quoted paths, grep, sed, awk); the glob test failed (`*/key`, `*/k*`, `goodqa/*`, `user-tok*`, `user-to?en`) until the samples were added. Allowed neighbours are pinned: `ls ~/.agent-harness/gq-browser/*`, config.json, `ls`, the lease file, a key directory that is not 16 hex characters, a file named `keys`, `echo user-token`, docs that mention the name, `user-token.md`.
Stated limits (the same as for the existing credential files): `cp` to a readable name and a later cat of the copy in another command, `export TOK=$(cat F)` and a later `echo $TOK`, an archive piped to a reader, a glob inside an already known 16-hex key directory. Possible later improvement (reviewer): judge a glob against the credential regex rather than one sample path.

Risk and rollback: revert the commit; the change only adds refusals for two file names. Coordination: the docs line and the AC-8 pin in PR 220 (docs/gq-browser.md, tests/test_gq_browser.py) are updated by that owner after this merges; this PR does not touch them.

## Validation (exact head a65fdcbd331382437f77fe73cfd1707b89901869; code as at 475a8295, the later commit adds only notes/)
$ python3 -B -m unittest tests.test_command_guard tests.test_command_guard_owned_checkout tests.test_command_guard_no_backup tests.test_command_guard_gq_credentials
Ran 230 tests in 78.309s
OK
exit 0
