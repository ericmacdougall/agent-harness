# PR review packet: the guard refuses scp and rsync into a remote harness path (agent-harness PR 219, GoodQA goodqa#15759)

Base: 4f9f4a3971eb0c1c68ea131df60762aebb55aa6b (origin/main; use `--snapshot-base 4f9f4a3971eb0c1c68ea131df60762aebb55aa6b`). Head: 9dd379243f67dd7b6b8549c3e6d3e8c5dbcaac4b (branch af9e-scp-gap). Claude-authored: `--author-harness claude`.
Changed code paths: harness/hooks/command_guard.py (remote_copy_dest, _copy_operands, remote_paths, REMOTE_DEST, REMOTE_URL, REMOTE_DAEMON, SCP_VALUE_FLAGS, RSYNC_VALUE_FLAGS, scp added to the destructive dispatch), tests/test_command_guard_scp_dest.py, tests/mutants_scp_dest.py, notes/goodqa-15759/ (spec.md, review-opus*.md, review-sonnet*.md, ticket-local-recursive.md, ticket-lows.md). The last commit adds only review reports under notes/; code is as at 126aa692.

## Outcome
On 2026-11-11 a hook file reached t2-dev by scp after the same copy was refused as a remote cp: a second route around the guard. The guard now judges scp and rsync with a remote destination by the same rule and tiers as cp (log and unknown; ancestor only for a recursive copy or an rsync delete), with the same refusal id and text naming `ah install-files` as the sanctioned route (PR 216). This is accident prevention, not an access control.

## Design (read command_guard.py remote_copy_dest)
- Operands: option values are skipped (`_copy_operands`): long value flags, a short value flag as a lone word, a short cluster whose LAST letter is a value flag takes the next word (`-avze ssh`, `-rP 22`), an attached value (`-P22`) does not.
- Destinations: the last operand, plus every remote operand that follows a local operand (an unknown option value after the destination cannot hide it).
- Remote forms (`remote_paths`): host:path, user@host:path, [v6]:path, scp:// and sftp:// and ssh:// urls (absolute and home-relative, percent-decoded), rsync:// and host::module; an empty `host:` is the home; a path relative to the home reads as ~/relative; local paths and Windows drive paths are not remote.
- A directory destination is judged with the source names (`scp command_guard.py host:~/.claude/hooks/`); a recursive copy or an rsync --delete is judged on its EFFECTIVE write root (dest/basename(src), or dest for a trailing-slash or `.` source and for --del*), so `scp -r proj host:~/` passes and `rsync -a ./ host:~/` or `rsync -a --delete proj host:~/` are refused.
- Downloads (remote source, local destination) are untouched.

## Spec, reviews, decisions
Spec attached to goodqa#15759 (comment ec774119). Labelled owner assumptions (none is a user decision): D1 same tiers and rule as cp; D2 a directory destination is judged by the source names; D3 sftp and tar over ssh are NOT covered (their commands are not on the command line), narrowing the ticket's sftp mention; D4 the container rule applies to remote destinations only. Reviews (Opus adversarial, Sonnet acceptance): spec ACCEPT; code review rounds: Sonnet BLOCK on rsync --delete into a remote hooks directory (fixed), Opus findings M1 to M4 (fixed), then M5 (short cluster ending in a value flag, unknown option values), M6 (empty host: path) and M7 (false refusal of scp -r proj host:~/) fixed at 126aa692; both ACCEPT at 126aa692 (Opus ran about 70 extra forms, read only). These are stage acceptances, not PR signoff.
Known lows, ticketed (tc-e781904934c29ed0fa07a389c1770427): L8 scp gets rsync's trailing-slash meaning (a false refusal of `scp -r d/ host:~/`), L9 `rsync -a d/ host:~/` is not probed locally, L10 a remote-looking option value after the destination is refused. Local recursive copy into the hooks directory is a parity gap tracked as goodqa#15767. Stated limits: sftp batch commands, tar over ssh, a directory SOURCE not expanded, a variable in the remote path (`host:$D`), a single-letter host alias followed by a slash is read as a Windows path (L7).

## Failing-first and risk table
`python3 -B tests/mutants_scp_dest.py` runs the new tests against origin/main (no fix: FAILS, good) and 15 controlled broken variants, each FAILS (caught): scp not dispatched, scp branch empty, rsync not checked, relative remote path not read as home, directory destination ignores the sources, option values not skipped, cluster value flag not skipped, upload target before the last operand ignored, empty remote path skipped, container judged on the destination instead of the write root, ipv6 hosts not read, url not home-relative, url not decoded, recursive and delete into a container allowed, daemon forms ignored. Highest-risk cases and their tests: hiding the destination (options before and after, clusters, IPv6, urls, percent escapes, daemon forms, an empty path), a recursive copy or delete into a container (rsync --del*, ./ to the home, scp -r hooks host:~/.claude/), and false positives on everyday transfers (downloads, /tmp, project folders, scp -r proj host:~/, value flags that consume the destination word).

Risk and rollback: revert the commit; the rule only adds refusals for scp and rsync with a remote destination that names protected harness paths.

## Validation (exact head 9dd379243f67dd7b6b8549c3e6d3e8c5dbcaac4b, code as at 126aa692, run in the owner worktree)
$ python3 -B -m unittest tests.test_command_guard_scp_dest tests.test_command_guard
Ran 114 tests in 67.547s
OK
exit 0
$ python3 -B tests/mutants_scp_dest.py
origin/main (no fix) FAILS (good); all 15 broken variants FAILS (good); none PASSES
