Follow-up to goodqa#15759 (scp and rsync into a remote harness path), lows from the independent code review at 126aa692. None blocks the PR; all are conservative false refusals.

- L8: scp is given rsync's trailing-slash "contents" meaning. `scp -r d/ t2-dev:~/` is refused although scp copies d itself. Restrict the "contents" meaning to rsync.
- L9: `rsync -a d/ t2-dev:~/` is refused unconditionally. It could probe whether d/.claude exists locally before refusing.
- L10: an option value that looks remote after the destination (`... t2-dev:/tmp/ --max-alloc t2-dev:~/.claude/hooks/command_guard.py`) is refused. Conservative.
- Stated limits unchanged: `t2-dev:$D` (a variable in the path) is allowed and a heredoc fed to sftp is not seen.

Acceptance: a test for each allowed form (L8, L9 where the local probe says no .claude) and the refused forms stay refused; a mutant for each.
