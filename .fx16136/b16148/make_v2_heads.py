"""goodqa#16148 code-review delta: v2 packet heads for PR 1372 and PR 1373, from the v1 heads. Run in .fx16136."""

def sub(s, old, new):
    assert s.count(old) == 1, old[:80]
    return s.replace(old, new)

# ---- PR 1372 (goodqa#16185) ----
s = open('packets/pr-16185-head.md').read()
s = sub(s, 'Expected HEAD: 3b7cde1a97478251ff15dde8c5a9768e7b4e493b', 'Expected HEAD: c9d61ac1aa3a575781e5e5fc9430bee993be1e86')
s = sub(s, '- 3b7cde1a9747 test(job-dispatcher): capture server logs in the held 422 case\n',
        '- 3b7cde1a9747 test(job-dispatcher): capture server logs in the held 422 case\n'
        '- c9d61ac1aa3a fix(job-dispatcher): cut the stderr line before the residue scan (code review F4)\n')
s = sub(s, '6. The tests are not vacuous: two broken variants each fail. (NEG-5)\n',
        '6. The tests are not vacuous: two broken variants each fail. (NEG-5)\n'
        '7. F4 (code review a5a2642f, LOW): after the full-stderr redaction, which is unchanged, the first line is cut to SCAN_LIMIT 4096 before the prefix, printable and residue scans. A 1 MiB line can no longer stall the event loop, and nothing past 4096 could reach the 200-char output.\n')
s = sub(s, 'At HEAD 3b7cde1a in apps/job-dispatcher, with a clean worktree:', 'At HEAD c9d61ac1 in apps/job-dispatcher, with a clean worktree:')
s = sub(s, ' Test Files  13 passed | 1 skipped (14)\n      Tests  315 passed | 14 skipped (329)\n',
        ' Test Files  13 passed | 1 skipped (14)\n      Tests  319 passed | 14 skipped (333)\n')
s = sub(s, '- After: `npx vitest run` (apps/job-dispatcher) gives 13 files passed, 1 skipped; 315 tests passed, 14 skipped.',
        '- F4 fail first: on the 3b7cde1a docker.ts with the four new tests, `npx vitest run test/docker-failure-message.test.ts` gives 2 failed and 38 passed. The two failures are the 1 MiB case (1909 ms against a 1000 ms bound) and the deterministic case (a fragment past 4096 used to drop the line). After the fix: 40 passed.\n'
        '- After: `npx vitest run` (apps/job-dispatcher) gives 13 files passed, 1 skipped; 319 tests passed, 14 skipped.')
s = sub(s, '## Source diff (apps/job-dispatcher/src only; the test file is on the branch)',
        '## Source diff (origin/main e9449087..c9d61ac1, apps/job-dispatcher/src only; the test file is on the branch)')
s = s.replace('# PR review packet (whole PR):', '# PR review packet v2 (whole PR, after the code-review delta):', 1)
open('packets/pr-16185-v2-head.md', 'w').write(s)

# ---- PR 1373 (goodqa#16148 step 2) ----
s = open('packets/pr-16148-head.md').read()
s = s.replace('# PR review packet (whole PR):', '# PR review packet v2 (whole PR, after the code-review delta):', 1)
s = sub(s, 'Base: 3b7cde1a97478251ff15dde8c5a9768e7b4e493b (fix/16185-docker-failure-category, draft PR #1372; stacked, merge #1372 first)',
        'Base: c9d61ac1aa3a575781e5e5fc9430bee993be1e86 (fix/16185-docker-failure-category, draft PR #1372; stacked, merge #1372 first)')
s = sub(s, 'Expected HEAD: 158ec0db4b6b0a9dbb56fdce63a05df97fc1548c', 'Expected HEAD: 97bfac5172322d3eddc3cf7d43e951421624dd67')
s = sub(s, '- 158ec0db4b6 test(selfhost): prove the job-secret mount survives a pin and rollback\n',
        '- 158ec0db4b6 test(selfhost): prove the job-secret mount survives a pin and rollback\n'
        '- f29da1848b3 fix(selfhost): fail closed on a derive swap; catch clustered -e (code review F2, F3)\n'
        '- 97bfac51723 merge of fix/16185 at c9d61ac1 (code review F4; a merge, so neither published branch is rewritten)\n')
s = sub(s, '9. The tests are not vacuous: every broken variant listed below fails.\n',
        '9. The tests are not vacuous: every broken variant listed below fails.\n'
        '10. F2 (code review a5a2642f): on a post-rename inode mismatch, derive unlinks the name (never its target), so the dispatcher sees the key as missing. Both swap tests assert that nothing is left at the target.\n'
        '11. F3: a single-dash token is read as pflag reads a shorthand cluster. The booleans d, i, t and P chain, and an e anywhere in the chain records -e(cluster), which is BAD. The first value-taking shorthand ends the chain. NEG-18 adds -de, -ieK=V and -dite.\n'
        '12. Tickets from the same review, not fixed here (lead ruling):\n'
        '    - goodqa#16195 (F1): the apply and restore write order, compose first and env last. It is a spec change, because it flips NEG-14 and H2.\n'
        '    - goodqa#16196 (F5): the root-only tests must not pass by skipping in CI.\n')
old_ev_start = s.index('At HEAD 158ec0db4b6b0a9dbb56fdce63a05df97fc1548c')
old_ev_end = s.index('```\n', s.index('```\n', old_ev_start) + 4) + 4
s = s[:old_ev_start] + open('b16148/evidence-v2-block.md').read() + s[old_ev_end:]
s = sub(s, '  - sampler: S1 keeps raw argv, S2 no cgroup filter, S3 no positive control, S4 attached short flag kept whole. All FAILED.\n',
        '  - sampler, rerun at 97bfac51: S1 keeps raw argv, S2 no cgroup filter, S3 no positive control, S4 attached short flag kept whole, and S5 e inside a cluster ignored (F3). All FAILED.\n'
        '  - F2 and F3 fail first: before the source fix, run_derive_tests.sh FAILED (failures=2, both swap tests) in the root container, and test_cmdline_sampler FAILED (failures=1, the cluster test).\n')
s = sub(s, '## Full diff (base..HEAD)', '## Full diff (base c9d61ac1..HEAD 97bfac51)')
open('packets/pr-16148-v2-head.md', 'w').write(s)
print('heads written')
