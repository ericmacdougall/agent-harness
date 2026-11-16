# PR review packet (delta only): PR #1372 receipt pr1372-v1 BLOCK fix, the residue threshold in UTF-8 bytes

Ticket: GoodQA goodqa#16185 (parent goodqa#16148). Source: main's exact-head receipt receipts/bugtracker-pr1372-v1.md, BLOCK.
- The finding: `apps/job-dispatcher/src/docker.ts` compared `value.length`, which counts UTF-16 code units, against the 8-byte MIN_WINDOW.
- So a secret under 8 code units but at least 8 UTF-8 bytes skipped the encoded-form checks, and its base64, hex or decimal-byte echo passed through in full.

Repo: ericmacdougall/bugtracker
Reviewed before: #1372 at c9d61ac1aa3a575781e5e5fc9430bee993be1e86
Expected HEAD: 80b26c7eeba20f9fa716fa7e2a8221d31f32cc31 (#1372, fast-forward on fix/16185-docker-failure-category)

Commits in this delta:
- 80b26c7eeba2 (#1372) fix(job-dispatcher): count the residue threshold in UTF-8 bytes

Also, outside this delta: #1373 (fix/16148-job-envfile) took it as merge commit 5dd6865c06499c30df6051d9ebf62a60e0ab294a.
- It is the parent 97bfac51 plus a merge of 80b26c7e, and it auto-merged with no conflict.
- Its #1373 suite at 5dd6865c: `npx vitest run` gives 375 passed and 14 skipped.

## Claims to verify
1. `byteLength(v)` is `Buffer.byteLength(v, 'utf8')`, and it is the only measure compared with MIN_WINDOW:
   - in `hasResidueIn`, so every value of at least 8 bytes gets every encoded-form window check;
   - in the whole-stderr redaction filter and its sort in `describeDockerFailure`.

   No `value.length` comparison against MIN_WINDOW remains.
2. A value under 8 bytes keeps the exact-token rule (NEG-17: short base values never shred a line), unchanged.
3. For a fake secret of 6 code units and 18 bytes, and one of 4 code units and 8 bytes, each echoed as base64, base64 at the other alignment, hex, HEX and decimal bytes in an allow-listed guard line, the message is exactly `docker run failed: guard_refused (stderr N bytes)`.
4. The same holds through the server's real 422 path (buildServer with the real dockerRunDetached): the body error is exactly the category and byte count. Neither the body nor any log line holds a 12-char piece of any encoded form.
5. Fail first: on c9d61ac1, 11 of the new cases fail. The leaked output was visible, for example `(got 56eY5a+G6Y215YCk5YWt5a2X)` in the 422 body. A broken variant that keeps the filter fix but puts the residue check back on `value.length` also fails those 11. No earlier test changed.

## Evidence (t2-dev)
At c9d61ac1 with only the new tests: `npx vitest run test/docker-failure-message.test.ts`: 11 failed, 41 passed (52).

At HEAD 80b26c7eeba20f9fa716fa7e2a8221d31f32cc31 (clean, 31G free):

```
$ cd apps/job-dispatcher && timeout 300 npx vitest run test/docker-failure-message.test.ts
      Tests  52 passed (52)
$ cd apps/job-dispatcher && timeout 600 npx vitest run
 Test Files  13 passed | 1 skipped (14)
      Tests  331 passed | 14 skipped (345)
$ cd apps/job-dispatcher && npx tsc --noEmit -p .
exit 0 (no output)
$ (broken variant: line 268 back to value.length) npx vitest run test/docker-failure-message.test.ts
      Tests  11 failed | 41 passed (52)
```

## Delta diff (c9d61ac1..80b26c7e)
