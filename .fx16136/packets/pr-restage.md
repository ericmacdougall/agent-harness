# PR review packet: bugtracker-harness restage of the job-image runtime (goodqa#16136)

Ticket: GoodQA goodqa#16136
Repo: ericmacdougall/bugtracker-harness (the lane harness, ~/repos/harness), branch fix/16136-job-images, draft PR #73
Base: 1786659bb29d39c8facf1b2ed88fdd8d45d4845d (origin/main of bugtracker-harness; not agent-harness)
Expected HEAD: 82b0fb2a9c5acf9fc096b9b0da97f787542d3037
Precedent: 300ddb0a1 (restage plus RELEASE_BINDING rebind)

## Scope
- config/goodqa-release/bin/rw-ship.sh: now byte-equal to bugtracker c6b303aee61c:infra/release-harness/rw-ship.sh.
- config/goodqa-release/bin/selfhost-ctl.py: now byte-equal to the same commit's selfhost-ctl.py.
- config/goodqa-release/bin/RELEASE_BINDING:
  - commit changes from 5a78109ac2d3d4a63bc4891b0e1533f66e578208 to c6b303aee61cdeba2ff8e3784764d6d5c3bb1e74;
  - rw-ship.sh changes from 9ae87fb9557aee822fdcacb766cce51ff44b2cfdf33dbba540a42b49fa727eef to 2443b0da41ec6169f4cc716c06af49f347bd351054dba758d290554b47a06ef9;
  - selfhost-ctl.py changes from 36ab26af033b4094c95128b1c3be9ca5c96e5cb8b827a0a88459efa8a8af11da to 757890c0b84171f700c1797a61b33b83d84f25b4b38897ca20573116cb04a5de;
  - rw-runtime.sh, rw-rollback.sh and ship-fast.sh are unchanged (byte-identical at the bound commit).
- Before-shas: rw-ship.sh 9ae87fb9557a, selfhost-ctl.py 36ab26af033b, RELEASE_BINDING 8b6ece07713a. After: RELEASE_BINDING 4957441b367c.

The code under review is bugtracker PR #1370 (packet pr-rh.md, HEAD c6b303aee61c). This packet covers only the byte equality and the binding.

## Claims to verify
1. Each staged file equals `git show c6b303aee61c:infra/release-harness/<file>` in bugtracker.
2. RELEASE_BINDING keeps the 7-line format, and each hash matches its staged file.
3. The keyed main-push blocks in the staged rw-ship.sh are byte-identical to bin/rw-ship.sh, and the keyed suite passes against the staged file.

## Evidence (t2-dev)

```
$ python -B -m pytest -q -p no:cacheprovider bin/test_goodqa_staged_rw_ship_keyed.py
4 passed in 14.84s
keyed exit 0
```

```
$ python -B bin/test-goodqa-release-unit.py
Ran 15 tests in 2.880s
OK
unit exit 0
```

## Risks
- ship.conf has no RELEASE_BINDING today (the ship log says UNBOUND), so the binding is recorded, not enforced.
- Once it is enforced, releases need c6b303aee61c reachable. The annotated tag release-16136-rh on bugtracker origin pins it.
- Today's binding names 5a78109, which no remote ref holds (noted on goodqa#16146).
- The staged copy of test_rw_ship_selfhost.py is left unchanged. It was already older than the base; the reviewed tests live in the bound commit.
- Merging syncs the live runtime binding. Deploy goes only through the release runner after merge, on main's authorization, and in the same release as bugtracker PR #1369 (the guard).
