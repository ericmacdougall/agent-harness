# Delta packet 2: PR #1329 (goodqa#15745) fixes for review r2-pr1329-babb2a9

Repo ericmacdougall/bugtracker, PR 1329 (draft). Head 1f4ac737826999b85fdaeecb83f35b17d9dc3db5 on feat/agent-browser-15745. Previous reviewed head babb2a9db18e6732a33c3da1a847ef44629ee084. Snapshot base (full ancestor): f1360b0944c2c8e1ef730c36dae6ece29db90a08. This commit changes only: worker.ts, workers/agent-browsers.ts, runtime.ts (one branch), both compose recipes, deploy.mjs, and tests.

## Evidence (t2-dev, runner summary lines verbatim)
```
$ AGENT_BROWSER_TRUSTED_LOCAL_TEST=1 xvfb-run -a python3 lanes/pgpool.py run --mode server -- pnpm --filter @bugtracker/api exec vitest run --maxWorkers=1 test/agent-browsers-headed.test.ts test/agent-browsers-concurrency.test.ts test/agent-browsers-tabs.test.ts test/agent-browser-worker-startup.test.ts test/agent-browsers-user-token-chain.test.ts test/mcp-e2e.test.ts   # head 1f4ac73
 Test Files  6 passed (6)
      Tests  53 passed (53)
exit 0
```
```
$ python3 lanes/pgpool.py run --mode server -- docker run --rm --network host --user node --cap-drop ALL --security-opt seccomp=infra/do/agent-browsers/seccomp.json -v <worktree>:/work gq15745-ab:r2 node vitest.mjs run test/agent-browsers.test.ts   # F3, the worker image, Chrome sandbox ON
 Test Files  1 passed (1)
      Tests  94 passed (94)
exit 0
```
```
$ AGENT_BROWSER_IMAGE=gq15745-ab:r2 xvfb-run -a python3 lanes/pgpool.py run --mode server -- pnpm --filter @bugtracker/api exec vitest run test/agent-browsers-container-stop.test.ts   # F1 and F2, production 45s grace
 Test Files  1 passed (1)
      Tests  3 passed (3)
exit 0
```
```
$ node --test infra/do/agent-browsers/deploy.test.mjs   # head 1f4ac73
# tests 279
# pass 279
# fail 0
exit 0
```

## Findings and fixes
- F1 (shutdown): the worker entry point waits for busy lanes for at most 10 s (`settle(10000)`, bounded by a timer), then `close()` closes every owned lease in parallel (`Promise.allSettled`) with a reason; a navigation or launch still running is cancelled by the runtime close. Both compose recipes set `stop_grace_period: 45s` (the broker-v1 recipe too); deploy.mjs SERVICE_KEYS allows the key and validateRecipe requires 30s to 120s for the worker; deploy.test.mjs adds short, long and missing cases (red on the prior deploy.mjs: `# fail 3`; green: 279 of 279). The container test reads the 45 s from compose.yaml, runs the real image with `--stop-timeout 45` and the production seccomp, with an idle lease, a lease mid-navigation (a 12 s page) and a just-claimed lease; `docker stop` returns inside the grace (asserted under 43 s), the exit code is not 137, all three leases end `closed`, idle and busy carry why `worker_stopped`, and no `worker_lost` row exists.
- F2 (lost display): a headed worker passes `displayCheck` (the Xvfb socket) to the worker; `tick()` returns before claiming when it fails and sets `displayLost`; the entry point then exits with code 70 and closes leases as `display_lost`, so `restart: unless-stopped` restarts the container. Unit test (a lost display never claims a pending lease; settle(800) returns false while a 15 s lane is busy): `Tests 1 failed | 4 passed (5)`, exit 1 on the prior code, 5 of 5 now. Container test: removing the display socket makes the container exit 70 with its lease closed as display_lost and a later lease never claimed (passed). No healthcheck added.
- F3 (evidence): the unfiltered `agent-browsers.test.ts` passes 94 of 94 inside the built worker image where the sandbox works, including the three sandbox-dependent tests (vault credential delivery, cookie isolation between contexts, remote MCP with a granted key). The remote MCP test pins the number of agent_browser_ tools; it failed once in this run (15 expected, 19 now because of the four tab tools, previously hidden by the sandbox failure) and is updated to 19. Image removed afterwards; t2-dev has 25 GB free.
- F4 (last-tab count): the last-tab refusal branch counts once per distinct refused URL (WeakMap), documented in the code.

## Risk and rollback
- The shutdown path of the worker changed; the container tests exercise it with real Chrome. Rollback: previous worker image tag and `AGENT_BROWSER_HEADED=0`; a `docker compose up` after the recipe change applies the new grace period.
- Not covered here: the live droplet (the same tests run on t2-dev Docker, not on DigitalOcean), and a healthcheck.
