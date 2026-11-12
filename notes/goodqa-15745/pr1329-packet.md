# PR packet: goodqa#15745 slices 1 and 2 (PR #1329, draft)

Repo ericmacdougall/bugtracker. Head cd9484df670ab93ee02123a1b31fcec28ad6d55a on branch feat/agent-browser-15745. Snapshot base (origin/main at the branch point, a full ancestor): f1360b0944c2c8e1ef730c36dae6ece29db90a08.
Ticket: GoodQA goodqa#15745 (spec attached via spec_flow; this PR covers AC-1, AC-2, AC-3, AC-6, NEG-4, NEG-5 (tab cap), NEG-16). Slices not in this PR: profiles and Mac helper, live view, user-token grant and key automation (goodqa#15746).

## Changed paths (non-generated)
- apps/api/src/modules/agent-browsers/runtime.ts: `headed` and `tmpRoot` options; headed without DISPLAY throws browser_display_missing (never silent headless); DISPLAY and XAUTHORITY passed to Chrome; per-lease directory under tmpRoot used as the browser TMPDIR and removed in close() even after a crash; tabs (MAX_TABS 8, adopt/sweep/close, popup adoption under the cap, out-of-origin tabs closed and counted in refusedTabs); actions tabs_list, tabs_new, tabs_switch, tabs_close.
- apps/api/src/modules/agent-browsers/worker.ts: claimPending, openPending, processOwned extracted; tick({detach}) runs each lease in its own tracked lane (inflight map), settle(); pending leases are claimed and opened in parallel up to cap (maxRuntimes, default 8); heartbeat timer now lives for the worker lifetime and is cleared in close().
- apps/api/src/modules/agent-browsers/service.ts: tabs_new url is checked against the lease origins at queue time.
- apps/api/src/workers/agent-browsers.ts: reads AGENT_BROWSER_HEADED, AGENT_BROWSER_TMP_ROOT, AGENT_BROWSER_MAX_LEASES; runs tick({detach:true}); settle before close.
- packages/shared/src/agent-browsers.ts: four tab actions in the zod union (index 0..7).
- apps/api/Dockerfile.agent-browsers, infra/do/agent-browsers/compose.yaml and compose.broker-v1.yaml: xvfb and xauth, CMD under xvfb-run, env defaults (AGENT_BROWSER_HEADED defaults to 1, MAX_LEASES 4).
- Tests: agent-browsers-headed.test.ts, agent-browsers-concurrency.test.ts, agent-browsers-tabs.test.ts; registry/tool-count updates in mcp-e2e.test.ts, mcp-token-tool-parity.test.ts, product-expert/tool-classes.ts.
- cd9484df670 is the output of `node scripts/docs-refresh.mjs` (33 generated files).

## Failing-first and results (t2-dev, verbatim runner summaries)
```
$ AGENT_BROWSER_TRUSTED_LOCAL_TEST=1 xvfb-run -a python3 lanes/pgpool.py run --mode server -- pnpm --filter @bugtracker/api exec vitest run --maxWorkers=1 test/agent-browsers-headed.test.ts test/agent-browsers-concurrency.test.ts test/agent-browsers-tabs.test.ts test/mcp-e2e.test.ts   # head cd9484df670
 Test Files  4 passed (4)
      Tests  30 passed (30)
exit 0
$ same command, the three new test files only, source files from prior code f1360b0944c
 Test Files  3 failed (3)
      Tests  12 failed (12)
exit 1
$ same runner: vitest run test/agent-browsers.test.ts -t 'remote MCP uses|credential delivery uses|real browser contexts isolate'   # origin/main sources, baseline
      Tests  3 failed | 91 skipped (94)
exit 1
```
Typecheck: `npx tsc --noEmit -p apps/api` shows no errors in the changed files.

## Baseline failures (identical on unmodified origin/main f1360b0944c, not caused by this PR)
1. agent-browsers.test.ts, 3 tests (remote MCP real PNG, credential delivery, real browser contexts isolate): Chrome cannot start without a sandbox on t2-dev (zygote: No usable sandbox, unprivileged user namespaces disabled). Re-run with the PR changes reverted (git checkout HEAD for the two source files) fails the same 3 tests with the same error; evidence in the lane log on t2-dev at /home/eric/work-15745/last-run.log of that run.
2. mcp-token-tool-parity, qac-tool-classes, product-catalog-api-mcp-parity, commander-action-registry (5 tests): memory_about, memory_what_happened, memory_cover, memory_coverage are unexplained or unclassified; unchanged by this PR (the PR adds its four tools to those registries).
3. docs-refresh product pack step: `Unclassified MCP tool: browser_create_solve_pair` from origin/main.

## Risk and rollback
- Highest risk: worker concurrency refactor changes when jobs run. Controls: per-session lane guard (inflight map), jobs still claimed under FOR UPDATE SKIP LOCKED, existing 91 lease tests pass, tick() without detach keeps the old awaited semantics for tests.
- Headed Chrome in the production container needs the seccomp profile to allow it: unproven until a live smoke. Rollback: set AGENT_BROWSER_HEADED=0 (compose env) and restart the worker; no API or schema change.
- No migration in this PR. New MCP tools only add names.
- Deploy: API image then worker image through infra/do/agent-browsers (main directs). Health check: worker readiness, then scripted lease open, navigate to a granted public origin, `navigator.userAgent` without HeadlessChrome, screenshot, tabs_list; 4-lease parallel probe.
- Assumption labels: caps (8 tabs, per-worker lease cap 4 in compose) are ASSUMPTIONS from the spec.
