# Delta packet: PR #1329 (goodqa#15745) fixes for review r1b-pr1329-cd9484d

Repo ericmacdougall/bugtracker, PR 1329 (draft). Head babb2a9db18e6732a33c3da1a847ef44629ee084 on feat/agent-browser-15745. Previous reviewed head cd9484df670ab93ee02123a1b31fcec28ad6d55a. Snapshot base (full ancestor): f1360b0944c2c8e1ef730c36dae6ece29db90a08. The head also contains a876ef5be0a (scripts/agent-browser-lease.mjs and a chain test, not part of the reviewed findings).

## Evidence (t2-dev, runner summary lines verbatim)
```
$ AGENT_BROWSER_TRUSTED_LOCAL_TEST=1 xvfb-run -a python3 lanes/pgpool.py run --mode server -- pnpm --filter @bugtracker/api exec vitest run --maxWorkers=1 test/agent-browsers-headed.test.ts test/agent-browsers-concurrency.test.ts test/agent-browsers-tabs.test.ts test/agent-browser-worker-startup.test.ts test/agent-browsers-user-token-chain.test.ts test/mcp-e2e.test.ts   # head babb2a9db18e
 Test Files  6 passed (6)
      Tests  52 passed (52)
exit 0
$ same runner: vitest run test/agent-browsers.test.ts   # F1, head babb2a9db18e, unfiltered
      Tests  3 failed | 91 passed (94)
exit 1
$ same runner: vitest run test/agent-browsers.test.ts   # F1, base sources f1360b0944c, unfiltered
      Tests  3 failed | 91 passed (94)
exit 1
```
F1 detail: the failing test names are identical at head and base (credential delivery uses a vault reference; remote MCP uses the same granted key and returns a real PNG; real browser contexts isolate cookies). Cause at both: `FATAL ... zygote_host_impl_linux.cc:128 No usable sandbox` on t2-dev (unprivileged user namespaces are disabled by AppArmor; those 3 tests do not set trustedLocalTest). Logs on t2-dev: /home/eric/work-15745/ev2-head.log and ev2-base.log. The Chrome sandbox DOES work in the production container: see F2 below.

## Findings and fixes
- F1 (evidence): above. 91 of 94 pass at head and at base, and the worker refactor passes every non-sandbox lease test. Sandboxed Chrome under the production seccomp profile is exercised by the container test in F2.
- F2 (docker stop): apps/api/docker/agent-browsers-entrypoint.sh starts Xvfb (display number overridable by AGENT_BROWSER_DISPLAY) and `exec node`; Dockerfile CMD runs it; /tmp/.X11-unix is created 1777 for the non-root user. Test apps/api/test/agent-browsers-container-stop.test.ts (skipped unless AGENT_BROWSER_IMAGE is set) runs the real image with the production seccomp profile, cap-drop ALL, tmpfs, NODE_ENV=test and no trustedLocalTest: it opens a lease, checks navigator.userAgent has no HeadlessChrome, runs `docker stop`, and asserts an agent_browser.closed audit row with why worker_stopped. Result on the xvfb-run image: 1 failed (`expected [] to include 'worker_stopped'`, after reaching active and passing the headed check). Result on the entrypoint image: `Test Files 1 passed (1)`, `Tests 1 passed (1)`, exit 0. Images removed afterwards.
- New finding while building the image: the worker image at origin/main f1360b0944c did not start (`ERR_MODULE_NOT_FOUND tools/qa-commander/goodqa-tool-classes.mjs` imported by mcp/audited-read-rpc.ts through plugins/auth). Dockerfile.agent-browsers never copied the four tools/ contract files that apps/api/Dockerfile copies. Now copied.
- F3 (tabs): failure state is a WeakSet per tab with listeners on every tab; the only tab is never closed (it goes to about:blank and stays failed); closing the current tab leaves no current tab and actions return browser_current_tab_closed until tabs_switch or tabs_new; tabs_switch and tabs_new do not clear any failure flag (deliverCredential reads the per-tab flag). Four new tests in agent-browsers-tabs.test.ts; run against the a876ef5be0a sources with the new tests kept: `Tests 8 failed | 13 passed (21)`, exit 1 (4 tab tests plus 4 startup cases), green at head.
- F4: concurrency test file gains a route test (tabs_new with an out-of-origin URL returns 403 and creates no job) and a worker round trip for tabs_list (job succeeded, one tab).
- F5: lease cap counts openings in flight (load getter); AGENT_BROWSER_MAX_LEASES must be an integer of at least 1 (checked before the worker imports, four startup cases red on the prior entry point, green now) with default 4; the DB pool is cap plus 2. The new cap test passed on the prior code too (the race is narrow with a sequential loop); it is a regression guard, not a failing-first test.
- F6: refusedTabs is counted once per tab (WeakSet); console is captured from every tab (new test).
- Shared Xvfb display (reviewer note): all leases share one display in one container under one uid. Accepted for this slice; per-lease Xvfb would add a process per lease. Recorded in the risk section, not changed.

## Risk and rollback
- Highest risk remains the worker refactor (91 of 94 lease tests pass at head and at base). Rollback: AGENT_BROWSER_HEADED=0 and the previous worker image tag; no schema change.
- The image start path changed (entrypoint): proved only in the t2-dev container test, not yet on the live droplet.
