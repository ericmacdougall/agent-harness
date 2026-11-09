# Source proof for t2-course PR #52 (drop `routes`, set `workers_dev:false`, `preview_urls:false`)

Claim: with `routes` absent and `workers_dev=false`, `preview_urls=false`, `wrangler deploy` (wrangler 4.92.0, the version pinned in t2-course package.json) does not call the zone-routes or custom-domain publish APIs, and does not clear or override the existing custom-domain attachment.

Source under review: the npm tarball `wrangler@4.92.0`, extracted read-only at
`/Users/eric/.agent-harness/scratch/claude-501/-Users-eric/baab765b-d85c-46b4-b7b9-588eb912c770/scratchpad/wr/package/wrangler-dist/cli.js` (bundled; `src/triggers/deploy.ts` and `src/deploy/deploy.ts` are inside it). Line numbers below are lines of that file.

## Trigger step: `triggersDeploy(props)` starts at line 290943

1. Line 290946: `const routes = props.routes ?? config.routes ?? (config.route ? [config.route] : []) ?? [];`
   With no `routes` in config, no `route`, and no `--route` / `--domain` flags (the `deploy` npm script passes none), `routes` is `[]`. In `deploy()` the same value feeds `allDeploymentRoutes` at lines 307962-307967 (`props.domains` is empty without `--domain`).
2. Lines 290947-290955: the loop that sorts `routes` into `routesOnly` and `customDomainsOnly`; with `[]` both stay empty.
3. Line 291145-291146 (`getSubdomainValues`): `defaultWorkersDev = routes.length === 0` is true, but `workers_dev = config_workers_dev ?? defaultWorkersDev` keeps the explicit config value `false`. Line 291148: `preview_urls = config_preview_urls ?? default` keeps `false`. So this is why the config sets both explicitly: without `workers_dev:false`, an empty `routes` would make wrangler turn workers.dev ON.
4. Lines 291212-291237 (`subdomainDeploy`): the only network calls here are `GET {workerUrl}/subdomain` and `POST {workerUrl}/subdomain` with body `{ enabled: false, previews_enabled: false }`. `workerUrl` is the worker's own `/accounts/{id}/workers/scripts/{name}` URL. This touches the workers.dev and preview flags only. It is the same call the failed deploy already made successfully (the failure came after it).
5. The zone-routes listing is not reached: line 290994 `if (!wantWorkersDev && workersDevInSync && routes.length !== 0) {` is false because `routes.length === 0`. That block is the ONLY place that lists zone routes (`GET /zones/{id}/workers/routes`, at line 291015; the helper `getRoutesForZone` at 290515 is not on this path). This is the call that returned the 403 "No access to the specified resource" on 2026-11-09 07:41Z. Hence the failure disappears.
6. Line 291053: `if (routesOnly.length > 0) { ... publishRoutes(...) }` is false, so `publishRoutes` (defined at 308631) is not called.
7. Line 291068: `if (customDomainsOnly.length > 0) { ... publishCustomDomains(...) }` is false. `publishCustomDomains` (defined at 307861) has exactly one caller, line 291070 (grep `publishCustomDomains(` finds only the definition and that call). The code that could replace or clear a worker's domains lives only inside it: `override_scope: true` at 307863 and `POST ${workerUrl}/domains/changeset?replace_state=true` at 307887, then `PUT ${workerUrl}/domains/records` at 307930. None of that runs when the list is empty, so the existing attachment of `learnai.ericmacdougall.com` is neither re-applied nor replaced nor removed.
8. Lines 291075-291135: schedules (`config.triggers?.crons`), queue producers/consumers and workflows. The t2-course config has none of these, so no further trigger calls are made.
9. Lines 291137-291141: `const targets = await Promise.all(deployments); ... if (deployments.length > 0) { logger.log("Deployed ... triggers") ... } else { logger.log("No deploy targets for", workerName, formatTime2(deployMs)); }`. `deployments` stays empty (nothing pushed: `workersDevURL` is only pushed when `wantWorkersDev`, line 291276), so wrangler prints the line `No deploy targets for learnai-field-lab <time>` at line 291141 and returns.

## Other places that mention domains or delete things

- `grep 'workers/domains'` finds: the SDK client class (lines 119759-119839, not used by deploy), `workers/domains/records?...service=` at 233932 (a read inside a different function, the config download for `last_deployed_from === "dash"`), and 307904 (a read inside publishCustomDomains). There is no `DELETE .../workers/domains` call on the deploy path.
- `deploy()` at 307955 reads `/accounts/{id}/workers/services/{name}` (line 307970). If `script.last_deployed_from === "dash"` it diffs the remote config against local (307976-307985). The last deploy came from wrangler (today's deploy), so that branch is not taken.

## What this does NOT prove

- It does not prove what Cloudflare's server does with an existing custom domain when a new script version is uploaded; the argument is that the deploy sends no domain request at all. After merge, the verifying deploy must show `No deploy targets for learnai-field-lab` in the output, exit code 0, and the domain still serving (3 media URLs, a lesson page, the home page).
- It does not cover a wrangler other than 4.92.0; `package.json` pins `"wrangler": "4.92.0"`.
