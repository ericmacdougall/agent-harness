This is a follow-up from goodqa#16148 (the PEM spec v1 risk), filed at the lead's request.

**Problem.** The self-host job-dispatcher starts every job as `docker run --rm -d ... -e KEY=VALUE ... <image>` (apps/job-dispatcher/src/docker.ts, around line 191). Every job secret is passed this way: today's JOB_ENV_* values, and from #16148 on, GITHUB_APP_PRIVATE_KEY too. As a result:
- the values are in the docker CLI's process argv on the app host while it runs, readable through /proc by root and possibly by other users, depending on hidepid;
- they are in the job container's config (`docker inspect`), readable by root and the docker group;
- they pass through the create-guard, which inspects Env.

**Proposal.** Pass job env without putting values on any command line. Candidate routes are a per-launch env-file under a private tmpfs, written with mode 0400 and deleted after create, or the Engine API create call with Env in the body. Container config exposure is inherent to Env; removing it as well would need an in-container secret file. That is a larger design and main's call.

**Acceptance:**
- A launch with a fake secret leaves the value out of every process argv captured during the launch.
- No value appears in dispatcher logs.
- The create-guard still enforces its Env checks, including GUARD_HELD_ENV.
- Tests are failing-first.

**Source:** wal: lead af3f19d2 relay, 2026-11-16 ("File the docker run -e exposure follow-up ticket now and link it from #16148"). This is not the user's request. No value was read.
