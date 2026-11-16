goodqa#16148: this PR adds the rw-ship job-secret unhold gate. It carries the goodqa#16136 job-image forward-port (#1371) and the goodqa#16148 job env-file work (#1373).

**What it carries**
- #1371 at bff96cc5: the job images forward-ported to main, with review fixes F1 and F2.
- #1373 content: env through a private `--env-file`, the GitHub App key as the only allow-listed JOB_ENVFILE, derive-job-secrets.py, the host apply and wrapper, and the cmdline sampler.
  - This branch joins #1373 at 97bfac51. The rest of #1373's head 5dd6865c is the #1372 UTF-8 residue fix, which is already on main.
- The gate itself:
  - an optional `derive-blob` binding line in install-d2.sh;
  - rw-ship derive stream and pre-switch gates (derive, dispatcher env names, trial boot);
  - post-guard gate (c), with re-hold and restore;
  - the selfhost-ctl verbs envfile-key, disp-boot, trial-boot and up-dispatcher;
  - the dispatcher `--boot-check` flag.
- The 1370 fail-closed fixes, ported here: ac13-count.py unknown and untimed records, store_is_containerd, and job_lines/presence_check.

**Landing.** #1371, #1373 and this PR land together in one window; main decides how #1371 and #1373 are closed at merge. Do not close them from here.

**Review.** One gate receipt covers all three parts (main's ruling). The packet is `.fx16136/packets/pr-gate.md` on the harness branch fx/16148-pem-spec.

**Status.** Draft. Not merged and not deployed. The host apply and the first held release follow the landing-window order on goodqa#16148.

🤖 Generated with [Claude Code](https://claude.com/claude-code)
