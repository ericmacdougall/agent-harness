"""goodqa#16148: broken copies of the gated rw-ship.sh. usage: python3 rwship_gate_mutants.py <rw-ship.sh> <outdir>
Each mutant must fail at least one test of test_rw_ship_jobsecret_gate.py."""
import os, sys

src, outd = sys.argv[1:3]
t = open(src).read()
M = {
    'M1-working-tree-derive': ('git -C "$REPO" cat-file blob "$b" |', 'cat "$REPO/$JS_DERIVE_PATH" 2>/dev/null |'),
    'M2-no-blob-check': ('[ "$got" = "$b" ] || { echo REFUSED-blob-mismatch; return 0; }', ':'),
    'M3-loose-derive-match': ('"0:job secret github-app-private-key: written") echo written;;', '*written*) echo written;;'),
    'M4-no-key-count': ('[ "$JSK" = 1 ] || js_refuse', 'true || js_refuse'),
    'M5-no-trial': ('[ "$JST" = ok ] || js_refuse', 'true || js_refuse'),
    'M6-no-gate-c': ('[ "$DST" = ok ] || js_hold_fail', 'true || js_hold_fail'),
    'M7-no-new-container-check': ('if [ -z "$DID" ] || [ "$DID" = "$DISP_PRE" ]; then js_hold_fail', 'if false; then js_hold_fail'),
    'M8-rollback-without-rehold': ('    infl rehold\n    js_rehold "${STAMP}h" ||', '    sh_fail_rollback "$1"; js_rehold "${STAMP}h" ||'),
    'M9-rehold-recreates-all': ('vmctl up-dispatcher --timeout "$SH_UP_TIMEOUT" > "$RD/up-$1.txt"', 'vmctl up --timeout "$SH_UP_TIMEOUT" > "$RD/up-$1.txt"'),
    'M10-held-derive-fatal': ('say "job secret (intelligence-worker held, not gated): derive $JSD"; JSGATE',
                              'case "$JSD" in written|unchanged|skipped-unbound) ;; *) js_refuse "held derive";; esac; JSGATE'),
    'M11-rehold-failure-ignored': ('js_rehold "${STAMP}h" || js_nohold', 'js_rehold "${STAMP}h" || true'),
    'M12-no-second-rehold': ('js_rehold "${STAMP}h2" || js_nohold', 'true || js_nohold'),
    'M13-unbound-derive-from-tree': ('case "${BWHY:-}" in OK*) ;; *) echo REFUSED-unbound; return 0;; esac', ':'),
    'M14-trial-by-tag': ('--image "$DREF" --stamp "$STAMP"', '--image "$IMG_DISP" --stamp "$STAMP"'),
    'M15-rehold-after-migration-skipped': ('    [ "${MIG_APPLIED:-0}" = 0 ] || mig_hold "$1 (intelligence-worker was re-held)"\n    rb_guard "rolling back ($1)" api',
                                           '    rb_guard "rolling back ($1)" api'),
}
os.makedirs(outd, exist_ok=True)
for name, (old, new) in M.items():
    assert t.count(old) >= 1, name
    open(os.path.join(outd, name + '.sh'), 'w').write(t.replace(old, new, 1))
print(' '.join(M))
