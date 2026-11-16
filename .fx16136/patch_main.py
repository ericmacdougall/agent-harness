"""goodqa#16136 AC-18: forward-port of the job-image release-harness change onto bugtracker main's scripts.
python3 patch_main.py DIR   (DIR = infra/release-harness of a bugtracker main checkout)
Reuses patch_ctl.py and patch_ship*.py, re-anchored where main's scripts differ from b3604eae (no set-env, no keyed
push, a parallel build plan via rw-image-jobs.py)."""
import os, re, subprocess, sys
D = sys.argv[1]; HERE = os.path.dirname(os.path.abspath(__file__))


def load(name):
    return open(os.path.join(HERE, name)).read()


def run(src, target, label):
    tmp = os.path.join(HERE, '.%s.port.py' % label)
    open(tmp, 'w').write(src)
    r = subprocess.run([sys.executable, tmp, os.path.join(D, target)], capture_output=True, text=True)
    os.remove(tmp)
    if r.returncode: sys.exit('%s failed: %s' % (label, (r.stderr or r.stdout)[-600:]))
    print(r.stdout.strip())


def sub(src, old, new):
    assert src.count(old) == 1, (src.count(old), old[:80]); return src.replace(old, new)


# ---- selfhost-ctl.py
c = load('patch_ctl.py')
c = sub(c, "rep('''                                 rides in the same backed-up, fenced env file, so `restore` (and every rollback) reverts it.\n''', '''                                 rides in the same backed-up, fenced env file, so `restore` (and every rollback) reverts it.\n",
           "rep('''                                 file before (= its backup) and after the re-pin (the fence `restore` checks).\n''', '''                                 file before (= its backup) and after the re-pin (the fence `restore` checks).\n")
c = sub(c, "rep('''        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i), allowed_env=self.allowed_env())''',",
           "rep('''        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i))''',")
c = sub(c, "        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i), allowed_env=self.allowed_env(),\n                    jobs=jobs,",
           "        return dict(core, fp=fp, running=run, missing=sorted(r for r, i in ids.items() if not i),\n                    jobs=jobs,")
c = sub(c, "rep('''def pin_prepare(stk, a):\n    extra = parse_set_env(getattr(a, 'set_env', None))''', '''def parse_job_args",
           "rep('''def pin_prepare(stk, a):\n    for x in (a.api, a.web, a.disp):''', '''def parse_job_args")
c = sub(c, "def pin_prepare(stk, a):\n    extra = parse_set_env(getattr(a, 'set_env', None))\n    new_jobs, held",
           "def pin_prepare(stk, a):\n    new_jobs, held")
c = sub(c, "(docker info DriverStatus has no io.containerd.snapshotter)')''')",
           "(docker info DriverStatus has no io.containerd.snapshotter)')\n    for x in (a.api, a.web, a.disp):''')")
c = sub(c, "rep('''    pn.add_argument('--set-env', action='append', default=[], metavar='KEY=VALUE')''',\n    '''    pn.add_argument('--set-env', action='append', default=[], metavar='KEY=VALUE')\n",
           "rep('''    for k in ('--stamp', '--sha', '--deploy-id', '--api', '--web', '--disp'): pn.add_argument(k, required=True)''',\n    '''    for k in ('--stamp', '--sha', '--deploy-id', '--api', '--web', '--disp'): pn.add_argument(k, required=True)\n")
c = sub(c, "rep('''        if a.cmd == 'check-set-env': out({'set_env': parse_set_env(a.items)}); return 0''',\n    '''        if a.cmd == 'check-set-env': out({'set_env': parse_set_env(a.items)}); return 0\n",
           "rep('''        if a.cmd == 'state': out(stk.state()); return 0''',\n    '''        if a.cmd == 'state': out(stk.state()); return 0\n")
run(c, 'selfhost-ctl.py', 'ctl')

# ---- rw-ship.sh
s = load('patch_ship.py')
# the job spec loop runs before main's build plan; the plan gets the job images as extra jobs
s = sub(s, "rep('''  IFS='|' read -r -a BSARR <<< \"$BSPECS\"''', '''  JOBIMGS=(); JOBKEYS=(); HOLDARGS=\"\"; GUARDARGS=\"\"; HOLDNOTE=\"\"",
           "rep('''  python3 - \"$RD\" \"$SHA\" \"$IMG_API\" \"$IMG_WEB\" \"$IMG_DISP\" \"$PROMOTED\" \"$GATE_RECEIPT\" <<'PY_PLAN' || exit 3''', '''  JOBIMGS=(); JOBKEYS=(); JOBSPECS=(); HOLDARGS=\"\"; GUARDARGS=\"\"; HOLDNOTE=\"\"")
s = sub(s, "    BSPECS=\"$BSPECS|$J $F goodqa-$J:$TAG\"; JOBIMGS+=(\"goodqa-$J:$TAG\"); JOBKEYS+=(\"$K\")",
           "    JOBSPECS+=(\"$J=$F=goodqa-$J:$TAG\"); JOBIMGS+=(\"goodqa-$J:$TAG\"); JOBKEYS+=(\"$K\")")
s = sub(s, "  say \"job images: building ${JOBIMGS[*]:-none}; held:${HOLDNOTE:- none}\"\n  IFS='|' read -r -a BSARR <<< \"$BSPECS\"''')",
           "  say \"job images: building ${JOBIMGS[*]:-none}; held:${HOLDNOTE:- none}\"\n  python3 - \"$RD\" \"$SHA\" \"$IMG_API\" \"$IMG_WEB\" \"$IMG_DISP\" \"$PROMOTED\" \"$GATE_RECEIPT\" \"${JOBSPECS[@]}\" <<'PY_PLAN' || exit 3''')\n"
           "rep('''rd, sha, api, web, disp, promoted, receipt = sys.argv[1:]''', '''rd, sha, api, web, disp, promoted, receipt = sys.argv[1:8]''')\n"
           "rep('''    jobs.append(dict(name=app, image=image, argv=argv))\n''', '''    jobs.append(dict(name=app, image=image, argv=argv))\n"
           "for spec in sys.argv[8:]:                  # goodqa#16136: the dispatcher job images, built from the same context\n"
           "    app, dockerfile, image = spec.split('=', 2)\n"
           "    jobs.append(dict(name=app, image=image, argv=['nice', '-n', '5', 'docker', 'buildx', 'build', '--platform', 'linux/amd64', '--pull',\n"
           "                                                  '-f', dockerfile, '--label', 'org.opencontainers.image.revision='+sha, '-t', image, '--load', rd+'/src']))\n''')")
s = sub(s, "rep('''--disp \"$IMG_DISP\"$SETENV_ARGS > \"$RD/pin.txt\" 2>&1; rc=$?''', '''--disp \"$IMG_DISP\"$SETENV_ARGS$JOBARGS$HOLDARGS$GUARDARGS > \"$RD/pin.txt\" 2>&1; rc=$?''')",
           "rep('''--disp \"$IMG_DISP\" > \"$RD/pin.txt\" 2>&1; rc=$?''', '''--disp \"$IMG_DISP\"$JOBARGS$HOLDARGS$GUARDARGS > \"$RD/pin.txt\" 2>&1; rc=$?''')")
run(s, 'rw-ship.sh', 'ship')
run(load('patch_ship2.py'), 'rw-ship.sh', 'ship2')
print('forward-port applied')
