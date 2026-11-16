"""goodqa#16136 review F1 + F2 (receipt bth-pr73-v1). python3 patch_f1f2.py DIR  (DIR = infra/release-harness)
F1: SELFHOST_JOB_HOLD is validated as one canonical comma list (no whitespace, no empty items) and held() reads that
    same string, so an accepted value can never release a kind.
F2: `disk` measures the filesystems that hold the active runtime's data: docker's own DockerRootDir and, for a
    containerd image store, containerd's configured root. Anything unresolved refuses (fail closed). rw-ship needs
    max(SELFHOST_VM_MIN_FREE_GB, 2 x the bytes it is about to load)."""
import os, sys
D = sys.argv[1]


def patch(name, pairs):
    p = os.path.join(D, name); t = open(p).read()
    for old, new in pairs:
        assert t.count(old) == 1, (name, t.count(old), old[:90]); t = t.replace(old, new)
    open(p, 'w').write(t)


patch('rw-ship.sh', [
    ('''  JHOLD=$(shconf SELFHOST_JOB_HOLD intelligence-worker,transcribe); [ "$JHOLD" = none ] && JHOLD=""
  for h in ${JHOLD//,/ }; do case "$h" in intelligence-worker|transcribe) ;; *)
    say "ABORT: SELFHOST_JOB_HOLD has an unknown kind '$(printf '%s' "$h" | tr -dc 'a-z0-9-' | cut -c1-40)' (allowed: intelligence-worker, transcribe, none); nothing built or switched"
    dbx "$NAME" deploy-failed "$BEFORE" "bad SELFHOST_JOB_HOLD; nothing went live; run $RD"; exit 2;; esac; done
  held(){ case ",$JHOLD," in *",$1,"*) return 0;; esac; return 1; }''',
     '''  # One canonical form (review F1): "none", or kinds joined by single commas with no spaces or empty items. held() reads
  # this same validated string, so a value that is accepted can never release a kind it names.
  JHOLD=$(shconf SELFHOST_JOB_HOLD intelligence-worker,transcribe)
  if [ "$JHOLD" = none ]; then JHOLD=""
  elif ! [[ "$JHOLD" =~ ^(intelligence-worker|transcribe)(,(intelligence-worker|transcribe))*$ ]]; then
    say "ABORT: SELFHOST_JOB_HOLD '$(printf '%s' "$JHOLD" | tr -c 'a-z0-9,-' '?' | cut -c1-60)' is not none or a comma list of intelligence-worker, transcribe (no spaces, no empty items); nothing built or switched"
    dbx "$NAME" deploy-failed "$BEFORE" "bad SELFHOST_JOB_HOLD; nothing went live; run $RD"; exit 2
  fi
  held(){ case ",$JHOLD," in *",$1,"*) return 0;; esac; return 1; }'''),
    ('''  VMFREE=$(vmctl disk 2>/dev/null | grep -m1 '^{' | python3 -c 'import json,sys; print(json.load(sys.stdin)["free_gb"])' 2>/dev/null)
  [ "${VMFREE:-0}" -ge "$SH_VM_MIN_FREE_GB" ] 2>/dev/null || { say "NO DISK on the VM (infrastructure, exit 11): ${VMFREE:-?}G free on $SH_APP, $SH_VM_MIN_FREE_GB G needed before loading seven images''',
     '''  # Review F2: the VM needs room for twice what is loaded (layers plus unpacked snapshots), and at least the floor.
  LOADBYTES=0; for i in "$IMG_API" "$IMG_WEB" "$IMG_DISP" "${JOBIMGS[@]}"; do
    b=$(docker image inspect -f '{{.Size}}' "$i" 2>/dev/null); [[ "$b" =~ ^[0-9]+$ ]] || b=x; [ "$b" = x ] && { LOADBYTES=x; break; }
    LOADBYTES=$((LOADBYTES + b)); done
  if [ "$LOADBYTES" = x ]; then VMNEED=x; else VMNEED=$(( (2 * LOADBYTES + (1 << 30) - 1) >> 30 )); [ "$VMNEED" -ge "$SH_VM_MIN_FREE_GB" ] || VMNEED=$SH_VM_MIN_FREE_GB; fi
  VMDISK=$(vmctl disk 2>/dev/null | grep -m1 '^{'); VMFREE=$(printf '%s' "$VMDISK" | python3 -c 'import json,sys; print(json.load(sys.stdin)["free_gb"])' 2>/dev/null)
  say "VM image store: $(printf '%s' "${VMDISK:-unresolved}" | cut -c1-900); need ${VMNEED}G (2 x ${LOADBYTES} bytes to load, floor ${SH_VM_MIN_FREE_GB}G)"
  [ "$VMNEED" != x ] && [ "${VMFREE:-0}" -ge "$VMNEED" ] 2>/dev/null || { say "NO DISK on the VM (infrastructure, exit 11): ${VMFREE:-?}G free on $SH_APP, ${VMNEED}G needed before loading seven images'''),
])

patch('selfhost-ctl.py', [
    ('''  disk                           one JSON line {"free_gb": N}: free space where the docker store lives (before a load)''',
     '''  disk                           one JSON line {"free_gb": N, "paths": {...}}: the least free space across the filesystems
                                 that hold the active runtime's data: docker's DockerRootDir and, with the containerd image
                                 store, containerd's configured root (`containerd config dump`). Refused (exit 3) when any
                                 of them cannot be resolved or measured.'''),
    ('''    def store_is_containerd(self):''',
     '''    def store_roots(self):
        """Review F2: the data roots the runtime itself reports; anything unresolved refuses."""
        r = docker('info', '-f', '{{.DockerRootDir}}', timeout=60)
        root = r.stdout.strip() if r.returncode == 0 else ''
        if not root.startswith('/') or '\\n' in root: raise Refused('cannot resolve the docker data root (docker info DockerRootDir)')
        roots = [root]
        if self.store_is_containerd():
            try: c = subprocess.run(['containerd', 'config', 'dump'], capture_output=True, text=True, timeout=60)
            except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot run containerd config dump: %s' % type(e).__name__)
            m = re.search(r'^root\\s*=\\s*(["\\x27])([^"\\x27\\n]+)\\1\\s*$', c.stdout, re.M) if c.returncode == 0 else None
            if not m or not m.group(2).startswith('/'): raise Refused('cannot resolve the containerd root (containerd config dump)')
            roots.append(m.group(2))
        return roots

    def free_gb(self, path):
        try: r = subprocess.run(['df', '-Pk', path], capture_output=True, text=True, timeout=60)
        except (OSError, subprocess.SubprocessError) as e: raise Refused('cannot measure %s: %s' % (path, type(e).__name__))
        rows = [l.split() for l in r.stdout.strip().split('\\n')[1:]] if r.returncode == 0 else []
        if len(rows) != 1 or len(rows[0]) < 6 or not rows[0][3].isdigit(): raise Refused('cannot measure free space of %s' % path)
        return int(rows[0][3]) // (1 << 20)

    def store_is_containerd(self):'''),
    ('''            root = next((d for d in ('/var/lib/containerd', '/var/lib/docker') if os.path.isdir(d)), '/')
            out({'free_gb': shutil.disk_usage(root).free // (1 << 30), 'path': root}); return 0''',
     '''            paths = {p: stk.free_gb(p) for p in stk.store_roots()}
            out({'free_gb': min(paths.values()), 'paths': paths}); return 0'''),
])
print('patched F1 F2')
