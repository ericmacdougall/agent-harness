#!/bin/bash
# goodqa#16148: broken variants of apply-job-secrets-host.py must each fail its tests (non-vacuous).
# Run from the step-2 worktree root after the file is committed; restores it after each variant.
set -u
F=infra/selfhost/app/apply-job-secrets-host.py
variant() {
  local name="$1" old="$2" new="$3"
  python3 -I - "$F" "$old" "$new" <<'EOF'
import sys
p, old, new = sys.argv[1:4]
s = open(p).read()
assert s.count(old) >= 1, old
open(p, 'w').write(s.replace(old, new))
EOF
  echo "$name: $(bash infra/selfhost/app/run_derive_tests.sh 2>&1 | grep -E '^(OK|FAILED)' | tr '\n' ' ')"
  git checkout -q -- "$F"
}
variant "H1 no compose validation" "                validate_compose(a.dir, probe)" "                pass"
variant "H2 compose written before env" "        if new_env != env:
            replace_file(edfd, 'dispatcher.env', new_env, est, hooks)
        if hooks and hooks.get('between_files'):
            hooks['between_files']()
        if new_comp != comp:
            replace_file(ddfd, 'compose.yaml', new_comp, cst, hooks)" "        if new_comp != comp:
            replace_file(ddfd, 'compose.yaml', new_comp, cst, hooks)
        if hooks and hooks.get('between_files'):
            hooks['between_files']()
        if new_env != env:
            replace_file(edfd, 'dispatcher.env', new_env, est, hooks)"
variant "H3 backup overwrites" "    write_new(dfd, name + BACKUP_INFIX + stamp, data, 0, 0, 0o600)" "    try:
        os.unlink(name + BACKUP_INFIX + stamp, dir_fd=dfd)
    except FileNotFoundError:
        pass
    write_new(dfd, name + BACKUP_INFIX + stamp, data, 0, 0, 0o600)"
variant "H4 restore drops later lines" "    return b'\\n'.join(lines[:i] + lines[i + 1:])" "    return b'\\n'.join(lines[:i]) + b'\\n'"
variant "H5 ignores other services" "    if sum(1 for l in lines if '/etc/goodqa/job-secrets' in l or '64910' in l)" "    if False and sum(1 for l in lines if '/etc/goodqa/job-secrets' in l or '64910' in l)"
variant "H6 follows links" "os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK" "os.O_RDONLY | os.O_NONBLOCK"
echo "restored: $(git status --short "$F" | wc -l) changed"
