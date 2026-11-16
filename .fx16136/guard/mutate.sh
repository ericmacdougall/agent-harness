#!/bin/bash
# goodqa#16136: broken-variant check for held-env.ts. Each mutation must make test/held-env.test.ts fail.
cd ~/repos/fx-16136/bt-guard/apps/job-dispatcher || exit 2
F=src/held-env.ts; cp "$F" /home/eric/repos/fx-16136/held-env.orig.ts
mut(){ python3 - "$F" "$1" "$2" <<'PY'
import sys
p, a, b = sys.argv[1:4]; t = open(p).read(); assert t.count(a) == 1, a; open(p, 'w').write(t.replace(a, b))
PY
}
run(){ name=$1; timeout 300 pnpm exec vitest run test/held-env.test.ts > /home/eric/repos/fx-16136/mut-$name.txt 2>&1; rc=$?
  echo "$name: vitest rc=$rc $(grep -E 'Tests ' /home/eric/repos/fx-16136/mut-$name.txt | sed 's/\x1b\[[0-9;]*m//g' | tr -s ' ')"
  cp /home/eric/repos/fx-16136/held-env.orig.ts "$F"; }
mut ".trim().toLowerCase() === held.value" "=== held.value"; run no-value-normalisation
mut "name.trim().toUpperCase() !== held.key" "name !== held.key"; run no-key-normalisation
mut "if (seen > 1) return" "if (false) return"; run no-repeat-refusal
mut "if (hasControlChars(value)) return" "if (false) return"; run no-control-char-refusal
mut "if (!Array.isArray(env)) return" "if (false) return"; run no-array-check
mut "if (top.Entrypoint !== undefined && top.Entrypoint !== null) {" "if (false) {"; run no-entrypoint-refusal
mut "if (!held) return null;" "return null;"; run hold-ignored
cmp -s "$F" /home/eric/repos/fx-16136/held-env.orig.ts && echo restored
