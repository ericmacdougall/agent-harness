#!/bin/bash
# Lead ruling 1: the argv tripwire must fail when the worker gains an argv-derived mode, then pass once restored.
cd ~/repos/fx-16136/bt-guard || exit 2
I=apps/transcoder/src/index.ts; cp "$I" ~/repos/fx-16136/index.orig.ts
python3 - "$I" <<'PY'
import sys
p = sys.argv[1]; t = open(p).read(); old = "  const mode = transcoderMode(process.env);"
assert t.count(old) == 1
open(p, 'w').write(t.replace(old, "  const mode = process.argv.includes('--mode=transcribe') ? 'transcribe' : transcoderMode(process.env);"))
PY
cd apps/job-dispatcher
timeout 300 pnpm exec vitest run test/held-env.test.ts > ~/repos/fx-16136/argv-variant.txt 2>&1; echo "broken variant (argv mode): rc=$? $(grep -E 'Tests ' ~/repos/fx-16136/argv-variant.txt | sed 's/\x1b\[[0-9;]*m//g' | tr -s ' ')"
cp ~/repos/fx-16136/index.orig.ts ../transcoder/src/index.ts
timeout 300 pnpm exec vitest run test/held-env.test.ts > ~/repos/fx-16136/argv-green.txt 2>&1; echo "restored: rc=$? $(grep -E 'Tests ' ~/repos/fx-16136/argv-green.txt | sed 's/\x1b\[[0-9;]*m//g' | tr -s ' ')"
cd ~/repos/fx-16136/bt-guard && git status --short
