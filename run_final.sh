#!/bin/sh
# On t2-dev: failing-first (new check vs clean 720afec archive on 8798), then the new check, npm and python tests on the clean final archive (8799).
export CHROMIUM="$HOME/.cache/ms-playwright/chromium-1228/chrome-linux64/chrome"
PY="$HOME/mobile-ui/venv/bin/python"
cd "$HOME/mobile-nav-final"
BASE=https://127.0.0.1:8798 PW_FILE=.pw $PY test/mobile/mobile_check_new.py --label ff > "$HOME/failfirst-720afec.log" 2>&1
cd "$HOME/mobile-nav-v3"
BASE=https://127.0.0.1:8799 PW_FILE=.pw $PY test/mobile/mobile_check.py --label final --shots shots > final-run.log 2>&1
npm test > final-npm.log 2>&1
python3 -m unittest discover -s test -p '*_test.py' > final-py.log 2>&1
echo done > "$HOME/mobile-nav-v3/final-done"
