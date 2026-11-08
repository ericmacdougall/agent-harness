#!/bin/bash
for h in dev2 mini t2-proxmox; do
  echo "== $h"
  ssh -o ConnectTimeout=6 -o BatchMode=yes "$h" 'find /home /Users /srv /opt -maxdepth 6 -path "*/.git/config" 2>/dev/null | xargs grep -l t2-course 2>/dev/null | head' 2>&1 | head -5
done
