#!/bin/bash
# on t2-dev: list dangling (unattached) docker volumes with created date, age hours, and mountpoint size if readable. Read-only.
now=$(date +%s)
for v in $(docker volume ls -f dangling=true -q); do
  c=$(docker volume inspect "$v" --format '{{.CreatedAt}}' 2>/dev/null)
  e=$(date -d "$c" +%s 2>/dev/null || echo 0)
  mp=$(docker volume inspect "$v" --format '{{.Mountpoint}}' 2>/dev/null)
  sz=$(du -sm "$mp" 2>/dev/null | cut -f1)
  printf '%s\t%sh\t%sMB\t%s\n' "$v" "$(( (now-e)/3600 ))" "${sz:-?}" "${c:0:10}"
done
