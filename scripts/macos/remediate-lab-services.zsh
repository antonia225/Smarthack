#!/bin/zsh
set -euo pipefail

services_dir="${1:-${0:A:h}/../../lab/services}"
state_path="$services_dir/remediation-state.txt"
: > "$state_path"

if pids="$(pgrep -f 'simulators\.py' || true)" && [[ -n "$pids" ]]; then
  for pid in ${(f)pids}; do
    ps -p "$pid" -o pid=,command= >> "$state_path"
    kill -TERM "$pid"
  done
fi

(cd "$services_dir" && docker compose stop mqtt simulators)

print "Remediere aplicata / Remediation applied. Starea este în / State is in $state_path"
print "Verificați / Verify: lsof -nP -iTCP:23 -sTCP:LISTEN; lsof -nP -iTCP:1883 -sTCP:LISTEN"
