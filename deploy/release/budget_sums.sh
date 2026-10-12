#!/bin/sh
# deploy/release/budget_sums.sh — the §67.2 memory budget check (ADR-0066 D-E, RF-11; gate c39_budget_sums, and step 1
# of a5_load_remeasure.sh with the measured MemTotal).
# Caller: the chain gate c39_budget_sums (N = 22528, the A5 band floor) and deploy/release/a5_load_remeasure.sh.
# Usage: budget_sums.sh --mem-total-mib N [--compose FILE] SIZING_ENV [OTHER_SIZING_ENV ...]
# Inputs: N = the host's MemTotal in MiB (measured, never nominal); SIZING_ENV = the profile whose sum is checked;
#   every further file must carry exactly SIZING_ENV's key set; --compose FILE (prod.yml) additionally requires every
#   *_MEM budget line but the parse-sandbox peak to be some service's `mem_limit:`, and every live `mem_limit:` /
#   `memswap_limit:` line of FILE to read a HUMAUX_SIZE_*_MEM key of SIZING_ENV.
# Output: one `budget: …` line (sum, reserve) and one `budget: fail …` line per violation; no secret (the files hold none).
# Exit: 0 = reserve = N - sum >= 4096 and every key-set / compose check holds; 1 = a violation; 2 = usage.
set -u
usage() { echo "usage: budget_sums.sh --mem-total-mib N [--compose FILE] SIZING_ENV [OTHER_SIZING_ENV ...]" >&2; exit 2; }
N=; COMPOSE=
while [ $# -gt 0 ]; do
  case $1 in
    --mem-total-mib) [ $# -ge 2 ] || usage; N=$2; shift 2 ;;
    --compose) [ $# -ge 2 ] || usage; COMPOSE=$2; shift 2 ;;
    --*) usage ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] || usage
case $N in ''|*[!0-9]*) usage ;; esac
# §67.2 "OS + page cache + backup spike 预留 >= 4 GiB".
RESERVE_MIN=4096
MAIN=$1; shift
for f in "$MAIN" "$@" ${COMPOSE:+"$COMPOSE"}; do [ -r "$f" ] || { echo "budget: fail — cannot read $f"; exit 1; }; done
keys() { grep -E '^[A-Z0-9_]+=' "$1" | cut -d= -f1 | sort; }
fails=0
SUM=$(grep -E '^HUMAUX_SIZE_[A-Z0-9_]+_MEM=' "$MAIN" | cut -d= -f2 | awk '{ s += $1 } END { print s + 0 }')
RES=$((N - SUM))
echo "budget: $MAIN sum(HUMAUX_SIZE_*_MEM)=${SUM} MiB mem_total=${N} MiB reserve=${RES} MiB (need >= $RESERVE_MIN)"
if [ "$RES" -lt "$RESERVE_MIN" ]; then echo "budget: fail — reserve ${RES} MiB < $RESERVE_MIN MiB"; fails=1; fi
for other in "$@"; do
  if [ "$(keys "$MAIN")" != "$(keys "$other")" ]; then
    echo "budget: fail — key sets differ: $MAIN vs $other"; fails=1
  fi
done
if [ -n "$COMPOSE" ]; then
  LIVE=$(grep -v '^[[:space:]]*#' "$COMPOSE")
  for k in $(grep -E '^HUMAUX_SIZE_[A-Z0-9_]+_MEM=' "$MAIN" | cut -d= -f1); do
    [ "$k" = HUMAUX_SIZE_PARSE_SANDBOX_PEAK_MEM ] && continue
    n=$(printf '%s\n' "$LIVE" | grep -cE "^[[:space:]]*mem_limit:[[:space:]]*[\"]?[\$][{]$k:[?]")
    [ "$n" -ge 1 ] || { echo "budget: fail — $k is no service's mem_limit in $COMPOSE"; fails=1; }
  done
  bad=$(printf '%s\n' "$LIVE" | grep -E '^[[:space:]]*(mem_limit|memswap_limit):' | grep -cvE '[$][{]HUMAUX_SIZE_[A-Z0-9_]+_MEM:[?]')
  [ "$bad" = 0 ] || { echo "budget: fail — $bad mem_limit/memswap_limit line(s) in $COMPOSE do not read a HUMAUX_SIZE_*_MEM key"; fails=1; }
fi
[ $fails = 0 ] && echo "budget: pass"
exit $fails
