#!/bin/sh
# deploy/release/deploy_rehearsal.sh — the runbook v2 executor (ADR-0066 §4 appendix A, rulings R-5 / R-8).
# Caller: the cheap agent of the clean-node rehearsal (its ONLY allowed shell call: `deploy_rehearsal.sh run <step-id>`,
#   plus --list / --show), the chain replay rehearse_node_c39 (TW/c39_rehearse_node.sh), the gate c39_runbook_steps
#   (--lint), and an operator on a production node.
# Usage:
#   deploy_rehearsal.sh [--runbook FILE] --list              the step ids, in runbook order, one per line
#   deploy_rehearsal.sh [--runbook FILE] --show <id>         that step's marker and block, verbatim
#   deploy_rehearsal.sh [--runbook FILE] --lint              every fenced `sh` block has a step marker, every marker a
#                                                            block, ids unique
#   deploy_rehearsal.sh [--runbook FILE] [--fault-path-extra DIR] run <id>
# Runbook contract: an executable step is a fenced ```sh block directly preceded by
#   <!-- step: <ID> expect: <exit code> [match: <fixed string>] [value: <KEY>=<ERE>] -->
#   (blank lines between marker and fence are allowed). `match:` must occur in the block's output; `value:` captures
#   the first match of <ERE> in the output, minus everything up to its first `=`, as <KEY> for later blocks.
# `run <id>`: the block runs whole, from the checkout root, as
#   env -i PATH=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin HOME=$HUMAUX_NODE_DIR/home LANG=C.UTF-8 \
#     HUMAUX_NODE_DIR=… HUMAUX_NODE_SIZING=… HUMAUX_NODE_PROJECT=… <captured KEY=VALUE…> /bin/sh -eu -c '<block>'
#   `/bin/sh` reads no ~/.zshenv (F23) and env -i drops the caller's PATH. In that same environment the executor
#   first asserts that no toolchain resolves (NOTOOLCHAIN); a toolchain on PATH refuses the step. --fault-path-extra
#   DIR prepends DIR to that PATH: the recorded red of `no_toolchain_every_step` (§5), never a production flag.
# Inputs (environment): HUMAUX_NODE_DIR (required for run: holds node.env, home/, evidence/), HUMAUX_NODE_SIZING and
#   HUMAUX_NODE_PROJECT (passed through for deploy/release/compose.sh).
# Outputs: the block's own stdout/stderr (also saved as $HUMAUX_NODE_DIR/evidence/steps/<id>.out, 0600);
#   $HUMAUX_NODE_DIR/evidence/exec.log, one line per step written by THIS script (never by the agent):
#   `STEP <id> BLOCK <sha256 of the block text> EXIT <rc> NOTOOLCHAIN <ok|FAIL> EXPECT <n>[ match=<s>] RESULT
#   <ok|mismatch> START <UTC> END <UTC>`, then `VALUE <KEY>=<value>` per captured value; captured values in
#   $HUMAUX_NODE_DIR/evidence/values.env (0600). Blocks print no secret by runbook rule; this script prints none.
# Exit: 0 = RESULT ok (or --list/--show/--lint clean); 1 = RESULT mismatch (STOP: a runbook bug, never a workaround)
#   or a --lint violation; 2 = usage, unknown step, HUMAUX_NODE_DIR unset; 3 = refused (NOTOOLCHAIN FAIL).
set -u
ROOT=$(cd "$(dirname "$0")/../.." && pwd)
RUNBOOK=$ROOT/docs/ops/runbook.md
EXTRA=
usage() { echo "usage: deploy_rehearsal.sh [--runbook FILE] (--list | --show <id> | --lint | [--fault-path-extra DIR] run <id>)" >&2; exit 2; }
while [ $# -gt 0 ]; do
  case $1 in
    --runbook) [ $# -ge 2 ] || usage; RUNBOOK=$2; shift 2 ;;
    --fault-path-extra) [ $# -ge 2 ] || usage; EXTRA=$2; shift 2 ;;
    *) break ;;
  esac
done
[ $# -ge 1 ] || usage
[ -r "$RUNBOOK" ] || { echo "deploy_rehearsal: missing object: runbook $RUNBOOK" >&2; exit 2; }

# ---- extractor (with the executor below, the only place that names a docker / Humaux / toolchain command) ----
# One record per step, fields separated by US (0x1f): id, expect, match, value, block (lines joined by RS 0x1e).
# Lint findings are LINT lines. Pure text processing. ADR-0066 §4 / R-8: an operator command exists in the runbook
# only as an executor-run block, so --lint also refuses an invocation (a line, or an inline `code` span, that
# starts with [sudo] docker / cargo / $C / a humaux-<binary> followed by arguments, or runs a deploy/ script) inside
# any other fenced block or in prose; naming a binary, a file or a service without arguments is not an invocation, and
# the executor itself (deploy_rehearsal.sh) is the one command a reader is told to run.
extract() {
  awk -v US="$(printf '\037')" -v RS_="$(printf '\036')" '
    function field(s, name,   i, rest) {
      i = index(s, name ":"); if (i == 0) return ""
      rest = substr(s, i + length(name) + 1)
      sub(/^[ ]+/, "", rest)
      sub(/[ ]+(expect|match|value):.*$/, "", rest)
      sub(/[ ]*-->.*$/, "", rest)
      return rest
    }
    function invokes(t) {
      sub(/^[ \t]*([$#][ \t]+)?/, "", t)
      if (t ~ /deploy_rehearsal\.sh/) return 0
      return t ~ /^(sudo[ \t]+)?(docker|cargo|\$C|humaux-[a-z0-9.-]+)[ \t]+[^ \t]/ || t ~ /^sh[ \t]+(\.\/)?deploy\// || t ~ /^(\.\/)?deploy\/[^ \t]*\.sh[ \t]+[^ \t]/
    }
    function spans(t,   s) {
      while (match(t, /`[^`]+`/)) {
        s = substr(t, RSTART + 1, RLENGTH - 2)
        if (invokes(s)) print "LINT invocation outside an executor block at line " NR ": " s
        t = substr(t, RSTART + RLENGTH)
      }
    }
    other && /^```[ ]*$/ { other = 0; next }
    other { if (invokes($0)) print "LINT invocation outside an executor block at line " NR ": " $0; next }
    /^<!-- step: / {
      if (pending != "") print "LINT marker without a block: " pending
      line = $0; sub(/[ ]*-->[ ]*$/, " -->", line)
      pending = field(line, "step"); exp_ = field(line, "expect"); mat = field(line, "match"); val = field(line, "value")
      if (pending == "" || exp_ !~ /^[0-9]+$/) { print "LINT malformed marker at line " NR; pending = "" }
      next
    }
    inblock && /^```[ ]*$/ { inblock = 0; print id US e US m US v US body; next }
    inblock { body = (body == "" && !started) ? $0 : body RS_ $0; started = 1; next }
    /^```sh[ ]*$/ {
      if (pending == "") { print "LINT sh block without a step marker at line " NR; skip = 1; inblock = 0; next }
      if (seen[pending]++) print "LINT duplicate step id " pending
      id = pending; e = exp_; m = mat; v = val; pending = ""; body = ""; started = 0; inblock = 1; next
    }
    skip && /^```[ ]*$/ { skip = 0; next }
    skip { next }
    /^```/ {
      if (pending != "") { print "LINT marker before a non-sh block: " pending; pending = "" }
      other = 1; next
    }
    /^[ ]*$/ { next }
    { spans($0); if (pending != "") { print "LINT marker without a block: " pending; pending = "" } }
    END {
      if (pending != "") print "LINT marker without a block: " pending
      if (inblock) print "LINT unterminated block " id
      if (other) print "LINT unterminated fence"
    }
  ' "$RUNBOOK"
}
# ---- end of extractor ----
US=$(printf '\037')
record() { extract | grep -v '^LINT ' | awk -F "$US" -v want="$1" '$1 == want'; }
block_text() { printf '%s\n' "$1" | awk -F "$US" '{ print $5 }' | tr '\036' '\n'; }

case $1 in
  --list) extract | grep -v '^LINT ' | cut -d "$US" -f1; exit 0 ;;
  --lint)
    findings=$(extract | grep '^LINT ')
    n=$(extract | grep -vc '^LINT ')
    if [ -n "$findings" ]; then printf '%s\n' "$findings"; echo "deploy_rehearsal: lint fail ($n steps)"; exit 1; fi
    echo "deploy_rehearsal: lint pass ($n steps)"; exit 0 ;;
  --show)
    [ $# -eq 2 ] || usage
    rec=$(record "$2"); [ -n "$rec" ] || { echo "deploy_rehearsal: unknown step $2" >&2; exit 2; }
    printf '%s\n' "$rec" | awk -F "$US" '{ print "<!-- step: " $1 " expect: " $2 ($3 != "" ? " match: " $3 : "") ($4 != "" ? " value: " $4 : "") " -->" }'
    echo '```sh'; block_text "$rec"; echo '```'
    exit 0 ;;
  run) [ $# -eq 2 ] || usage; ID=$2 ;;
  *) usage ;;
esac

[ -n "${HUMAUX_NODE_DIR:-}" ] || { echo "deploy_rehearsal: missing object: HUMAUX_NODE_DIR is not set" >&2; exit 2; }
rec=$(record "$ID"); [ -n "$rec" ] || { echo "deploy_rehearsal: unknown step $ID" >&2; exit 2; }
EXPECT=$(printf '%s\n' "$rec" | cut -d "$US" -f2)
MATCH=$(printf '%s\n' "$rec" | cut -d "$US" -f3)
VALUE=$(printf '%s\n' "$rec" | cut -d "$US" -f4)
BLOCK=$(block_text "$rec")
EV=$HUMAUX_NODE_DIR/evidence
umask 077
mkdir -p "$EV/steps" "$HUMAUX_NODE_DIR/home"
touch "$EV/values.env"
if command -v sha256sum >/dev/null 2>&1; then HASH=$(printf '%s\n' "$BLOCK" | sha256sum | cut -d' ' -f1)
else HASH=$(printf '%s\n' "$BLOCK" | shasum -a 256 | cut -d' ' -f1); fi
START=$(date -u +%Y-%m-%dT%H:%M:%SZ)
P=/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin
[ -n "$EXTRA" ] && P="$EXTRA:$P"
# The captured values of earlier steps, as KEY=VALUE arguments of env -i (values.env holds only such lines).
set --
while IFS= read -r kv; do case $kv in [A-Z]*=*) set -- "$@" "$kv" ;; esac; done < "$EV/values.env"
BASE="PATH=$P HOME=$HUMAUX_NODE_DIR/home LANG=C.UTF-8 HUMAUX_NODE_DIR=$HUMAUX_NODE_DIR HUMAUX_NODE_SIZING=${HUMAUX_NODE_SIZING:-} HUMAUX_NODE_PROJECT=${HUMAUX_NODE_PROJECT:-}"

# ---- executor (the only place that names a toolchain) ----
# shellcheck disable=SC2086 # BASE is a list of KEY=VALUE words without spaces
SEEN=$(env -i $BASE /bin/sh -c 'command -v cargo; command -v rustc; command -v rustup' 2>/dev/null)
if [ -n "$SEEN" ]; then
  NOTOOL=FAIL
  echo "deploy_rehearsal: refused: a toolchain resolves inside the step environment: $(printf '%s' "$SEEN" | tr '\n' ' ')" >&2
  RC=-; RESULT=mismatch
else
  NOTOOL=ok
  # shellcheck disable=SC2086
  ( cd "$ROOT" && env -i $BASE "$@" /bin/sh -eu -c "$BLOCK" ) > "$EV/steps/$ID.out" 2>&1
  RC=$?
  cat "$EV/steps/$ID.out"
  RESULT=ok
  [ "$RC" = "$EXPECT" ] || RESULT=mismatch
  if [ -n "$MATCH" ] && ! grep -qF -- "$MATCH" "$EV/steps/$ID.out"; then RESULT=mismatch; fi
fi
# ---- end of executor ----
CAPTURED=
if [ "$RESULT" = ok ] && [ -n "$VALUE" ]; then
  KEY=${VALUE%%=*}; ERE=${VALUE#*=}
  GOT=$(grep -oE -- "$ERE" "$EV/steps/$ID.out" | head -1)
  GOT=${GOT#*=}
  if [ -n "$GOT" ]; then
    grep -v "^$KEY=" "$EV/values.env" > "$EV/values.env.tmp"; echo "$KEY=$GOT" >> "$EV/values.env.tmp"; mv "$EV/values.env.tmp" "$EV/values.env"
    CAPTURED="VALUE $KEY=$GOT"
  else
    RESULT=mismatch; CAPTURED="VALUE $KEY=(no match of the value marker)"
  fi
fi
END=$(date -u +%Y-%m-%dT%H:%M:%SZ)
echo "STEP $ID BLOCK $HASH EXIT $RC NOTOOLCHAIN $NOTOOL EXPECT $EXPECT${MATCH:+ match=$MATCH} RESULT $RESULT START $START END $END" >> "$EV/exec.log"
[ -z "$CAPTURED" ] || echo "$CAPTURED" >> "$EV/exec.log"
echo "deploy_rehearsal: STEP $ID EXIT $RC NOTOOLCHAIN $NOTOOL RESULT $RESULT"
[ "$NOTOOL" = ok ] || exit 3
[ "$RESULT" = ok ] || exit 1
exit 0
