#!/bin/sh
# deploy/release/snapshot.sh — the sha of a commit whose tree is exactly the working tree (ADR-0066 D-A, ruling R-3).
# Caller: the chain gates release_build / c39_image_build / rehearse_c39 (HUMAUX_BUILD_GIT_SHA=$(sh snapshot.sh)), the
#   S8 build runs (`build.sh $(sh snapshot.sh) --unreleased`) and the rehearsal's UPGRADE build (`--child`).
# Usage: snapshot.sh [--child <sha40>]
# Inputs: the repository this script lives in (its working tree as `git add -A` sees it: tracked + untracked, minus
#   .gitignore). --child <sha40>: make a distinct commit of the same tree whose parent is <sha40> (the rehearsal's
#   "upgrade" build: same code, another burned-in sha, other image IDs, §5).
# What it writes: blob/tree/commit OBJECTS only (like `git stash create`), through a temporary index. It never moves a
#   ref, never touches the real index or HEAD, never runs `git commit` / `stash` / `reset` (E-12, R-3). `git gc` may
#   prune an unreferenced snapshot later (L-16); production builds are commits on main (build.sh refuses others).
# Determinism: when the tree equals HEAD^{tree} it prints HEAD itself. Otherwise `git commit-tree <tree> -p HEAD` with
#   author and committer `humaux-snapshot` and both dates set to HEAD's committer date, so the same tree gives the same
#   sha on every run; --child uses the same identity and dates with -p <sha40>.
# Output (stdout): one 40-hex sha. Nothing else on stdout; no file content and no secret is printed.
# Exit: 0 = sha printed; 1 = a git step failed; 2 = usage (bad --child argument).
set -eu
usage() { echo "usage: snapshot.sh [--child <sha40>]" >&2; exit 2; }
PARENT=
case $# in
  0) ;;
  2) [ "$1" = --child ] || usage; PARENT=$2
     printf '%s' "$PARENT" | grep -Eqx '[0-9a-f]{40}' || { echo "snapshot.sh: --child needs a 40-hex sha: $PARENT" >&2; exit 2; } ;;
  *) usage ;;
esac
REPO=$(cd "$(dirname "$0")/../.." && pwd)
cd "$REPO"
HEAD=$(git rev-parse --verify HEAD^{commit})
[ -z "$PARENT" ] || git cat-file -e "$PARENT^{commit}" || { echo "snapshot.sh: --child $PARENT is not a commit" >&2; exit 2; }
TMP_INDEX=$(mktemp "${TMPDIR:-/tmp}/humaux-snapshot-index.XXXXXX")
trap 'rm -f "$TMP_INDEX"' EXIT
trap 'exit 143' TERM INT
# A copy of the real index (stat cache only: no hash work for unchanged files); the real index is only read.
cp "$(git rev-parse --git-path index)" "$TMP_INDEX"
GIT_INDEX_FILE=$TMP_INDEX git add -A
TREE=$(GIT_INDEX_FILE=$TMP_INDEX git write-tree)
if [ -z "$PARENT" ] && [ "$TREE" = "$(git rev-parse HEAD^{tree})" ]; then
  echo "$HEAD"
  exit 0
fi
DATE=$(git show -s --format=%cI HEAD)
export GIT_AUTHOR_NAME=humaux-snapshot GIT_AUTHOR_EMAIL=humaux-snapshot@localhost GIT_AUTHOR_DATE="$DATE"
export GIT_COMMITTER_NAME=humaux-snapshot GIT_COMMITTER_EMAIL=humaux-snapshot@localhost GIT_COMMITTER_DATE="$DATE"
if [ -n "$PARENT" ]; then
  echo "humaux snapshot: child of $PARENT (same tree, distinct build identity)" | git commit-tree "$TREE" -p "$PARENT"
else
  echo "humaux snapshot of the working tree on $HEAD" | git commit-tree "$TREE" -p "$HEAD"
fi
