#!/bin/sh
# Runs `safe-router anchor` against the real log, then commits and pushes
# the resulting head.json to the off-box anchor remote (SPEC.md §11 Q4).
# Never touches the log itself — `anchor` already refuses to write a head
# over a broken chain (see src/main.rs anchor_cmd), so a failure here means
# nothing gets pushed, which is the correct fail-closed behavior.
#
# The daemon never runs this — it's a separate offline process on purpose
# (CLAUDE.md: no off-box connection from a running plane process).
set -eu

SAFE_ROUTER_HOME="${SAFE_ROUTER_HOME:-$HOME/.safe-router}"
BIN="$SAFE_ROUTER_HOME/bin/safe-router"
HEAD_FILE="$SAFE_ROUTER_HOME/anchor/head.json"
REPO_DIR="$SAFE_ROUTER_HOME/anchor-repo"
# No default: an unset remote must fail, not push somewhere unintended.
REPO_URL="${ANCHOR_REPO_URL:?set ANCHOR_REPO_URL to your anchor remote}"

"$BIN" anchor

if [ ! -d "$REPO_DIR/.git" ]; then
    git clone "$REPO_URL" "$REPO_DIR"
fi

cd "$REPO_DIR"
git pull --ff-only origin main
cp "$HEAD_FILE" head.json

if [ -z "$(git status --porcelain -- head.json)" ]; then
    echo "anchor-push: head.json unchanged, nothing to push"
    exit 0
fi

id=$(jq -r '.id' head.json)
ts=$(jq -r '.ts' head.json)

git add head.json
git commit -m "anchor row $id ($ts)"
git push origin main
echo "anchor-push: pushed row $id"
