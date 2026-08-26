#!/usr/bin/env bash
# Fails if anything is not formatted the way `mojo format` would write it.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

before=$(find src tests bench -name '*.mojo' -exec shasum {} \; | shasum)
pixi run mojo format -q src tests bench > /dev/null
after=$(find src tests bench -name '*.mojo' -exec shasum {} \; | shasum)

if [ "$before" != "$after" ]; then
    echo "Formatting differences found. Run: pixi run format" >&2
    git --no-pager diff --stat 2>/dev/null || true
    exit 1
fi
echo "formatting is clean"
