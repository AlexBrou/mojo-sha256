#!/usr/bin/env bash
# Treats compiler warnings as failures.
#
# Mojo has no separate linter; the compiler is it. Warnings here mean unused
# assignments, deprecated APIs and similar — all worth fixing before they land.
set -uo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

OUT=${TMPDIR:-/tmp}/mojo-sha256-warn
mkdir -p "$OUT"

found=0
for f in tests/test_*.mojo; do
    # The GPU test needs a device to run, but it still has to compile.
    log="$OUT/$(basename "$f").log"
    pixi run mojo build -I src -I . -o "$OUT/out.bin" "$f" > "$log" 2>&1 || {
        echo "FAILED to build $f"
        cat "$log"
        found=1
        continue
    }
    if grep -q "warning:" "$log"; then
        echo "warnings in $f:"
        grep -A2 "warning:" "$log" | head -30
        found=1
    fi
done

if [ $found -ne 0 ]; then
    echo "compiler warnings found" >&2
    exit 1
fi
echo "no compiler warnings"
