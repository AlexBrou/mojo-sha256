#!/usr/bin/env bash
# Checks that clear() survives optimization.
#
# Wiping a value nothing reads again is a dead store, and the optimizer deletes
# it. scrub.mojo writes through a volatile store to stop that. This compiles
# two functions differing only in how they wipe and inspects the assembly: the
# naive one should contain no stores, the volatile one should contain some.
set -euo pipefail
cd "$(dirname "$0")/.."
export PATH="$HOME/.pixi/bin:$PATH"

OUT=${TMPDIR:-/tmp}/mojo-sha256-scrub
mkdir -p "$OUT"

cat > "$OUT/probe.mojo" <<'MOJO'
from sha256.constants import State
from sha256.scrub import scrub_state


@no_inline
def naive_wipe() -> UInt32:
    var s = State(1, 2, 3, 4, 5, 6, 7, 8)
    var out = s[0] ^ s[7]
    s = State(0)
    return out


@no_inline
def volatile_wipe() -> UInt32:
    var s = State(1, 2, 3, 4, 5, 6, 7, 8)
    var out = s[0] ^ s[7]
    scrub_state(s)
    return out


def main():
    print(naive_wipe(), volatile_wipe())
MOJO

pixi run mojo build --emit asm -I src -o "$OUT/probe.s" "$OUT/probe.mojo" 2>/dev/null

body() {
    awk -v start="$1" '
        index($0, start) > 0 { f = 1; next }
        f && /^\t?ret/ { exit }
        f { print }
    ' "$OUT/probe.s"
}

naive=$(body 'probe::naive_wipe()' | grep -cE '^\s*(str|stp|stur|mov.*\[)' || true)
vol=$(body 'probe::volatile_wipe()' | grep -cE '^\s*(str|stp|stur)' || true)

echo "  naive wipe   : $naive store instructions (expected 0 - deleted by the optimizer)"
echo "  scrub_state(): $vol store instructions (expected > 0)"

if [ "$naive" -ne 0 ]; then
    echo "  unexpected: the naive wipe was not optimized away, so this probe is" >&2
    echo "  no longer testing what it thinks it is" >&2
    exit 1
fi
if [ "$vol" -lt 1 ]; then
    echo "  FAILED: scrub_state() was optimized away - values are not wiped" >&2
    exit 1
fi
echo "  scrubbing survives optimization"
