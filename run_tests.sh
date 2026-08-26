#!/usr/bin/env bash
# Runs every test module. Vector files resolve relative to the repository
# root, so run this from there.
#
# Set SHA256_SKIP_GPU=1 where there is no GPU — CI runners, containers.
set -uo pipefail
cd "$(dirname "$0")"
export PATH="$HOME/.pixi/bin:$PATH"

failed=0
for t in tests/test_*.mojo; do
    if [ "${SHA256_SKIP_GPU:-0}" = "1" ] && [ "$t" = "tests/test_gpu.mojo" ]; then
        echo "=== $t (skipped: SHA256_SKIP_GPU=1)"
        continue
    fi
    echo "=== $t"
    if ! pixi run mojo run -I src -I . "$t" "$@"; then
        failed=1
    fi
done

echo "=== tools/check_scrub.sh (secret scrubbing)"
if ! ./tools/check_scrub.sh; then
    failed=1
fi

if [ $failed -ne 0 ]; then
    echo "SOME TESTS FAILED"
    exit 1
fi
echo "ALL TESTS PASSED"
