"""SHA-256 through the ARMv8 SHA-2 crypto extension.

About sixteen times faster than the portable backend on an Apple M2 — roughly
seventy cycles per block, which is close to what the instructions can do.

Four instructions do the work. `sha256h`/`sha256h2` each perform four rounds,
and `sha256su0`/`sha256su1` between them compute four message-schedule words.
There is no LLVM documentation page for these; `IntrinsicsAArch64.td` in the
LLVM tree is the authoritative definition.

Availability: the extension is optional in ARMv8-A. It is present on every
Apple silicon part, on AWS Graviton, and on essentially all server-class ARM —
but what matters is whether the *compilation target* advertises it, not whether
the CPU has it. On a generic aarch64 target (a Debian arm64 container, say)
emitting these intrinsics aborts the compiler with

    LLVM ERROR: Cannot select: intrinsic %llvm.aarch64.crypto.sha256h

so `core.mojo` only selects this backend automatically on Apple silicon, where
the target always includes it. To use it elsewhere, pin `Backend.ARM` and build
for a CPU that advertises the extension (`-mcpu=neoverse-n1` and similar).
"""

from std.bit import byte_swap
from std.sys.intrinsics import llvm_intrinsic

from .constants import K, Block, State

comptime W = SIMD[DType.uint32, 4]


@always_inline
def _h(abcd: W, efgh: W, wk: W) -> W:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h", W](abcd, efgh, wk)


@always_inline
def _h2(efgh: W, abcd: W, wk: W) -> W:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256h2", W](efgh, abcd, wk)


@always_inline
def _su0(a: W, b: W) -> W:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su0", W](a, b)


@always_inline
def _su1(a: W, b: W, c: W) -> W:
    return llvm_intrinsic["llvm.aarch64.crypto.sha256su1", W](a, b, c)


@always_inline
def _kvec[t: Int]() -> W:
    comptime a = K[t]
    comptime b = K[t + 1]
    comptime c = K[t + 2]
    comptime d = K[t + 3]
    return W(a, b, c, d)


def compress(mut state: State, block: Block):
    """Absorb one 64-byte block into `state`."""
    var abcd = state.slice[4]()
    var efgh = state.slice[4, offset=4]()
    var abcd0 = abcd
    var efgh0 = efgh

    # The block is big-endian on the wire; load it into four vectors of four
    # words each, which is the shape su0/su1 operate on.
    # See the note in portable.mojo: an explicit byte_swap rather than the
    # big_endian flag, so both backends load blocks the same way.
    var wv = byte_swap(SIMD[DType.uint32, 16].from_bytes(block))
    var s = Array[W, 4](uninitialized=True)
    comptime for v in range(4):
        s[v] = wv.slice[4, offset=v * 4]()

    # Rounds 0-15 consume the schedule as loaded; from round 16 each group
    # rewrites the oldest vector in place and the four rotate through.
    comptime for t in range(0, 64, 4):
        comptime v = (t // 4) & 3
        comptime if t >= 16:
            s[v] = _su1(
                _su0(s[v], s[(v + 1) & 3]), s[(v + 2) & 3], s[(v + 3) & 3]
            )
        var wk = s[v] + _kvec[t]()
        var prev = abcd
        abcd = _h(abcd, efgh, wk)
        efgh = _h2(efgh, prev, wk)

    state = (abcd0 + abcd).join(efgh0 + efgh)
