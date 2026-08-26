"""The portable SHA-256 compression function.

Runs anywhere, including inside a GPU kernel: no intrinsics, no heap, no
64-bit-only operations. Fully unrolled with a 16-word rolling message
schedule — the obvious `for i in range(64)` over a 64-word schedule measured
four times slower, because the working variables never stay in registers.
"""

from std.bit import byte_swap

from .constants import K, Block, State


@always_inline
def _rotr(x: UInt32, n: UInt32) -> UInt32:
    return (x >> n) | (x << (32 - n))


def compress(mut state: State, block: Block):
    """Absorb one 64-byte block into `state`."""
    # One bulk load plus an explicit byte swap, rather than sixteen
    # shift-and-or groups.
    #
    # Deliberately NOT `from_bytes[big_endian=True]`: that flag is ignored when
    # this compiles for Metal, so the GPU backend silently produced
    # little-endian words and wrong digests. `byte_swap` is an explicit
    # operation and behaves the same on both. (Both targets are little-endian,
    # which is what makes the swap the right direction here.)
    var wv = byte_swap(SIMD[DType.uint32, 16].from_bytes(block))
    var w = InlineArray[UInt32, 16](uninitialized=True)
    comptime for i in range(16):
        w[i] = wv[i]

    var a = state[0]
    var b = state[1]
    var c = state[2]
    var d = state[3]
    var e = state[4]
    var f = state[5]
    var g = state[6]
    var h = state[7]

    comptime for i in range(64):
        comptime j = i & 15
        comptime if i >= 16:
            comptime j1 = (j + 1) & 15
            comptime j9 = (j + 9) & 15
            comptime j14 = (j + 14) & 15
            var s0 = _rotr(w[j1], 7) ^ _rotr(w[j1], 18) ^ (w[j1] >> 3)
            var s1 = _rotr(w[j14], 17) ^ _rotr(w[j14], 19) ^ (w[j14] >> 10)
            w[j] = w[j] + s0 + w[j9] + s1

        comptime ki = K[i]
        var t1 = (
            h
            + (_rotr(e, 6) ^ _rotr(e, 11) ^ _rotr(e, 25))
            + ((e & f) ^ (~e & g))
            + ki
            + w[j]
        )
        var t2 = (_rotr(a, 2) ^ _rotr(a, 13) ^ _rotr(a, 22)) + (
            (a & b) ^ (a & c) ^ (b & c)
        )
        h = g
        g = f
        f = e
        e = d + t1
        d = c
        c = b
        b = a
        a = t1 + t2

    state[0] += a
    state[1] += b
    state[2] += c
    state[3] += d
    state[4] += e
    state[5] += f
    state[6] += g
    state[7] += h
