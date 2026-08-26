"""Explicitly wipe values from memory.

A plain `x = 0` on a value nothing reads again is a dead store, and the
optimizer is entitled to delete it — which is what happens to naive attempts at
wiping. These write through a volatile store, which the compiler must emit.
`tools/check_scrub.sh` verifies that at the assembly level.

This is defence in depth. It does not protect a secret while it is in use, only
shortens how long a copy lingers afterwards — in a core dump, or in a page that
later gets swapped.
"""

from .constants import State


@always_inline
def scrub_u8(mut x: UInt8):
    Pointer(to=x).unsafe_store[volatile=True](0, UInt8(0))


@always_inline
def scrub_u32(mut x: UInt32):
    Pointer(to=x).unsafe_store[volatile=True](0, UInt32(0))


@always_inline
def scrub_state(mut s: State):
    """SIMD lanes are not individually addressable, so reach the underlying
    words through a bitcast of the vector's address."""
    var p = Pointer(to=s).unsafe_bitcast[UInt32]()
    for i in range(8):
        p.unsafe_store[volatile=True](i, UInt32(0))
