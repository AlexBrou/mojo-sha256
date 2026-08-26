"""The SHA-256 hasher, and the backend selection behind it."""

from std.bit import byte_swap
from std.memory import unsafe_memcpy
from std.sys.info import CompilationTarget

from .constants import (
    BLOCK_SIZE,
    Block,
    DIGEST_SIZE,
    Digest,
    State,
    initial_state,
)
from .portable import compress as compress_portable
from .scrub import scrub_state, scrub_u8
from .arm import compress as compress_arm


struct Backend:
    """Which compression routine to use.

    `AUTO` resolves at compile time to the fastest available. Name a backend
    explicitly to pin it — the tests do this to check every backend agrees, and
    it is the escape hatch for a target where `has_neon()` is true but the
    SHA-2 crypto extension is absent.
    """

    comptime AUTO = 0
    comptime PORTABLE = 1
    comptime ARM = 2


@always_inline
def _resolve[backend: Int]() -> Int:
    """Which backend `AUTO` means on this target.

    Apple silicon is the only aarch64 target selected automatically, because it
    is the only one where the SHA-2 crypto extension is guaranteed to be part
    of the compilation target.

    `has_neon()` is NOT a sufficient test, and using it was a bug: it is true on
    a generic aarch64 target — a Debian arm64 container, for instance — where
    the crypto extension is not enabled. Emitting the intrinsic there does not
    fall back or produce a slow path, it fails instruction selection and
    **aborts the compiler**:

        LLVM ERROR: Cannot select: intrinsic %llvm.aarch64.crypto.sha256h

    Other ARM parts that do have the extension (Graviton, most server-class
    aarch64) can opt in by pinning `Backend.ARM`, provided the build targets a
    CPU that advertises it — `-mcpu=neoverse-n1` or similar. See `arm.mojo`.
    """
    comptime if backend != Backend.AUTO:
        return backend
    comptime if CompilationTarget.is_apple_silicon():
        return Backend.ARM
    return Backend.PORTABLE


@always_inline
def arm_backend_available() -> Bool:
    """Whether `Backend.ARM` can be compiled for this target.

    Pinning `Backend.ARM` where this is False aborts the compiler rather than
    failing gracefully, so tests and any conditional use should gate on it.
    """
    return CompilationTarget.is_apple_silicon()


struct Sha256[backend: Int = Backend.AUTO](Copyable, Movable):
    """Streaming SHA-256.

    ```mojo
    var h = Sha256()
    h.write(first)
    h.write(second)
    var d = h.digest()          # InlineArray[UInt8, 32], no allocation
    ```

    A hasher is single-use: `digest()` applies the padding, so writing again
    afterwards is meaningless. Build a new one instead.
    """

    var s: State
    var buf: Block
    var buf_len: Int
    var total: UInt64

    def __init__(out self):
        self.s = initial_state()
        # Left uninitialized deliberately: nothing reads a byte of `buf` that
        # write() or the padding in _finish() has not set first.
        self.buf = Block(uninitialized=True)
        self.buf_len = 0
        self.total = 0

    @always_inline
    def _compress(mut self):
        comptime if _resolve[Self.backend]() == Backend.ARM:
            compress_arm(self.s, self.buf)
        else:
            compress_portable(self.s, self.buf)

    def write(mut self, data: Span[UInt8, _]):
        """Absorb more input. Any number of calls, any sizes."""
        var n = len(data)
        self.total += UInt64(n)
        var i = 0

        if self.buf_len != 0:
            var take = BLOCK_SIZE - self.buf_len
            if take > n:
                take = n
            unsafe_memcpy(
                dest=Pointer(to=self.buf[self.buf_len]),
                src=data.unsafe_ptr(),
                count=take,
            )
            self.buf_len += take
            i = take
            if self.buf_len == BLOCK_SIZE:
                self._compress()
                self.buf_len = 0

        while n - i >= BLOCK_SIZE:
            unsafe_memcpy(
                dest=Pointer(to=self.buf[0]),
                src=data.unsafe_ptr().unsafe_offset(i),
                count=BLOCK_SIZE,
            )
            self._compress()
            i += BLOCK_SIZE

        var rest = n - i
        if rest != 0:
            unsafe_memcpy(
                dest=Pointer(to=self.buf[self.buf_len]),
                src=data.unsafe_ptr().unsafe_offset(i),
                count=rest,
            )
            self.buf_len += rest

    def _finish(mut self):
        """FIPS 180-4 section 5.1.1: append 0x80, pad with zeros, then the
        message length in bits as a big-endian 64-bit value."""
        var bits = self.total * 8
        self.buf[self.buf_len] = 0x80
        self.buf_len += 1

        if self.buf_len > 56:
            while self.buf_len < BLOCK_SIZE:
                self.buf[self.buf_len] = 0
                self.buf_len += 1
            self._compress()
            self.buf_len = 0

        while self.buf_len < 56:
            self.buf[self.buf_len] = 0
            self.buf_len += 1
        for i in range(8):
            self.buf[56 + i] = UInt8((bits >> UInt64(56 - 8 * i)) & 0xFF)
        self._compress()
        self.buf_len = 0

    def digest(mut self) -> Digest:
        """The 32-byte digest, without touching the heap."""
        self._finish()
        # The digest is the state in big-endian order: one vector byte-swap
        # and one store, rather than 32 shift-and-mask steps.
        var out = Digest(uninitialized=True)
        Pointer(to=out[0]).unsafe_bitcast[UInt32]().unsafe_store[width=8](
            0, byte_swap(self.s)
        )
        return out^

    def hexdigest(mut self) -> String:
        return _hex(self.digest())

    def clear(mut self):
        """Wipe the state and the block buffer.

        The buffer matters as much as the state: it holds the tail of whatever
        was hashed, which for keyed constructions is key material. Uses
        volatile stores, because a plain assignment to a value nothing reads
        again is a dead store the optimizer deletes.
        """
        scrub_state(self.s)
        for i in range(BLOCK_SIZE):
            scrub_u8(self.buf[i])
        self.buf_len = 0
        self.total = 0


def sha256[backend: Int = Backend.AUTO](data: Span[UInt8, _]) -> Digest:
    """One-shot SHA-256."""
    var h = Sha256[backend]()
    h.write(data)
    return h.digest()


comptime _HEX = "0123456789abcdef"


def _hex(d: Digest) -> String:
    var out = String()
    for i in range(DIGEST_SIZE):
        var v = Int(d[i])
        out += _HEX[byte=v >> 4]
        out += _HEX[byte=v & 0xF]
    return out^
