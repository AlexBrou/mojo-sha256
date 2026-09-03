"""Batch SHA-256 on the GPU. **Work in progress.**

One message per thread. The portable compression function is used verbatim —
it has no intrinsics, no heap and no 128-bit arithmetic, so it compiles for
Metal and CUDA unchanged.

Status: correct, and checked against the CPU for every message length it
accepts, but only ever run on one device — the integrated GPU of an Apple M2.
It has never been exercised on a discrete GPU, on CUDA, or on AMD. The
limitations worth knowing:

* only one device tested, and it is an integrated GPU;
* messages must fit in one block, so `msg_len` is capped at 55 bytes;
* one message length per launch, so mixed-length batches need several calls;
* `block_size = 256` was tuned on the M2 and not revisited elsewhere.

**When this is worth using.** Measured on that M2 against the ARMv8 crypto
extension on one CPU core, hashing 32-byte messages:

| batch size | CPU (ARMv8 SHA) | GPU        |
|-----------:|----------------:|-----------:|
|      4,096 |      45.0 M/s   |  11.3 M/s  |
|     65,536 |      44.8 M/s   |  42-44 M/s |
|  1,048,576 |      44.2 M/s   |  47-53 M/s |

So on this hardware the GPU only pulls ahead past about a million messages, and
then by roughly 15%. Below 64k the launch and transfer cost dominates and the
CPU wins outright. This is also not a way to make a *single* hash faster;
nothing here helps latency.

The GPU path is not written with side channels in mind, and is intended for
public data.
"""

from max.gpu.host import DeviceBuffer, DeviceContext, HostBuffer
from std.memory import unsafe_memcpy
from std.gpu import global_idx

from .constants import BLOCK_SIZE, DIGEST_SIZE, Block, Digest, initial_state
from .core import _hex
from .portable import compress

comptime Bytes = Pointer[UInt8, MutAnyOrigin]

# Below this many messages, the CPU is faster; `hash_batch` says so rather than
# silently doing the slow thing.
comptime GPU_WORTH_IT_FROM = 65536


def kernel_hash_fixed(inp: Bytes, outp: Bytes, msg_len: Int64, count: Int64):
    """Hash `count` messages of `msg_len` bytes each, one per thread.

    `msg_len` is capped at one block. Longer messages need the loop below to
    absorb several blocks, which is a straightforward extension but is not
    what this kernel is for.
    """
    var i = global_idx.x
    if Int64(i) >= count:
        return

    var n = Int(msg_len)
    var block = Block(fill=0)
    for j in range(n):
        block[j] = inp[unsafe_offset=i * n + j]

    # FIPS 180-4 section 5.1.1 padding, for a message that fits in one block
    block[n] = 0x80
    var bits = UInt64(n) * 8
    for j in range(8):
        block[56 + j] = UInt8((bits >> UInt64(56 - 8 * j)) & 0xFF)

    var state = initial_state()
    compress(state, block)

    for j in range(8):
        for b in range(4):
            outp[unsafe_offset=i * DIGEST_SIZE + 4 * j + b] = UInt8(
                (state[j] >> UInt32(24 - 8 * b)) & 0xFF
            )


struct GpuHasher(Movable):
    """Hashes many equally-sized messages at once.

    ```mojo
    var g = GpuHasher()
    var digests = g.hash_batch(flat_messages, msg_len=32, count=n)
    ```

    Build one and reuse it: the first launch pays for shader compilation.
    """

    var dev: DeviceContext
    var block_size: Int

    # Buffers are kept between calls and grown on demand. Allocating four
    # buffers per call costs more than the kernel: with per-call allocation the
    # GPU loses to one ARM CPU core at every batch size, and with reuse it wins
    # from about 256k messages.
    var cap_in: Int
    var cap_out: Int
    var h_in: HostBuffer[DType.uint8]
    var d_in: DeviceBuffer[DType.uint8]
    var d_out: DeviceBuffer[DType.uint8]
    var h_out: HostBuffer[DType.uint8]

    def __init__(out self) raises:
        self.dev = DeviceContext()
        # 256 measured best on an M2; the kernel is not register-hungry.
        self.block_size = 256
        self.cap_in = 64
        self.cap_out = 64
        self.h_in = self.dev.enqueue_create_host_buffer[DType.uint8](64)
        self.d_in = self.dev.enqueue_create_buffer[DType.uint8](64)
        self.d_out = self.dev.enqueue_create_buffer[DType.uint8](64)
        self.h_out = self.dev.enqueue_create_host_buffer[DType.uint8](64)
        self.dev.synchronize()
        self._self_test()

    def _ensure(mut self, n_in: Int, n_out: Int) raises:
        """Grow the staging buffers if this batch needs more room."""
        if n_in > self.cap_in:
            self.h_in = self.dev.enqueue_create_host_buffer[DType.uint8](n_in)
            self.d_in = self.dev.enqueue_create_buffer[DType.uint8](n_in)
            self.cap_in = n_in
        if n_out > self.cap_out:
            self.d_out = self.dev.enqueue_create_buffer[DType.uint8](n_out)
            self.h_out = self.dev.enqueue_create_host_buffer[DType.uint8](n_out)
            self.cap_out = n_out
        self.dev.synchronize()

    def device_name(mut self) raises -> String:
        return self.dev.name()

    def _self_test(mut self) raises:
        """A known-answer check that the kernel actually ran.

        A launch configuration a device cannot host is skipped *silently* by
        Metal, leaving the output buffer zeroed. Without this you would read
        that as a digest of all zeros.
        """
        var msg = String("abc")
        var got = self.hash_batch(msg.as_bytes(), 3, 1, check_size=False)
        comptime EXPECTED = (
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        )
        var digest = Digest(fill=0)
        for i in range(DIGEST_SIZE):
            digest[i] = got[i]
        if _hex(digest) != EXPECTED:
            raise Error(
                "GPU self-test failed: the kernel did not hash correctly."
                " The launch configuration (block_size="
                + String(self.block_size)
                + ") may be too large for this device."
            )

    def hash_batch(
        mut self,
        data: Span[UInt8, _],
        msg_len: Int,
        count: Int,
        check_size: Bool = True,
    ) raises -> List[UInt8]:
        """Hash `count` messages of `msg_len` bytes, laid out back to back.

        Returns `count * 32` bytes of digests, in the same order.
        """
        if msg_len < 0 or msg_len > 55:
            raise Error(
                "msg_len must be 0..55: this kernel hashes one block per"
                " message, and the padding needs 9 bytes"
            )
        if len(data) < msg_len * count:
            raise Error("data is shorter than msg_len * count")
        if count == 0:
            return List[UInt8]()
        if check_size and count < GPU_WORTH_IT_FROM:
            print(
                "sha256.gpu: batch of",
                count,
                "is below",
                GPU_WORTH_IT_FROM,
                "- the CPU backend is faster at this size",
            )

        var n_in = msg_len * count
        var n_out = count * DIGEST_SIZE
        self._ensure(n_in, n_out)

        # Bulk copy: filling a 32 MB staging buffer a byte at a time costs far
        # more than the kernel it feeds.
        if n_in > 0:
            unsafe_memcpy(
                dest=self.h_in.unsafe_ptr(), src=data.unsafe_ptr(), count=n_in
            )
        self.dev.enqueue_copy(dst_buf=self.d_in, src_buf=self.h_in)

        # Pass the `DeviceBuffer`s, not `unsafe_ptr()`. A `DeviceBuffer` is
        # `DevicePassable` and reaches the kernel as the same
        # `Pointer[UInt8, MutAnyOrigin]`, but handing over the raw pointer
        # drops the link the lifetime checker uses to keep the buffer alive
        # across an asynchronous launch.
        self.dev.enqueue_function[kernel_hash_fixed](
            self.d_in,
            self.d_out,
            Int64(msg_len),
            Int64(count),
            grid_dim=(count + self.block_size - 1) // self.block_size,
            block_dim=self.block_size,
        )

        self.dev.enqueue_copy(dst_buf=self.h_out, src_buf=self.d_out)
        self.dev.synchronize()
        var out = List[UInt8](capacity=n_out)
        # Uninitialized: the memcpy below writes every byte, and zero-filling
        # first would be a second pass over the whole result.
        out.resize(unsafe_uninit_length=n_out)
        unsafe_memcpy(
            dest=out.unsafe_ptr(), src=self.h_out.unsafe_ptr(), count=n_out
        )
        return out^
