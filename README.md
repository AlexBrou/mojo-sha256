# mojo-sha256

SHA-256, HMAC-SHA256 and the RFC 6979 DRBG in pure Mojo, with a
hardware-accelerated CPU backend on ARM and an experimental GPU backend.

- **Hardware SHA-2 on ARM.** The ARMv8 crypto extension, reached through LLVM
  intrinsics — about 6x the portable implementation, and close to what the
  instructions can do.
- **A portable backend** that runs anywhere, including inside a GPU kernel: no
  intrinsics, no heap, no 128-bit arithmetic.
- **No allocation** on the hashing path. State is fixed-size arrays, digests
  come back as `InlineArray[UInt8, 32]`.
- **GPU batching** — see the status note below before reaching for it.

### Status

**There is no x86 backend.** On x86 you get the portable implementation, which
is correct and tested but roughly 6x slower than what SHA-NI could do. Writing
one is not hard — it would mirror `arm.mojo` using `llvm.x86.sha256rnds2` and
friends — but there is no x86 machine here to verify it on, and an unverified
crypto backend is worse than none. See [Backends](#backends).

**The GPU backend is a work in progress.** It is correct — checked against the
CPU for every message length it accepts — but it has only ever run on one
device, the integrated GPU of an Apple M2, and on that device it only overtakes
a single CPU core past about a million messages. It has never been run on a
discrete GPU or on CUDA. Treat it as something to experiment with rather than
something to depend on; the [numbers and caveats](#gpu-batching-work-in-progress)
are below.

## Install

Add the repository as a dependency and point the compiler at `src/`:

```
mojo run -I path/to/mojo-sha256/src your_program.mojo
```

Or precompile it once:

```
mojo precompile src/sha256 -o sha256.mojopkg
```

Note that a `.mojopkg` is tied to the compiler version that produced it, so it
is a build-time convenience rather than a distribution format.

Requires Mojo 1.0 and the `max` package (for the GPU backend only). Both are
installed by `pixi install`.

## Usage

### Hashing

```mojo
from sha256 import sha256, Sha256

# one shot
var digest = sha256(data)              # InlineArray[UInt8, 32]

# streaming, for data you do not have all at once
var h = Sha256()
h.write(header)
h.write(body)
var d = h.digest()

# hex, when you want to print or compare it
var h2 = Sha256()
h2.write(data)
print(h2.hexdigest())
```

A hasher is single-use: `digest()` applies the padding, so writing afterwards is
meaningless. Build a new one.

### HMAC

```mojo
from sha256 import HmacSha256, hmac_sha256

var tag = hmac_sha256(key, message)

# or streaming
var mac = HmacSha256(key)
mac.write(part_one)
mac.write(part_two)
var tag2 = mac.digest()
```

Keys of any length work: longer than 64 bytes are hashed first, shorter are
zero-padded, per RFC 2104.

### RFC 6979 deterministic nonces

```mojo
from sha256 import Rfc6979

var rng = Rfc6979(seckey_and_message)   # the seed
var nonce = rng.generate()              # 32 bytes
var retry = rng.generate()              # the next in the sequence
```

Used by deterministic ECDSA to derive a nonce without a source of randomness.
Same seed, same stream, every time.

### Wiping secrets

Anything holding key material has `clear()`:

```mojo
var mac = HmacSha256(key)
mac.write(message)
var tag = mac.digest()
mac.clear()             # wipes both hash states
```

These use volatile stores, because a plain assignment to a value nothing reads
again is a dead store that the optimizer deletes. `tools/check_scrub.sh` checks
that at the assembly level and runs as part of the test suite.

This is defence in depth: it shortens how long a copy lingers in memory, in a
core dump or in a swapped page. It does not protect a secret while in use.

### GPU batches (experimental)

Correct but only ever benchmarked on an Apple M2; see
[Status](#status). For most workloads the ARM CPU backend is the faster choice.

```mojo
from sha256.gpu import GpuHasher

var g = GpuHasher()

# `data` holds `count` messages of `msg_len` bytes, back to back.
# Returns count * 32 bytes of digests, in the same order.
var digests = g.hash_batch(data, msg_len=32, count=1_000_000)
```

Build one `GpuHasher` and reuse it: the first call pays for shader compilation,
and the staging buffers are kept between calls and grown on demand.

Messages must fit in one block, so `msg_len` is limited to 55 bytes (64 minus
the 9 bytes SHA-256 padding needs). Longer messages are a straightforward
extension of the kernel that is not written yet.

## Backends

`Sha256` resolves its backend at compile time and you normally do not think
about it. To pin one — the tests do this, to check they agree:

```mojo
from sha256 import Sha256, Backend

var portable = Sha256[Backend.PORTABLE]()
var arm      = Sha256[Backend.ARM]()
var auto     = Sha256[Backend.AUTO]()      # the default
```

| Backend | Where it runs | Notes |
|---|---|---|
| `PORTABLE` | anywhere, including GPU kernels | unrolled, 16-word rolling schedule |
| `ARM` | aarch64 with the SHA-2 crypto extension | `sha256h`, `sha256h2`, `sha256su0/1` |
| `AUTO` | picks `ARM` where `has_neon()`, else `PORTABLE` | the default |

Two caveats on selection. Mojo exposes no `has_sha2()` predicate, so `AUTO`
uses `has_neon()` as a proxy for aarch64. The crypto extension is optional in
ARMv8-A, though present on all Apple silicon, AWS Graviton and essentially all
server-class ARM. If you hit a target with NEON but no crypto extension, pin
`Backend.PORTABLE`.

**There is no x86 SHA-NI backend.** On x86, `AUTO` resolves to `PORTABLE`:
correct, tested in CI on `ubuntu-24.04`, and roughly 6x slower than the ARM
backend on comparable hardware. Adding one means mirroring `arm.mojo` with
`llvm.x86.sha256rnds2`, `llvm.x86.sha256msg1` and `llvm.x86.sha256msg2`, then
gating it on `CompilationTarget.has_sha_ni()` if such a predicate appears, or
on an explicit opt-in until then. It is absent for one reason: there is no x86
machine here to verify it on. Contributions welcome, ideally with CI coverage
on an x86 runner.

## Performance

Apple M2, best of 5 rounds. Every loop chains its output into the next input —
without that the optimizer hoists the call out of the timing loop and the
benchmark measures nothing.

### CPU

```
pixi run bench
```

| message size | portable | ARMv8 SHA-2 | speedup |
|---|---:|---:|---:|
| 32 bytes | 5.0 M/s (153 MB/s) | **28.8 M/s** (879 MB/s) | 5.7x |
| 64 bytes | 2.6 M/s (161 MB/s) | **16.4 M/s** (1001 MB/s) | 6.2x |
| 1024 bytes | 0.32 M/s (315 MB/s) | **2.17 M/s** (2119 MB/s) | 6.7x |

### GPU batching (work in progress)

```
mojo run -I src -I . bench/bench_gpu.mojo
```

**Measured on exactly one device: the integrated GPU of an Apple M2.** Nothing
here has been run on a discrete GPU, on CUDA, or on any AMD part. The figures
below should be read as "what happened on one laptop", not as a characterisation
of the backend.

Hashing 32-byte messages, GPU against **one** CPU core:

| batch | portable CPU | ARMv8 CPU | GPU | |
|---:|---:|---:|---:|---|
| 4,096 | 5.3 M/s | **45.0 M/s** | 11.3 M/s | CPU wins 4x |
| 16,384 | 5.3 M/s | **44.9 M/s** | 25–33 M/s | CPU wins |
| 65,536 | 5.3 M/s | 44.8 M/s | 42–44 M/s | about even |
| 262,144 | 5.3 M/s | **44.7 M/s** | 37.9 M/s | CPU wins |
| 1,048,576 | 5.3 M/s | 44.2 M/s | **47–53 M/s** | GPU wins ~15% |

**On this hardware the GPU is not the obvious win it sounds like.** It only
overtakes a single ARM CPU core somewhere past a million messages, and then by
about 15%. Below 64k it loses badly. The integrated GPU shares memory bandwidth
with the CPU, and at these sizes the copies dominate — the workload is memory
bound, not compute bound.

A discrete GPU would look quite different: far more compute, but a PCIe round
trip instead of shared memory. Which way that lands is an open question, and
the honest answer is that nobody has measured it yet.

`hash_batch` warns when called with a batch below 64k, since that is nearly
always a mistake. Pass `check_size=False` to silence it.

Known gaps in the GPU backend, in rough order of how much they would matter:

- only one device tested, and it is an integrated GPU;
- messages are limited to one block (55 bytes), so it cannot hash anything
  larger;
- one message length per launch, so mixed-length batches need several calls;
- the launch configuration (`block_size = 256`) was tuned on the M2 and has not
  been revisited for any other device.

## Testing

```
./run_tests.sh                      # everything
SHA256_SKIP_GPU=1 ./run_tests.sh    # skip the GPU tests
```

27 tests. Vectors in `tests/vectors/vectors.txt` are generated by Python's
`hashlib` and `hmac` (which wrap OpenSSL) and cover:

- the FIPS 180-4 examples, and every message length from 0 to 129 bytes, so the
  padding boundaries at 55, 56 and 64 are all exercised;
- RFC 4231 HMAC vectors, including the two with 131-byte keys that force the
  hash-the-key path;
- RFC 6979 DRBG output, three values deep, so the reseed-on-retry path runs.

Each is checked on **both** CPU backends, and the backends are checked against
each other. Streaming is checked against one-shot at seven chunk sizes either
side of the 64-byte block. The GPU backend is checked against the CPU for every
message length it accepts.

## Notes

**`from_bytes[big_endian=True]` is not portable to Metal.** The flag is ignored
when the code compiles for the GPU, so words load little-endian and digests
come out wrong. Both backends use an explicit `byte_swap` instead. This is the
kind of bug that produces plausible-looking garbage rather than a crash — the
`GpuHasher` constructor runs a known-answer self-test partly for that reason,
and partly because Metal silently skips a kernel whose launch configuration is
too large rather than reporting an error.

**Constant time is not a goal here.** SHA-256 has no secret-dependent branches
or memory accesses by construction, so the CPU backends are naturally constant
time with respect to the message. But nothing has been verified against
generated assembly, and the GPU backend is explicitly not written with side
channels in mind.

## Licence

MIT. See [LICENSE](LICENSE).
