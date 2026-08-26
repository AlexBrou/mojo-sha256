"""GPU batch throughput against one CPU core, across batch sizes.

The point of this benchmark is to find where the GPU starts to win, which is
the only thing that decides whether it is worth using.
"""

from std.time import perf_counter_ns

from sha256.core import Backend, Sha256
from sha256.gpu import GpuHasher


def _pad(s: String, width: Int) -> String:
    var out = s
    while out.byte_length() < width:
        out += " "
    return out^


def _rate(count: Int, ns: Int) -> String:
    if ns == 0:
        return _pad("n/a", 16)
    return _pad(String(Int(Float64(count) * 1.0e9 / Float64(ns))), 16)


def main() raises:
    var g = GpuHasher()
    print("GPU:", g.device_name())
    print()
    print(
        _pad("batch", 12)
        + _pad("CPU portable", 16)
        + _pad("CPU ARMv8", 16)
        + _pad("GPU", 16)
        + "verdict"
    )
    print()

    var total = UInt64(0)
    comptime L = 32
    for count in [4096, 16384, 65536, 262144, 1048576]:
        var data = List[UInt8](capacity=count * L)
        for i in range(count):
            for j in range(L):
                data.append(UInt8((i * 31 + j) & 0xFF))

        var sink = UInt64(0)

        var best_p = 0
        for r in range(3):
            var t0 = perf_counter_ns()
            for i in range(count):
                var h = Sha256[Backend.PORTABLE]()
                h.write(Span(data)[i * L : (i + 1) * L])
                sink += UInt64(h.digest()[0])
            var ns = perf_counter_ns() - t0
            if r == 0 or ns < best_p:
                best_p = ns

        var best_a = 0
        for r in range(3):
            var t0 = perf_counter_ns()
            for i in range(count):
                var h = Sha256[Backend.ARM]()
                h.write(Span(data)[i * L : (i + 1) * L])
                sink += UInt64(h.digest()[0])
            var ns = perf_counter_ns() - t0
            if r == 0 or ns < best_a:
                best_a = ns

        var best_g = 0
        for r in range(3):
            var t0 = perf_counter_ns()
            var out = g.hash_batch(data, L, count, check_size=False)
            var ns = perf_counter_ns() - t0
            if r == 0 or ns < best_g:
                best_g = ns
            sink += UInt64(out[0])

        var verdict = "GPU wins" if best_g < best_a else "CPU wins"
        print(
            _pad(String(count), 12)
            + _rate(count, best_p)
            + _rate(count, best_a)
            + _rate(count, best_g)
            + verdict
        )
        total += sink

    # Printed so the hashing above cannot be discarded as dead code; without
    # this the CPU loops vanish and the comparison is meaningless.
    print()
    print("(checksum", total, ")")
