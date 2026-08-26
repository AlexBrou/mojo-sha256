"""Throughput of each backend.

Every loop chains its output into the next input. Without that the optimizer
hoists the whole call out of the timing loop and the benchmark measures
nothing — which is easy to miss, because the result looks spectacular.
"""

from std.time import perf_counter_ns

from sha256.core import Backend, Sha256, sha256
from sha256.constants import Digest


def _pad(s: String, width: Int) -> String:
    var out = s
    while out.byte_length() < width:
        out += " "
    return out^


def _rate(count: Int, ns: Int) -> String:
    if ns == 0:
        return _pad("n/a", 16)
    var per_sec = Float64(count) * 1.0e9 / Float64(ns)
    return _pad(String(Int(per_sec)), 16)


def _mbs(count: Int, msg_len: Int, ns: Int) -> String:
    if ns == 0:
        return "n/a"
    var mb = Float64(count * msg_len) / (1024.0 * 1024.0)
    return String(Int(mb * 1.0e9 / Float64(ns))) + " MB/s"


def bench_cpu[backend: Int](name: String, msg_len: Int, iters: Int) -> Int:
    var msg = List[UInt8](capacity=msg_len)
    for i in range(msg_len):
        msg.append(UInt8((i * 7 + 3) & 0xFF))

    var best = 0
    var sink = UInt64(0)
    for round in range(5):
        var t0 = perf_counter_ns()
        for _ in range(iters):
            var h = Sha256[backend]()
            h.write(msg)
            var d = h.digest()
            # chain: the next message depends on this digest
            msg[0] = d[0]
            sink += UInt64(d[1])
        var ns = perf_counter_ns() - t0
        if round == 0 or ns < best:
            best = ns
    print(
        "  " + _pad(name, 22) + _rate(iters, best) + _mbs(iters, msg_len, best)
    )
    _ = sink
    return best


def main() raises:
    print("SHA-256 throughput, hashes/sec (best of 5 rounds)")
    print()

    for msg_len in [32, 64, 1024]:
        print(_pad("message size: " + String(msg_len) + " bytes", 30))
        var iters = 200000 if msg_len <= 64 else 20000
        var p = bench_cpu[Backend.PORTABLE]("CPU portable", msg_len, iters)
        var a = bench_cpu[Backend.ARM]("CPU ARMv8 SHA-2", msg_len, iters)
        if p > 0 and a > 0:
            var ratio = Float64(p) / Float64(a)
            print("  " + _pad("ARM speedup", 22) + String(ratio) + "x")
        print()
