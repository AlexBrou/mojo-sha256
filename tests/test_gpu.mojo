"""The GPU batch backend, checked against the CPU."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from sha256.core import sha256, _hex
from sha256.gpu import GpuHasher
from tests.vec import hex_to_bytes, load


def test_device_available() raises:
    var g = GpuHasher()
    assert_true(g.device_name().byte_length() > 0)


def test_matches_cpu() raises:
    var g = GpuHasher()
    comptime N = 4000
    comptime L = 32
    var data = List[UInt8](capacity=N * L)
    for i in range(N):
        for j in range(L):
            data.append(UInt8((i * 31 + j * 7 + 5) & 0xFF))

    var digests = g.hash_batch(data, L, N, check_size=False)
    assert_equal(len(digests), N * 32)
    for i in range(N):
        var msg = List[UInt8]()
        for j in range(L):
            msg.append(data[i * L + j])
        var expect = sha256(msg)
        for j in range(32):
            assert_equal(
                Int(digests[i * 32 + j]),
                Int(expect[j]),
                "mismatch at message " + String(i),
            )


def test_known_vectors() raises:
    """Every one-block vector from the shared file, hashed as a batch."""
    var g = GpuHasher()
    var msgs = List[List[UInt8]]()
    var expected = List[String]()
    for r in load("SHA256"):
        var m = hex_to_bytes(r.arg(0))
        if len(m) > 55:
            continue  # the kernel hashes one block per message
        msgs.append(m.copy())
        expected.append(r.arg(1))

    # Group by length: the kernel takes one length per launch.
    for length in range(0, 56):
        var batch = List[UInt8]()
        var want = List[String]()
        for i in range(len(msgs)):
            if len(msgs[i]) == length:
                batch.extend(msgs[i].copy())
                want.append(expected[i])
        if len(want) == 0:
            continue
        var out = g.hash_batch(batch, length, len(want), check_size=False)
        for i in range(len(want)):
            var got = String()
            comptime H = "0123456789abcdef"
            for j in range(32):
                var v = Int(out[i * 32 + j])
                got += H[byte=v >> 4]
                got += H[byte=v & 0xF]
            assert_equal(got, want[i], "length " + String(length))


def test_varying_lengths() raises:
    """The padding differs for every length; check each one the kernel takes."""
    var g = GpuHasher()
    for length in [0, 1, 31, 32, 54, 55]:
        comptime N = 300
        var data = List[UInt8]()
        for i in range(N):
            for j in range(length):
                data.append(UInt8((i + j * 3) & 0xFF))
        var out = g.hash_batch(data, length, N, check_size=False)
        for i in range(N):
            var msg = List[UInt8]()
            for j in range(length):
                msg.append(data[i * length + j])
            var expect = sha256(msg)
            for j in range(32):
                assert_equal(Int(out[i * 32 + j]), Int(expect[j]))


def test_large_batch() raises:
    """More threads than one block holds, and a count that is not a multiple
    of the block size, so the bounds check in the kernel matters."""
    var g = GpuHasher()
    comptime N = 70001
    comptime L = 32
    var data = List[UInt8](capacity=N * L)
    for i in range(N):
        for j in range(L):
            data.append(UInt8((i * 13 + j) & 0xFF))
    var out = g.hash_batch(data, L, N)
    assert_equal(len(out), N * 32)

    # Spot-check the ends and the boundaries rather than all 70k.
    for i in [0, 1, 255, 256, 257, N - 2, N - 1]:
        var msg = List[UInt8]()
        for j in range(L):
            msg.append(data[i * L + j])
        var expect = sha256(msg)
        for j in range(32):
            assert_equal(
                Int(out[i * 32 + j]), Int(expect[j]), "mismatch at " + String(i)
            )


def test_empty_batch() raises:
    var g = GpuHasher()
    assert_equal(len(g.hash_batch(List[UInt8](), 32, 0)), 0)


def test_rejects_oversized_messages() raises:
    """Messages that do not fit in one block must be refused, not silently
    truncated."""
    var g = GpuHasher()
    var data = List[UInt8]()
    for _ in range(64):
        data.append(0)
    var raised = False
    try:
        _ = g.hash_batch(data, 56, 1, check_size=False)
    except:
        raised = True
    assert_true(raised, "msg_len of 56 should be rejected")


def test_rejects_short_buffer() raises:
    var g = GpuHasher()
    var data = List[UInt8]()
    for _ in range(10):
        data.append(0)
    var raised = False
    try:
        _ = g.hash_batch(data, 32, 100, check_size=False)
    except:
        raised = True
    assert_true(
        raised, "a buffer shorter than msg_len * count should be rejected"
    )


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
