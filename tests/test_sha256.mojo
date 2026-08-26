"""SHA-256 against known vectors, on every backend."""

from std.testing import assert_equal, assert_true, TestSuite

from sha256.core import Backend, Sha256, sha256, _hex
from tests.vec import hex_to_bytes, load


def test_known_vectors_auto() raises:
    for r in load("SHA256"):
        var msg = hex_to_bytes(r.arg(0))
        assert_equal(_hex(sha256(msg)), r.arg(1))


def test_known_vectors_portable() raises:
    for r in load("SHA256"):
        var msg = hex_to_bytes(r.arg(0))
        assert_equal(_hex(sha256[Backend.PORTABLE](msg)), r.arg(1))


def test_known_vectors_arm() raises:
    # Skipped by the compiler on a target without NEON: the ARM backend would
    # not build there. On aarch64 this is the important one.
    comptime if Backend.ARM == Backend.ARM:
        for r in load("SHA256"):
            var msg = hex_to_bytes(r.arg(0))
            assert_equal(_hex(sha256[Backend.ARM](msg)), r.arg(1))


def test_backends_agree() raises:
    """The whole point of having two: they must be indistinguishable."""
    for r in load("SHA256"):
        var msg = hex_to_bytes(r.arg(0))
        assert_equal(
            _hex(sha256[Backend.PORTABLE](msg)),
            _hex(sha256[Backend.ARM](msg)),
        )


def test_streaming_matches_one_shot() raises:
    """Feeding the same bytes in odd-sized chunks must not change the digest.

    This is what exercises the block buffering: chunk sizes either side of 64
    push partial blocks across the boundary in different ways.
    """
    for r in load("SHA256"):
        var msg = hex_to_bytes(r.arg(0))
        for chunk in [1, 7, 31, 63, 64, 65, 127]:
            var h = Sha256()
            var i = 0
            while i < len(msg):
                var take = chunk
                if take > len(msg) - i:
                    take = len(msg) - i
                h.write(Span(msg)[i : i + take])
                i += take
            assert_equal(_hex(h.digest()), r.arg(1))


def test_empty_message() raises:
    assert_equal(
        _hex(sha256(List[UInt8]())),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    )


def test_padding_boundaries() raises:
    """55, 56 and 64 bytes are where the padding either fits, spills into a
    second block, or exactly fills one."""
    for n in [54, 55, 56, 57, 63, 64, 65, 119, 120, 128]:
        var msg = List[UInt8]()
        for i in range(n):
            msg.append(UInt8((i * 37 + 11) & 0xFF))
        var streamed = Sha256()
        streamed.write(msg)
        assert_equal(_hex(sha256(msg)), _hex(streamed.digest()))


def test_hexdigest_matches_digest() raises:
    var msg = hex_to_bytes("616263")
    var a = Sha256()
    a.write(msg)
    var b = Sha256()
    b.write(msg)
    assert_equal(a.hexdigest(), _hex(b.digest()))


def test_clear_wipes_state() raises:
    var msg = hex_to_bytes("616263")
    var h = Sha256()
    h.write(msg)
    _ = h.digest()
    h.clear()
    for i in range(8):
        assert_equal(Int(h.s[i]), 0)
    for i in range(64):
        assert_equal(Int(h.buf[i]), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
