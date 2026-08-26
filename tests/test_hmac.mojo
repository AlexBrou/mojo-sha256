"""HMAC-SHA256 against RFC 4231 and generated vectors."""

from std.testing import assert_equal, assert_true, TestSuite

from sha256.core import Backend, _hex
from sha256.hmac import HmacSha256, hmac_sha256
from tests.vec import hex_to_bytes, load


def test_known_vectors() raises:
    for r in load("HMAC"):
        var key = hex_to_bytes(r.arg(0))
        var data = hex_to_bytes(r.arg(1))
        assert_equal(_hex(hmac_sha256(key, data)), r.arg(2))


def test_backends_agree() raises:
    for r in load("HMAC"):
        var key = hex_to_bytes(r.arg(0))
        var data = hex_to_bytes(r.arg(1))
        assert_equal(
            _hex(hmac_sha256[Backend.PORTABLE](key, data)),
            _hex(hmac_sha256[Backend.ARM](key, data)),
        )


def test_long_key_is_hashed_first() raises:
    """RFC 2104: a key longer than the 64-byte block is replaced by its hash.
    Two of the RFC 4231 cases use a 131-byte key and cover this."""
    var long_key = List[UInt8]()
    for _ in range(131):
        long_key.append(0xAA)
    var data = List[UInt8]()
    for c in String(
        "Test Using Larger Than Block-Size Key - Hash Key First"
    ).as_bytes():
        data.append(c)
    assert_equal(
        _hex(hmac_sha256(long_key, data)),
        "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54",
    )


def test_streaming_matches_one_shot() raises:
    for r in load("HMAC"):
        var key = hex_to_bytes(r.arg(0))
        var data = hex_to_bytes(r.arg(1))
        for chunk in [1, 13, 64, 65]:
            var h = HmacSha256(key)
            var i = 0
            while i < len(data):
                var take = chunk
                if take > len(data) - i:
                    take = len(data) - i
                h.write(Span(data)[i : i + take])
                i += take
            assert_equal(_hex(h.digest()), r.arg(2))


def test_clear_wipes_state() raises:
    var key = hex_to_bytes("0b0b0b0b")
    var h = HmacSha256(key)
    h.write(key)
    _ = h.digest()
    h.clear()
    for i in range(8):
        assert_equal(Int(h.inner.s[i]), 0)
        assert_equal(Int(h.outer.s[i]), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
