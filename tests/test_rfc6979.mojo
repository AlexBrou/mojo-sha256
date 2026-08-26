"""The RFC 6979 HMAC-DRBG."""

from std.testing import assert_equal, assert_true, assert_false, TestSuite

from sha256.core import Backend, _hex
from sha256.rfc6979 import Rfc6979
from tests.vec import hex_to_bytes, load


def test_known_vectors() raises:
    """Three successive outputs per seed: the first is a plain generate, the
    later ones exercise the reseed-on-retry path in section 3.2.h."""
    for r in load("RFC6979"):
        var seed = hex_to_bytes(r.arg(0))
        var rng = Rfc6979(seed)
        assert_equal(_hex(rng.generate()), r.arg(1))
        assert_equal(_hex(rng.generate()), r.arg(2))
        assert_equal(_hex(rng.generate()), r.arg(3))


def test_backends_agree() raises:
    for r in load("RFC6979"):
        var seed = hex_to_bytes(r.arg(0))
        var a = Rfc6979[Backend.PORTABLE](seed)
        var b = Rfc6979[Backend.ARM](seed)
        for _ in range(3):
            assert_equal(_hex(a.generate()), _hex(b.generate()))


def test_deterministic() raises:
    """The point of the construction: same seed, same stream, every time."""
    var seed = hex_to_bytes("00112233445566778899aabbccddeeff")
    var a = Rfc6979(seed)
    var b = Rfc6979(seed)
    for _ in range(4):
        assert_equal(_hex(a.generate()), _hex(b.generate()))


def test_different_seeds_diverge() raises:
    var s1 = hex_to_bytes("00112233445566778899aabbccddeeff")
    var s2 = hex_to_bytes("00112233445566778899aabbccddeef0")
    var a = Rfc6979(s1)
    var b = Rfc6979(s2)
    assert_true(_hex(a.generate()) != _hex(b.generate()))


def test_clear_wipes_state() raises:
    var seed = hex_to_bytes("00112233445566778899aabbccddeeff")
    var rng = Rfc6979(seed)
    _ = rng.generate()
    rng.clear()
    for i in range(32):
        assert_equal(Int(rng.v[i]), 0)
        assert_equal(Int(rng.k[i]), 0)


def main() raises:
    TestSuite.discover_tests[__functions_in_module()]().run()
