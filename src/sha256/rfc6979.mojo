"""The HMAC-SHA256 deterministic random bit generator of RFC 6979 section 3.2.

Used to derive signature nonces without a source of randomness. Kept here
because it is pure HMAC-SHA256 and has no dependency on any curve.
"""

from .constants import DIGEST_SIZE, Digest
from .core import Backend
from .hmac import HmacSha256
from .scrub import scrub_u8


struct Rfc6979[backend: Int = Backend.AUTO](Copyable, Movable):
    """```mojo
    var rng = Rfc6979(seed)         # seed is usually seckey || message
    var nonce = rng.generate()      # 32 bytes, deterministic
    var another = rng.generate()    # the next in the sequence
    ```

    Nothing here allocates: the state is two fixed 32-byte arrays.
    """

    var v: Array[UInt8, DIGEST_SIZE]
    var k: Array[UInt8, DIGEST_SIZE]
    var retry: Bool

    def __init__(out self, key: Span[UInt8, _]):
        # 3.2.b and 3.2.c
        self.v = Array[UInt8, DIGEST_SIZE](fill=0x01)
        self.k = Array[UInt8, DIGEST_SIZE](fill=0x00)
        self.retry = False
        # 3.2.d and 3.2.f
        self._update(0x00, key, True)
        self._update(0x01, key, True)

    def _update(mut self, sep: UInt8, key: Span[UInt8, _], with_key: Bool):
        var sep_arr = Array[UInt8, 1](fill=sep)
        var h = HmacSha256[Self.backend](self.k)
        h.write(self.v)
        h.write(sep_arr)
        if with_key:
            h.write(key)
        self.k = h.digest()
        var h2 = HmacSha256[Self.backend](self.k)
        h2.write(self.v)
        self.v = h2.digest()

    def generate(mut self) -> Digest:
        """The next 32 bytes of output (RFC 6979 section 3.2.h)."""
        if self.retry:
            var empty = Array[UInt8, 1](fill=0)
            self._update(0x00, Span(empty)[0:0], False)
        var h = HmacSha256[Self.backend](self.k)
        h.write(self.v)
        self.v = h.digest()
        self.retry = True
        return self.v.copy()

    def clear(mut self):
        """Wipe the state.

        `k` in particular would let an observer regenerate every value this
        instance would go on to produce.
        """
        for i in range(DIGEST_SIZE):
            scrub_u8(self.v[i])
            scrub_u8(self.k[i])
        self.retry = False
