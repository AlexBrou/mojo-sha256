"""HMAC-SHA256, per RFC 2104."""

from .constants import BLOCK_SIZE, Digest
from .core import Backend, Sha256, _hex
from .scrub import scrub_u8


struct HmacSha256[backend: Int = Backend.AUTO](Copyable, Movable):
    """```mojo
    var h = HmacSha256(key)
    h.write(message)
    var tag = h.digest()
    ```
    """

    var inner: Sha256[Self.backend]
    var outer: Sha256[Self.backend]

    def __init__(out self, key: Span[UInt8, _]):
        # RFC 2104: keys longer than the block size are hashed first, shorter
        # ones are zero-padded.
        var rkey = Array[UInt8, BLOCK_SIZE](fill=0)
        if len(key) > BLOCK_SIZE:
            var kh = Sha256[Self.backend]()
            kh.write(key)
            var kd = kh.digest()
            for i in range(32):
                rkey[i] = kd[i]
        else:
            for i in range(len(key)):
                rkey[i] = key[i]

        var ipad = Array[UInt8, BLOCK_SIZE](fill=0)
        var opad = Array[UInt8, BLOCK_SIZE](fill=0)
        for i in range(BLOCK_SIZE):
            ipad[i] = rkey[i] ^ 0x36
            opad[i] = rkey[i] ^ 0x5C

        self.inner = Sha256[Self.backend]()
        self.inner.write(ipad)
        self.outer = Sha256[Self.backend]()
        self.outer.write(opad)

        # rkey, ipad and opad are all derived from the key; do not leave them
        # on the stack for the next frame to inherit.
        for i in range(BLOCK_SIZE):
            scrub_u8(rkey[i])
            scrub_u8(ipad[i])
            scrub_u8(opad[i])

    def write(mut self, data: Span[UInt8, _]):
        self.inner.write(data)

    def digest(mut self) -> Digest:
        var t = self.inner.digest()
        self.outer.write(t)
        return self.outer.digest()

    def hexdigest(mut self) -> String:
        return _hex(self.digest())

    def clear(mut self):
        """Wipe both hash states; see `Sha256.clear`."""
        self.inner.clear()
        self.outer.clear()


def hmac_sha256[
    backend: Int = Backend.AUTO
](key: Span[UInt8, _], data: Span[UInt8, _]) -> Digest:
    var h = HmacSha256[backend](key)
    h.write(data)
    return h.digest()
