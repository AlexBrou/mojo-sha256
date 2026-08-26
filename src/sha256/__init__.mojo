"""SHA-256 for Mojo, with CPU and GPU backends.

The everyday entry points:

```mojo
from sha256 import sha256, Sha256

var digest = sha256(data)          # one shot, 32 bytes

var h = Sha256()                   # streaming
h.write(part_one)
h.write(part_two)
var d = h.digest()
```

`Sha256` picks the fastest CPU backend for the target at compile time: the
ARMv8 SHA-2 crypto extension where available, otherwise a portable
implementation. Both produce identical digests — the test suite checks that
against every vector.

Batch work on the GPU lives in `sha256.gpu`; see its docstring for when it is
worth using (roughly, above 64k messages per batch).
"""

from .core import Sha256, sha256, Backend
from .hmac import HmacSha256, hmac_sha256
from .rfc6979 import Rfc6979
