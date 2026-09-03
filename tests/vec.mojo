"""Loader for tests/vectors/vectors.txt."""

from std.pathlib import Path


@fieldwise_init
struct Row(Copyable):
    var op: String
    var args: List[String]

    def arg(self, i: Int) -> String:
        return self.args[i]


def load(op: String) raises -> List[Row]:
    """Every row with the given op. Raises if there are none, so a typo in the
    op name fails loudly instead of vacuously passing."""
    var text = Path("tests/vectors/vectors.txt").read_text()
    var rows = List[Row]()
    for line in text.split("\n"):
        var s = line.strip()
        if s.byte_length() == 0 or s.startswith("#"):
            continue
        # Fields are kept even when empty: the digest of the empty message has
        # a zero-length first argument, and dropping it would shift the rest.
        var parts = List[String]()
        for p in s.split(" "):
            parts.append(String(p))
        if len(parts) < 2 or parts[0] != op:
            continue
        var args = List[String]()
        for i in range(1, len(parts)):
            args.append(parts[i])
        rows.append(Row(parts[0], args^))
    if len(rows) == 0:
        raise Error("no vectors for op " + op)
    return rows^


def hex_to_bytes(s: StringSlice) raises -> List[UInt8]:
    var b = s.as_bytes()
    var n = len(b)
    if n % 2 != 0:
        raise Error("hex string has odd length")
    var out = List[UInt8](capacity=n // 2)
    var i = 0
    while i < n:
        out.append((_nibble(b[i]) << 4) | _nibble(b[i + 1]))
        i += 2
    return out^


def _nibble(c: UInt8) raises -> UInt8:
    if c >= 48 and c <= 57:
        return c - 48
    if c >= 97 and c <= 102:
        return c - 87
    if c >= 65 and c <= 70:
        return c - 55
    raise Error("invalid hex digit")
