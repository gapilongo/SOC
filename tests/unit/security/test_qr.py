"""QR encoder: decoded back by an independent reader written from the standard.

The reader below re-derives everything it needs (function-pattern layout,
format information, zig-zag order, block de-interleaving) and checks the
Reed-Solomon codewords by evaluating syndromes, a different computation from
the encoder's polynomial division. A symbol that decodes to the input with
all syndromes zero is what a phone camera reads.
"""

from __future__ import annotations

from typing import List, Set, Tuple

import pytest

from lg_sotf.security import qr, totp

# Capacity in bytes at level M (ISO/IEC 18004 table 7) for versions 1-25.
BYTE_CAPACITY_M = [14, 26, 42, 62, 84, 106, 122, 152, 180, 213, 251, 287, 331, 362, 412, 450, 504, 560, 624, 666,
                   711, 779, 857, 911, 997]  # fmt: skip
# Alignment pattern centres (ISO/IEC 18004 annex E) for a few versions.
ALIGNMENT = {1: [], 2: [6, 18], 7: [6, 22, 38], 14: [6, 26, 46, 66], 22: [6, 26, 50, 74, 98], 25: [6, 32, 58, 84, 110]}

# GF(256) with the QR polynomial, built by repeated doubling (not the encoder's bitwise multiply).
EXP = [0] * 512
LOG = [0] * 256
_x = 1
for _i in range(255):
    EXP[_i] = _x
    LOG[_x] = _i
    _x <<= 1
    if _x & 0x100:
        _x ^= 0x11D
for _i in range(255, 512):
    EXP[_i] = EXP[_i - 255]


def gf_mul(a: int, b: int) -> int:
    return 0 if a == 0 or b == 0 else EXP[LOG[a] + LOG[b]]


def syndromes(block: List[int], ecc_len: int) -> List[int]:
    """Evaluate the codeword polynomial at alpha^0 .. alpha^(ecc_len-1); all zero for a valid block."""
    out = []
    for i in range(ecc_len):
        acc = 0
        for byte in block:
            acc = gf_mul(acc, EXP[i]) ^ byte
        out.append(acc)
    return out


def function_modules(version: int) -> Set[Tuple[int, int]]:
    size = 4 * version + 17
    cells: Set[Tuple[int, int]] = set()
    for cx, cy in ((0, 0), (size - 7, 0), (0, size - 7)):  # finders plus separators
        for y in range(cy - 1, cy + 8):
            for x in range(cx - 1, cx + 8):
                if 0 <= x < size and 0 <= y < size:
                    cells.add((x, y))
    for i in range(size):
        cells.add((6, i))
        cells.add((i, 6))
    centres = ALIGNMENT.get(version, qr.alignment_positions(version))
    for px in centres:
        for py in centres:
            if (px, py) in ((6, 6), (6, size - 7), (size - 7, 6)):
                continue
            for y in range(py - 2, py + 3):
                for x in range(px - 2, px + 3):
                    cells.add((x, y))
    for i in range(9):  # format information around the finders, plus the dark module
        cells.add((8, i))
        cells.add((i, 8))
    for i in range(8):
        cells.add((size - 1 - i, 8))
        cells.add((8, size - 1 - i))
    if version >= 7:
        for i in range(6):
            for j in range(3):
                cells.add((size - 11 + j, i))
                cells.add((i, size - 11 + j))
    return cells


def read_format(m: List[List[bool]]) -> Tuple[int, int]:
    """(ec level bits, mask) from the copy around the top-left finder, BCH-checked against all 32 words."""
    bits = 0
    positions = [(8, i) for i in range(6)] + [(8, 7), (8, 8), (7, 8)] + [(14 - i, 8) for i in range(9, 15)]
    for i, (x, y) in enumerate(positions):
        bits |= int(m[y][x]) << i
    valid = {}
    for data in range(32):
        rem = data
        for _ in range(10):
            rem = (rem << 1) ^ (0x537 if rem & 0x200 else 0)
        valid[((data << 10) | (rem & 0x3FF)) ^ 0x5412] = data
    assert bits in valid, "format information is not a valid BCH codeword"
    data = valid[bits]
    return data >> 3, data & 7


MASKS = [
    lambda x, y: (x + y) % 2 == 0,
    lambda x, y: y % 2 == 0,
    lambda x, y: x % 3 == 0,
    lambda x, y: (x + y) % 3 == 0,
    lambda x, y: (x // 3 + y // 2) % 2 == 0,
    lambda x, y: (x * y) % 2 + (x * y) % 3 == 0,
    lambda x, y: ((x * y) % 2 + (x * y) % 3) % 2 == 0,
    lambda x, y: ((x + y) % 2 + (x * y) % 3) % 2 == 0,
]


def decode(rows: List[str]) -> Tuple[int, bytes]:
    m = [[c == "1" for c in row] for row in rows]
    size = len(m)
    version = (size - 17) // 4
    assert size == 4 * version + 17 and all(len(r) == size for r in rows)
    for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
        for dy in range(-3, 4):
            for dx in range(-3, 4):
                assert m[cy + dy][cx + dx] == (max(abs(dx), abs(dy)) != 2), "finder pattern"
    for i in range(8, size - 8):
        assert m[6][i] == (i % 2 == 0) and m[i][6] == (i % 2 == 0), "timing pattern"
    assert m[size - 8][8], "dark module"
    ecl, mask = read_format(m)
    assert ecl == 0b00, "error-correction level M"
    functional = function_modules(version)
    # Zig-zag: column pairs from the right, skipping the vertical timing column, alternating direction.
    order: List[Tuple[int, int]] = []
    x = size - 1
    upward = True
    while x > 0:
        if x == 6:
            x -= 1
        ys = range(size - 1, -1, -1) if upward else range(size)
        for y in ys:
            for xx in (x, x - 1):
                if (xx, y) not in functional:
                    order.append((xx, y))
        upward = not upward
        x -= 2
    bits = [int(m[y][xx] ^ MASKS[mask](xx, y)) for xx, y in order]
    total = len(bits) // 8
    codewords = [int("".join(map(str, bits[i * 8 : i * 8 + 8])), 2) for i in range(total)]
    blocks_n = qr._BLOCKS_M[version]
    ecc_len = qr._ECC_PER_BLOCK_M[version]
    short_data = total // blocks_n - ecc_len
    num_long = total % blocks_n
    data_lens = [short_data] * (blocks_n - num_long) + [short_data + 1] * num_long
    blocks: List[List[int]] = [[] for _ in range(blocks_n)]
    k = 0
    for i in range(short_data + 1):
        for b in range(blocks_n):
            if i < data_lens[b]:
                blocks[b].append(codewords[k])
                k += 1
    for _ in range(ecc_len):
        for b in range(blocks_n):
            blocks[b].append(codewords[k])
            k += 1
    data: List[int] = []
    for b, block in enumerate(blocks):
        assert syndromes(block, ecc_len) == [0] * ecc_len, f"block {b} fails Reed-Solomon"
        data.extend(block[: data_lens[b]])
    stream = "".join(f"{byte:08b}" for byte in data)
    assert stream[:4] == "0100", "byte mode"
    count_bits = 8 if version <= 9 else 16
    length = int(stream[4 : 4 + count_bits], 2)
    start = 4 + count_bits
    payload = bytes(int(stream[start + 8 * i : start + 8 * i + 8], 2) for i in range(length))
    return version, payload


@pytest.mark.parametrize(
    "text",
    [
        "A",
        "otpauth://totp/LG-SOTF:ana@example.com?secret=JBSWY3DPEHPK3PXP&issuer=LG-SOTF",
        totp.provisioning_uri(totp.generate_secret(), "a" * 64 + "@" + "b" * 60 + ".example.com", "LG-SOTF"),
        totp.provisioning_uri(totp.generate_secret(), "x" * 300 + "@example.com", "LG-SOTF"),
        "Zürich ✓ " * 20,
    ],
    # Fixed ids: two of the inputs hold a random secret, and pytest-xdist needs every worker to collect the same ids.
    ids=["one-char", "otpauth", "long-account", "overlong-account", "unicode"],
)
def test_symbols_decode_back_to_the_input(text: str) -> None:
    version, payload = decode(qr.matrix_rows(text))
    assert payload == text.encode("utf-8")
    assert version == qr._choose_version(len(text.encode("utf-8")))


@pytest.mark.parametrize("version", range(1, qr.MAX_VERSION + 1))
def test_every_version_decodes_at_full_capacity(version: int) -> None:
    capacity = BYTE_CAPACITY_M[version - 1]
    assert qr.data_codewords(version) - (2 if version <= 9 else 3) == capacity
    text = "".join(chr(0x61 + (i % 26)) for i in range(capacity))
    decoded_version, payload = decode(qr.matrix_rows(text))
    assert (decoded_version, payload) == (version, text.encode())


@pytest.mark.parametrize("version", sorted(ALIGNMENT))
def test_alignment_positions_match_the_standard(version: int) -> None:
    assert qr.alignment_positions(version) == ALIGNMENT[version]


def test_version_information_is_bch_protected() -> None:
    # ISO/IEC 18004 annex D lists 0x07C94 for version 7; every other word is checked as a BCH(18,6) codeword.
    assert qr.version_bits(7) == 0x07C94
    for version in range(7, qr.MAX_VERSION + 1):
        word = qr.version_bits(version)
        rem = word
        for shift in range(17, 11, -1):
            if rem & (1 << shift):
                rem ^= 0x1F25 << (shift - 12)
        assert word >> 12 == version and rem == 0


def test_too_long_input_is_refused() -> None:
    with pytest.raises(qr.QrTooLong):
        qr.matrix_rows("x" * (BYTE_CAPACITY_M[-1] + 1))
