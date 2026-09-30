"""Minimal QR Code encoder (ISO/IEC 18004) for MFA enrollment.

Only what an ``otpauth://`` URI needs: byte mode, error-correction level M,
versions 1-25 (up to 997 bytes), automatic mask selection. The result is a
module matrix the web UI draws as an inline SVG path, so the TOTP secret
never goes to a third-party QR service and no image library is needed.

The construction follows the standard directly (and the structure of
Project Nayuki's public-domain reference implementation): data codewords,
Reed-Solomon error correction over GF(2^8) with polynomial 0x11D, block
interleaving, function patterns, zig-zag placement, the eight data masks
scored with the standard penalty rules, then BCH-protected format and
version information.
"""

from __future__ import annotations

from typing import List, Sequence, Tuple

MAX_VERSION = 25
# Error-correction level M: codewords per block and number of blocks, per version (index 0 unused).
_ECC_PER_BLOCK_M = (
    -1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28,
)  # fmt: skip
_BLOCKS_M = (-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21)
_FORMAT_BITS_M = 0b00
_PENALTY_N1, _PENALTY_N2, _PENALTY_N3, _PENALTY_N4 = 3, 3, 40, 10


class QrTooLong(ValueError):
    """The data does not fit the largest supported version."""


def _raw_data_modules(version: int) -> int:
    result = (16 * version + 128) * version + 64
    if version >= 2:
        num_align = version // 7 + 2
        result -= (25 * num_align - 10) * num_align - 55
        if version >= 7:
            result -= 36
    return result


def data_codewords(version: int) -> int:
    return _raw_data_modules(version) // 8 - _ECC_PER_BLOCK_M[version] * _BLOCKS_M[version]


def _gf_multiply(x: int, y: int) -> int:
    z = 0
    for i in reversed(range(8)):
        z = (z << 1) ^ ((z >> 7) * 0x11D)
        z ^= ((y >> i) & 1) * x
    return z


def _rs_divisor(degree: int) -> List[int]:
    result = [0] * (degree - 1) + [1]
    root = 1
    for _ in range(degree):
        for j in range(degree):
            result[j] = _gf_multiply(result[j], root)
            if j + 1 < degree:
                result[j] ^= result[j + 1]
        root = _gf_multiply(root, 0x02)
    return result


def _rs_remainder(data: Sequence[int], divisor: Sequence[int]) -> List[int]:
    result = [0] * len(divisor)
    for byte in data:
        factor = byte ^ result.pop(0)
        result.append(0)
        for i, coef in enumerate(divisor):
            result[i] ^= _gf_multiply(coef, factor)
    return result


def _choose_version(length: int) -> int:
    for version in range(1, MAX_VERSION + 1):
        count_bits = 8 if version <= 9 else 16
        if length < (1 << count_bits) and 4 + count_bits + 8 * length <= data_codewords(version) * 8:
            return version
    raise QrTooLong(f"{length} bytes do not fit a version {MAX_VERSION} QR code")


def _data_codewords_for(data: bytes, version: int) -> List[int]:
    capacity_bits = data_codewords(version) * 8
    bits: List[int] = []

    def append(value: int, width: int) -> None:
        bits.extend((value >> i) & 1 for i in reversed(range(width)))

    append(0b0100, 4)
    append(len(data), 8 if version <= 9 else 16)
    for byte in data:
        append(byte, 8)
    append(0, min(4, capacity_bits - len(bits)))
    append(0, -len(bits) % 8)
    codewords = [int("".join(map(str, bits[i : i + 8])), 2) for i in range(0, len(bits), 8)]
    pad = 0xEC
    while len(codewords) < capacity_bits // 8:
        codewords.append(pad)
        pad ^= 0xEC ^ 0x11
    return codewords


def _interleave_with_ecc(data: List[int], version: int) -> List[int]:
    num_blocks = _BLOCKS_M[version]
    ecc_len = _ECC_PER_BLOCK_M[version]
    raw_codewords = _raw_data_modules(version) // 8
    num_short = num_blocks - raw_codewords % num_blocks
    short_len = raw_codewords // num_blocks
    divisor = _rs_divisor(ecc_len)
    blocks: List[List[int]] = []
    k = 0
    for i in range(num_blocks):
        size = short_len - ecc_len + (0 if i < num_short else 1)
        block = data[k : k + size]
        k += size
        ecc = _rs_remainder(block, divisor)
        if i < num_short:
            block = block + [0]
        blocks.append(block + ecc)
    result: List[int] = []
    for i in range(len(blocks[0])):
        for j, block in enumerate(blocks):
            # Short blocks carry a placeholder at the last data position; skip it.
            if i != short_len - ecc_len or j >= num_short:
                result.append(block[i])
    return result


def alignment_positions(version: int) -> List[int]:
    if version == 1:
        return []
    num_align = version // 7 + 2
    size = version * 4 + 17
    step = (version * 8 + num_align * 3 + 5) // (num_align * 4 - 4) * 2
    return [6] + sorted(size - 7 - i * step for i in range(num_align - 1))


def _mask_bit(mask: int, x: int, y: int) -> bool:
    if mask == 0:
        return (x + y) % 2 == 0
    if mask == 1:
        return y % 2 == 0
    if mask == 2:
        return x % 3 == 0
    if mask == 3:
        return (x + y) % 3 == 0
    if mask == 4:
        return (x // 3 + y // 2) % 2 == 0
    if mask == 5:
        return x * y % 2 + x * y % 3 == 0
    if mask == 6:
        return (x * y % 2 + x * y % 3) % 2 == 0
    return ((x + y) % 2 + x * y % 3) % 2 == 0


def format_bits(mask: int) -> int:
    """15-bit format information for level M and ``mask`` (BCH(15,5), XOR 0x5412)."""
    data = _FORMAT_BITS_M << 3 | mask
    rem = data
    for _ in range(10):
        rem = (rem << 1) ^ ((rem >> 9) * 0x537)
    return (data << 10 | rem) ^ 0x5412


def version_bits(version: int) -> int:
    rem = version
    for _ in range(12):
        rem = (rem << 1) ^ ((rem >> 11) * 0x1F25)
    return version << 12 | rem


class _Symbol:
    def __init__(self, version: int) -> None:
        self.version = version
        self.size = version * 4 + 17
        self.modules = [[False] * self.size for _ in range(self.size)]
        self.function = [[False] * self.size for _ in range(self.size)]

    def set_function(self, x: int, y: int, dark: bool) -> None:
        self.modules[y][x] = dark
        self.function[y][x] = True

    def draw_function_patterns(self) -> None:
        size = self.size
        for i in range(size):
            self.set_function(6, i, i % 2 == 0)
            self.set_function(i, 6, i % 2 == 0)
        for cx, cy in ((3, 3), (size - 4, 3), (3, size - 4)):
            for dy in range(-4, 5):
                for dx in range(-4, 5):
                    x, y = cx + dx, cy + dy
                    if 0 <= x < size and 0 <= y < size:
                        self.set_function(x, y, max(abs(dx), abs(dy)) not in (2, 4))
        positions = alignment_positions(self.version)
        last = len(positions) - 1
        for i, px in enumerate(positions):
            for j, py in enumerate(positions):
                if (i, j) in ((0, 0), (0, last), (last, 0)):
                    continue  # finder pattern corners
                for dy in range(-2, 3):
                    for dx in range(-2, 3):
                        self.set_function(px + dx, py + dy, max(abs(dx), abs(dy)) != 1)
        self.draw_format(0)  # reserve the area; overwritten once the mask is chosen
        if self.version >= 7:
            bits = version_bits(self.version)
            for i in range(18):
                dark = (bits >> i) & 1 == 1
                a, b = size - 11 + i % 3, i // 3
                self.set_function(a, b, dark)
                self.set_function(b, a, dark)

    def draw_format(self, mask: int) -> None:
        bits = format_bits(mask)
        size = self.size

        def bit(i: int) -> bool:
            return (bits >> i) & 1 == 1

        for i in range(6):
            self.set_function(8, i, bit(i))
        self.set_function(8, 7, bit(6))
        self.set_function(8, 8, bit(7))
        self.set_function(7, 8, bit(8))
        for i in range(9, 15):
            self.set_function(14 - i, 8, bit(i))
        for i in range(8):
            self.set_function(size - 1 - i, 8, bit(i))
        for i in range(8, 15):
            self.set_function(8, size - 15 + i, bit(i))
        self.set_function(8, size - 8, True)  # the dark module

    def draw_codewords(self, codewords: Sequence[int]) -> None:
        total_bits = len(codewords) * 8
        i = 0
        right = self.size - 1
        while right >= 1:
            if right == 6:
                right = 5  # skip the vertical timing pattern
            upward = (right + 1) & 2 == 0
            for vert in range(self.size):
                y = self.size - 1 - vert if upward else vert
                for x in (right, right - 1):
                    if not self.function[y][x] and i < total_bits:
                        self.modules[y][x] = (codewords[i >> 3] >> (7 - (i & 7))) & 1 == 1
                        i += 1
            right -= 2

    def apply_mask(self, mask: int) -> None:
        for y in range(self.size):
            for x in range(self.size):
                if not self.function[y][x] and _mask_bit(mask, x, y):
                    self.modules[y][x] = not self.modules[y][x]

    def penalty(self) -> int:
        size = self.size
        m = self.modules
        result = 0
        for lines in (m, [list(col) for col in zip(*m, strict=True)]):
            for line in lines:
                result += self._line_penalty(line)
        for y in range(size - 1):
            for x in range(size - 1):
                if m[y][x] == m[y][x + 1] == m[y + 1][x] == m[y + 1][x + 1]:
                    result += _PENALTY_N2
        dark = sum(sum(row) for row in m)
        total = size * size
        k = (abs(dark * 20 - total * 10) + total - 1) // total - 1
        return result + k * _PENALTY_N4

    def _line_penalty(self, line: Sequence[bool]) -> int:
        size = self.size
        result = 0
        run_color = False
        run_len = 0
        history = [0] * 7

        def add_history(length: int) -> None:
            if history[0] == 0:
                length += size  # the light border before the first run
            history.pop()
            history.insert(0, length)

        def count_patterns() -> int:
            n = history[1]
            core = n > 0 and history[2] == history[4] == history[5] == n and history[3] == n * 3
            return int(core and history[0] >= n * 4 and history[6] >= n) + int(
                core and history[6] >= n * 4 and history[0] >= n
            )

        for dark in line:
            if dark == run_color:
                run_len += 1
                if run_len == 5:
                    result += _PENALTY_N1
                elif run_len > 5:
                    result += 1
            else:
                add_history(run_len)
                if not run_color:
                    result += count_patterns() * _PENALTY_N3
                run_color = dark
                run_len = 1
        if run_color:
            add_history(run_len)
            run_len = 0
        add_history(run_len + size)
        return result + count_patterns() * _PENALTY_N3


def encode(text: str) -> Tuple[int, List[List[bool]]]:
    """``(version, modules)`` for ``text`` (UTF-8, byte mode, level M); ``modules[y][x]`` is dark."""
    data = text.encode("utf-8")
    version = _choose_version(len(data))
    codewords = _interleave_with_ecc(_data_codewords_for(data, version), version)
    symbol = _Symbol(version)
    symbol.draw_function_patterns()
    symbol.draw_codewords(codewords)
    best_mask, best_penalty = 0, None
    for mask in range(8):
        symbol.apply_mask(mask)
        symbol.draw_format(mask)
        score = symbol.penalty()
        if best_penalty is None or score < best_penalty:
            best_mask, best_penalty = mask, score
        symbol.apply_mask(mask)  # XOR again: undo
    symbol.apply_mask(best_mask)
    symbol.draw_format(best_mask)
    return version, symbol.modules


def matrix_rows(text: str) -> List[str]:
    """The symbol as rows of ``"1"`` (dark) / ``"0"`` (light), without the quiet zone."""
    _, modules = encode(text)
    return ["".join("1" if dark else "0" for dark in row) for row in modules]
