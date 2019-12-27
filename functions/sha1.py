import struct
from typing import List, Tuple


class SHA1:
    @staticmethod
    def _rotl(x: int, n: int) -> int:
        return ((x << n) | (x >> 32 - n)) & 0xFFFFFFFF

    @staticmethod
    def _padding(data: bytes) -> bytes:
        data_len = len(data)

        data += b"\x80"

        while (len(data) * 8) % 512 != 448:
            data += b"\x00"

        data += struct.pack(">Q", (data_len * 8))

        return data

    @staticmethod
    def _get_blocks(data: bytes) -> List[List[bytes]]:
        blocks = []

        for i in range(0, len(data), 64):
            words = []
            for j in range(0, 64, 4):
                words.append(data[i + j : i + j + 4])
            blocks.append(words)

        return blocks

    @staticmethod
    def _process_block(
        block: List[bytes], h: Tuple[int, int, int, int, int]
    ) -> Tuple[int, int, int, int, int]:
        w = []

        for t in range(16):
            w.append(struct.unpack(">I", block[t])[0])

        for t in range(16, 80):
            w.append(SHA1._rotl((w[t - 3] ^ w[t - 8] ^ w[t - 14] ^ w[t - 16]), 1))

        a = h[0]
        b = h[1]
        c = h[2]
        d = h[3]
        e = h[4]

        for t in range(80):
            if t <= 19:
                K = 0x5A827999
                f = (b & c) ^ (~b & d)
            elif t <= 39:
                K = 0x6ED9EBA1
                f = b ^ c ^ d
            elif t <= 59:
                K = 0x8F1BBCDC
                f = (b & c) ^ (b & d) ^ (c & d)
            else:
                K = 0xCA62C1D6
                f = b ^ c ^ d

            T = (SHA1._rotl(a, 5) + f + e + K + w[t]) & 0xFFFFFFFF
            e = d
            d = c
            c = SHA1._rotl(b, 30)
            b = a
            a = T

        h0 = (a + h[0]) & 0xFFFFFFFF
        h1 = (b + h[1]) & 0xFFFFFFFF
        h2 = (c + h[2]) & 0xFFFFFFFF
        h3 = (d + h[3]) & 0xFFFFFFFF
        h4 = (e + h[4]) & 0xFFFFFFFF

        return (h0, h1, h2, h3, h4)

    @staticmethod
    def digest(data: bytes) -> bytes:
        h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]

        padded_data = SHA1._padding(data)
        data_blocks = SHA1._get_blocks(padded_data)

        for block in data_blocks:
            h = SHA1._process_block(block, h)

        return struct.pack(">IIIII", *h)

    @staticmethod
    def hex_digest(data: bytes) -> str:
        return SHA1.digest(data).hex()


class SHA1KeyedMAC:
    def __init__(self, key: bytes):
        self._key = key

    def digest(self, data: bytes) -> bytes:
        return SHA1.digest(self._key + data)

    def hex_digest(self, data: bytes) -> str:
        return SHA1.hex_digest(self._key + data)

    def validate(self, data: bytes, sign: bytes) -> bool:
        return SHA1.digest(self._key + data) == sign

    def hex_validate(self, data: bytes, sign: str) -> bool:
        return SHA1.hex_digest(self._key + data) == sign
