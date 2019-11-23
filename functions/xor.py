from itertools import cycle, combinations
from typing import Callable, List

from functions.string_score import calc_score


def xor_byte_arrays(a: bytes, b: bytes) -> bytes:
    return bytes([x ^ y for x, y in zip(a, cycle(b))])


def rank_xor_single_byte_key(
    cipher: bytes, quality_test: Callable[[bytes], float] = calc_score
) -> List[bytes]:
    plains = [(key, xor_byte_arrays(cipher, bytes([key]))) for key in range(256)]
    rank_keys = sorted(
        plains, key=lambda score: (quality_test(score[1]), score[1]), reverse=True
    )
    keys = [bytes([key]) for key, _ in rank_keys]
    return keys


def bruteforce_xor_single_byte_key(
    cipher: bytes, quality_test: Callable[[bytes], float] = calc_score
) -> bytes:
    return rank_xor_single_byte_key(cipher, quality_test)[0]


def hamming(a: bytes, b: bytes) -> int:
    c = xor_byte_arrays(a, b)
    return bin(int(c.hex(), 16)).count("1")


def guess_key_length(
    cipher: bytes,
    min_length: int = 2,
    max_length: int = 40,
    distance: Callable[[bytes, bytes], int] = hamming,
) -> int:
    best_keysize = []
    for keysize in range(min_length, max_length + 1):
        blocks = [cipher[i * keysize : (i + 1) * keysize] for i in range(4)]
        blocks = list(combinations(blocks, 2))
        score = 0
        for pair in blocks:
            score += distance(*pair)
        score /= 6 * keysize
        best_keysize.append((score, keysize))
    best_keysize.sort(key=lambda keysize: keysize[0])
    return best_keysize[0][1]


def bruteforce_xor_multi_byte_key(cipher: bytes, keysize: int) -> bytes:
    bytes_blocks = []
    for i in range(keysize):
        block = bytes()
        for j in range(i, len(cipher), keysize):
            block += bytes([cipher[j]])
        bytes_blocks.append(block)

    key = bytes()
    for i in range(len(bytes_blocks)):
        block_key = bruteforce_xor_single_byte_key(bytes_blocks[i])
        key += block_key

    return key
