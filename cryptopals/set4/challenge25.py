#!/usr/bin/env python3

import base64
import pathlib

from functions.aes import AESCipher, gen_random_bytes
from functions.xor import xor_byte_arrays


_KEY = gen_random_bytes(16)
_NONCE = b"\x00" * 8


def _encrypt_it(path: str) -> (bytes, bytes):
    ecb = AESCipher(AESCipher.MODE_ECB, key=b"YELLOW SUBMARINE")

    with open(path) as f:
        cipher_text = base64.b64decode(f.read())

    plain_text = ecb.decrypt(cipher_text)

    ctr = AESCipher(AESCipher.MODE_CTR, _KEY, nonce=_NONCE)

    cipher_text = ctr.encrypt(plain_text)

    return cipher_text, plain_text


def _edit(cipher_text: bytes, offset: int, new_text: bytes) -> bytes:
    ctr = AESCipher(AESCipher.MODE_CTR, _KEY, nonce=_NONCE)
    plain_text = ctr.decrypt(cipher_text)

    plain_text = plain_text[:offset] + new_text + plain_text[offset + len(new_text) :]

    return ctr.encrypt(plain_text)


def challenge25(path: str) -> bool:
    cipher_text, plain_text = _encrypt_it(path)

    keystream = _edit(cipher_text, 0, bytes([0]) * len(cipher_text))

    pt = xor_byte_arrays(cipher_text, keystream)

    if pt == plain_text:
        return True

    return False


if __name__ == "__main__":
    assert challenge25(
        pathlib.Path(__file__).absolute().parent.parent.parent / "data" / "25.txt"
    ), "The result does not match the expected value"

    print("Ok")
