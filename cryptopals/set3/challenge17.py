#!/usr/bin/env python3

import base64

from functions import aes
from functions.aes import PKCS7BadPadding


_STRINGS = tuple(
    base64.b64decode(s)
    for s in (
        "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
        "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
        "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
        "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
        "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
        "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
        "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
        "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
        "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
        "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
    )
)

_KEY = aes.gen_random_bytes(16)


def _encrypt(pt: bytes) -> (bytes, bytes):
    iv = aes.gen_random_bytes(16)
    ct = aes.aes_cbc_encrypt(pt, _KEY, iv)

    return iv, ct


def _oracle(iv: bytes, ct: bytes) -> bool:
    try:
        aes.aes_cbc_decrypt(ct, _KEY, iv)
    except PKCS7BadPadding:
        return False

    return True


def _attack(iv: bytes, ct: bytes) -> bytes:
    cipher_blocks = [iv] + aes.get_blocks(ct)

    pt = b""

    for i in reversed(range(1, len(cipher_blocks))):
        ct_block_pre_xor = cipher_blocks[i - 1]
        ct_block_current = cipher_blocks[i]
        intermediate_block = b""

        for j in reversed(range(16)):
            ctb_prefix = aes.gen_random_bytes(j)
            ctb_suffix = b""

            for k in range(len(intermediate_block)):
                ctb_suffix += bytes([(16 - j) ^ intermediate_block[k]])

            n = 0
            for m in range(256):
                ctb = ctb_prefix + bytes([m]) + ctb_suffix

                if _oracle(ctb, ct_block_current):
                    n = m
                    break

            intermediate_block = bytes([n ^ (16 - j)]) + intermediate_block
            pt = bytes([ct_block_pre_xor[j] ^ int(intermediate_block[0])]) + pt

    return aes.pkcs7_padding_del(pt)


def challenge17() -> bool:
    for msg in _STRINGS:
        ret = _attack(*_encrypt(msg))

        if ret not in _STRINGS:
            return False

    return True


if __name__ == "__main__":
    assert challenge17(), "The result does not match the expected value"

    print("Ok")
