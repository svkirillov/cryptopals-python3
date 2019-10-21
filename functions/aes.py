import os
from typing import List

from Crypto.Cipher import AES

from functions import xor


class PKCS7BadPadding(Exception):
    def __init__(self, block: bytes):
        super().__init__(self)
        self._block = block

    def __str__(self):
        return f"Oops! Bad PKCS#7 padding: {self._block}"


def get_blocks(bytes_: bytes, block_size: int = 16) -> List[bytes]:
    return [bytes_[i : i + block_size] for i in range(0, len(bytes_), block_size)]


def gen_random_bytes(size: int = 16) -> bytes:
    return os.urandom(size)


def pkcs7_padding_add(bytes_: bytes, block_size: int = 16) -> bytes:
    padding = block_size - len(bytes_) % block_size
    return bytes_ + bytes([padding] * padding)


def pkcs7_padding_del(bytes_: bytes) -> bytes:
    index = len(bytes_) - 1
    padding = bytes_[index]

    for i in range(index, index - padding, -1):
        if bytes_[i] != padding:
            raise PKCS7BadPadding(bytes_[-padding:])

    return bytes_[:-padding]


def aes_ecb_encrypt(plain: bytes, key: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    plain_with_pad = pkcs7_padding_add(plain, len(key))
    return aes.encrypt(plain_with_pad)


def aes_ecb_decrypt(cipher: bytes, key: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    plain_with_pad = aes.decrypt(cipher)
    return pkcs7_padding_del(plain_with_pad)


def aes_cbc_encrypt(plain: bytes, key: bytes, iv: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    plain_with_padding = pkcs7_padding_add(plain, len(key))
    plain_blocks = get_blocks(plain_with_padding)
    cipher = bytes()
    block = iv

    for i in range(len(plain_blocks)):
        block = aes.encrypt(xor.xor_byte_arrays(plain_blocks[i], block))
        cipher += block

    return cipher


def aes_cbc_decrypt(cipher: bytes, key: bytes, iv: bytes) -> bytes:
    aes = AES.new(key, AES.MODE_ECB)
    cipher_blocks = get_blocks(cipher)
    plain = bytes()

    plain += xor.xor_byte_arrays(aes.decrypt(cipher_blocks[0]), iv)

    for i in range(1, len(cipher_blocks)):
        plain += xor.xor_byte_arrays(
            aes.decrypt(cipher_blocks[i]), cipher_blocks[i - 1]
        )

    return pkcs7_padding_del(plain)
