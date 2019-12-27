from math import ceil
from random import getrandbits
from typing import Tuple

from functions.aes import AESCipher, gen_random_bytes, pkcs7_pad, pkcs7_unpad
from functions.sha1 import sha1


class DHClient:
    def __init__(self, p_: int, g_: int):
        self.p = p_
        self.g = g_
        self._private_key = getrandbits(1024) % self.p
        self.public_key = pow(self.g, self._private_key, self.p)
        self._session_key = 0

    def gen_session_key(self, public_key: int) -> None:
        self._session_key = pow(public_key, self._private_key, self.p)

    def encrypt_msg(self, msg: bytes) -> Tuple[bytes, bytes]:
        key = sha1(
            self._session_key.to_bytes(ceil(self._session_key.bit_length() / 8), "big")
        )[:16]
        iv = gen_random_bytes(16)

        cbc = AESCipher(AESCipher.MODE_CBC, key, iv=iv)

        return (iv, cbc.encrypt(pkcs7_pad(msg)))

    def decrypt_msg(self, iv: bytes, msg: bytes) -> bytes:
        key = sha1(
            self._session_key.to_bytes(ceil(self._session_key.bit_length() / 8), "big")
        )[:16]

        cbc = AESCipher(AESCipher.MODE_CBC, key, iv=iv)

        return pkcs7_unpad(cbc.decrypt(msg))
