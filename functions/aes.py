import os
from typing import List, Optional, Union

from Crypto.Cipher import AES

from functions.xor import xor_byte_arrays


class PKCS7Error(Exception):
    def __init__(self, error_args: Union[str, Exception]):
        super().__init__(self)
        self._error_args = error_args

    @property
    def error_args(self):
        return self._error_args

    def __str__(self):
        return f"Oops! Error occurred in PKCS#7 padding function: {self._error_args}"


class AESError(Exception):
    def __init__(self, error_args: Union[str, Exception]):
        super().__init__(self)
        self._error_args = error_args

    @property
    def error_args(self):
        return self._error_args

    def __str__(self):
        return f"Oops! Error occurred in AES function: {self._error_args}."


class AESCipher:
    MODE_ECB = 1
    MODE_CBC = 2
    MODE_CTR = 3

    def __init__(
        self,
        mode: int,
        key: bytes,
        *,
        iv: Optional[bytes] = None,
        nonce: Optional[bytes] = None,
        counter: Optional[int] = None,
    ) -> None:
        if len(key) not in (16, 24, 32):
            raise AESError(f"wrong key length")

        self._mode: int = mode
        self._key: bytes = key
        self._block_size: int = len(key)
        self._iv = None
        self._nonce = None
        self._counter = None

        self._aes = AES.new(self._key, AES.MODE_ECB)

        if mode == self.MODE_ECB:
            self.encrypt = self._aes_ecb_encrypt
            self.decrypt = self._aes_ecb_decrypt
        elif mode == self.MODE_CBC:
            self._iv = iv
            if len(self._iv) != self._block_size:
                raise AESError("bad iv size")
            self.encrypt = self._aes_cbc_encrypt
            self.decrypt = self._aes_cbc_decrypt
        elif mode == self.MODE_CTR:
            self._nonce = nonce
            if len(self._nonce) != self._block_size // 2:
                raise AESError("bad nonce size")
            self._counter = 0 if counter is None else counter
            self.encrypt = self._aes_ctr_encrypt
            self.decrypt = self._aes_ctr_decrypt
        else:
            raise AESError("unknown AES mode")

    def _aes_ecb_encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) % self._block_size:
            raise AESError("bad plaintext length")

        return self._aes.encrypt(plaintext)

    def _aes_ecb_decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % self._block_size:
            raise AESError("bad ciphertext length")

        return self._aes.decrypt(ciphertext)

    def _aes_cbc_encrypt(self, plaintext: bytes) -> bytes:
        if len(plaintext) % self._block_size:
            raise AESError("bad plaintext length")

        pt_blocks = get_blocks(plaintext)
        ct = bytes()
        block = self._iv

        for i in range(len(pt_blocks)):
            block = self._aes.encrypt(xor_byte_arrays(pt_blocks[i], block))
            ct += block

        return ct

    def _aes_cbc_decrypt(self, ciphertext: bytes) -> bytes:
        if len(ciphertext) % self._block_size:
            raise AESError("bad ciphertext length")

        ct_blocks = get_blocks(ciphertext)
        pt = bytes()

        pt += xor_byte_arrays(self._aes.decrypt(ct_blocks[0]), self._iv)

        for i in range(1, len(ct_blocks)):
            pt += xor_byte_arrays(self._aes.decrypt(ct_blocks[i]), ct_blocks[i - 1])

        return pt

    def _aes_ctr_encrypt(self, plaintext: bytes) -> bytes:
        length = len(plaintext) // self._block_size + (
            len(plaintext) % self._block_size > 0
        )

        pt_blocks = get_blocks(plaintext)

        ct = bytes()

        for i in range(length):
            ct += xor_byte_arrays(
                pt_blocks[i],
                self._aes.encrypt(
                    self._nonce + self._counter.to_bytes(8, byteorder="little")
                ),
            )
            self._counter += 1

        return ct

    def _aes_ctr_decrypt(self, ciphertext: bytes) -> bytes:
        return self._aes_ctr_encrypt(ciphertext)


def get_blocks(bytes_: bytes, block_size: int = 16) -> List[bytes]:
    return [bytes_[i : i + block_size] for i in range(0, len(bytes_), block_size)]


def gen_random_bytes(size: int = 16) -> bytes:
    return os.urandom(size)


def pkcs7_pad(bytes_: bytes, block_size: int = 16) -> bytes:
    padding = block_size - len(bytes_) % block_size
    return bytes_ + bytes([padding] * padding)


def pkcs7_unpad(bytes_: bytes, block_size: int = 16) -> bytes:
    if len(bytes_) % block_size != 0:
        raise PKCS7Error("bad data size")

    index = len(bytes_) - 1
    padding = bytes_[index]

    if padding == 0 or padding > block_size:
        raise PKCS7Error(f"bad padding: {bytes_[-1:]}")

    for i in range(index - 1, index - padding, -1):
        if bytes_[i] != padding:
            raise PKCS7Error(f"bad padding: {bytes_[-padding:]}")

    return bytes_[:-padding]
