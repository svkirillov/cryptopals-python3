#!/usr/bin/env python3

import random

from Crypto.Util import Padding

from functions.xor import hamming
from functions.aes import pkcs7_unpad, pkcs7_pad, gen_random_bytes, AESCipher


class TestXorFunctions:
    def test_hamming(self):
        a = bytes("this is a test".encode("ascii"))
        b = bytes("wokka wokka!!!".encode("ascii"))
        c = hamming(a, b)

        assert c == 37, "The result does not match the expected value"


class TestPKCS7:
    def test_pkcs7_padding_add(self):
        a = gen_random_bytes(random.randint(1, 16))
        b = pkcs7_pad(a)
        c = Padding.pad(a, 16)

        assert b == c, "The result does not match the expected value"

    def test_pkcs7_padding_add_block(self):
        a = gen_random_bytes()
        b = pkcs7_pad(a)
        c = Padding.pad(a, 16)

        assert b == c, "The result does not match the expected value"

    def test_pkcs7_padding_del(self):
        a = gen_random_bytes(random.randint(1, 16))
        b = Padding.pad(a, 16)
        c = pkcs7_unpad(b)

        assert c == a, "The result does not match the expected value"

    def test_pkcs7_padding_del_block(self):
        a = gen_random_bytes()
        b = Padding.pad(a, 16)
        c = pkcs7_unpad(b)

        assert c == a, "The result does not match the expected value"


class TestAES:
    def test_aes_ecb_encrypt(self):
        # Test vectors from NIST Special Publication 800-38A 2001 Edition

        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        ct = bytes.fromhex(
            "3ad77bb40d7a3660a89ecaf32466ef97"
            "f5d3d58503b9699de785895a96fdbaaf"
            "43b1cd7f598ece23881b00e3ed030688"
            "7b0c785e27e8ad3f8223207104725dd4"
        )

        ecb = AESCipher(AESCipher.MODE_ECB, key)

        result = ecb.encrypt(pt)

        assert result == ct, "The result does not match the expected value"

    def test_aes_ecb_decrypt(self):
        # Test vectors from NIST Special Publication 800-38A 2001 Edition

        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ct = bytes.fromhex(
            "3ad77bb40d7a3660a89ecaf32466ef97"
            "f5d3d58503b9699de785895a96fdbaaf"
            "43b1cd7f598ece23881b00e3ed030688"
            "7b0c785e27e8ad3f8223207104725dd4"
        )
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )

        ecb = AESCipher(AESCipher.MODE_ECB, key)

        result = ecb.decrypt(ct)

        assert result == pt, "The result does not match the expected value"

    def test_aes_cbc_encrypt(self):
        # Test vectors from NIST Special Publication 800-38A 2001 Edition

        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        ct = bytes.fromhex(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        )

        cbc = AESCipher(AESCipher.MODE_CBC, key, iv=iv)

        result = cbc.encrypt(pt)

        assert result == ct, "The result does not match the expected value"

    def test_aes_cbc_decrypt(self):
        # Test vectors from NIST Special Publication 800-38A 2001 Edition

        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        iv = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
        ct = bytes.fromhex(
            "7649abac8119b246cee98e9b12e9197d"
            "5086cb9b507219ee95db113a917678b2"
            "73bed6b8e3c1743b7116e69e22229516"
            "3ff1caa1681fac09120eca307586e1a7"
        )
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )

        cbc = AESCipher(AESCipher.MODE_CBC, key, iv=iv)

        result = cbc.decrypt(ct)

        assert result == pt, "The result does not match the expected value"

    def test_aes_ctr_encrypt(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        nonce = bytes.fromhex("f0f1f2f3f4f5f6f7")
        counter = 0
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        ct = bytes.fromhex(
            "67ee05547499f8bcf0c38324e8605c28"
            "525d5e12872acb0bc8bc4378d1bd42b1"
            "58f03c2f330fbaa4c3f99afff5103d83"
            "77500b263590f755a6fba4f9949eac46"
        )

        cbc = AESCipher(AESCipher.MODE_CTR, key, nonce=nonce, counter=counter)

        result = cbc.encrypt(pt)

        assert result == ct, "The result does not match the expected value"

    def test_aes_ctr_decrypt(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        nonce = bytes.fromhex("f0f1f2f3f4f5f6f7")
        counter = 0
        ct = bytes.fromhex(
            "67ee05547499f8bcf0c38324e8605c28"
            "525d5e12872acb0bc8bc4378d1bd42b1"
            "58f03c2f330fbaa4c3f99afff5103d83"
            "77500b263590f755a6fba4f9949eac46"
        )
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )

        cbc = AESCipher(AESCipher.MODE_CTR, key, nonce=nonce, counter=counter)

        result = cbc.decrypt(ct)

        assert result == pt, "The result does not match the expected value"
