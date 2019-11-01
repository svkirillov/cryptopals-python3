#!/usr/bin/env python3

import random

from Crypto.Util import Padding

from functions import xor, aes


class TestFunctions:
    def test_hamming(self):
        a = bytes("this is a test".encode("ascii"))
        b = bytes("wokka wokka!!!".encode("ascii"))
        c = xor.hamming(a, b)

        assert c == 37, "The result does not match the expected value"

    def test_pkcs7_padding_add(self):
        a = aes.gen_random_bytes(random.randint(1, 16))
        b = aes.pkcs7_padding_add(a)
        c = Padding.pad(a, 16)

        assert b == c, "The result does not match the expected value"

    def test_pkcs7_padding_add_block(self):
        a = aes.gen_random_bytes()
        b = aes.pkcs7_padding_add(a)
        c = Padding.pad(a, 16)

        assert b == c, "The result does not match the expected value"

    def test_pkcs7_padding_del(self):
        a = aes.gen_random_bytes(random.randint(1, 16))
        b = Padding.pad(a, 16)
        c = aes.pkcs7_padding_del(b)

        assert c == a, "The result does not match the expected value"

    def test_pkcs7_padding_del_block(self):
        a = aes.gen_random_bytes()
        b = Padding.pad(a, 16)
        c = aes.pkcs7_padding_del(b)

        assert c == a, "The result does not match the expected value"

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
            "a254be88e037ddd9d79fb6411c3f9df8"  # Padding block
        )

        result = aes.aes_ecb_encrypt(pt, key)

        assert result == ct, "The result does not match the expected value"

    def test_aes_ecb_decrypt(self):
        # Test vectors from NIST Special Publication 800-38A 2001 Edition

        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        ct = bytes.fromhex(
            "3ad77bb40d7a3660a89ecaf32466ef97"
            "f5d3d58503b9699de785895a96fdbaaf"
            "43b1cd7f598ece23881b00e3ed030688"
            "7b0c785e27e8ad3f8223207104725dd4"
            "a254be88e037ddd9d79fb6411c3f9df8"  # Padding block
        )
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )

        result = aes.aes_ecb_decrypt(ct, key)

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
            "8cb82807230e1321d3fae00d18cc2012"  # Padding block
        )

        result = aes.aes_cbc_encrypt(pt, key, iv)

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
            "8cb82807230e1321d3fae00d18cc2012"  # Padding block
        )
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )

        result = aes.aes_cbc_decrypt(ct, key, iv)

        assert result == pt, "The result does not match the expected value"
