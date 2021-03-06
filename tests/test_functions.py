#!/usr/bin/env python3

import random

from Crypto.Util import Padding

from functions.aes import pkcs7_unpad, pkcs7_pad, gen_random_bytes, AESCipher
from functions.dh import DHClient
from functions.sha1 import sha1
from functions.xor import hamming


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
        counter = 0xF8F9FAFBFCFDFEFF
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )
        ct = bytes.fromhex(
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee"
        )

        cbc = AESCipher(
            AESCipher.MODE_CTR,
            key,
            nonce=nonce,
            counter=counter,
            counter_byteorder="big",
        )

        result = cbc.encrypt(pt)

        assert result == ct, "The result does not match the expected value"

    def test_aes_ctr_decrypt(self):
        key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
        nonce = bytes.fromhex("f0f1f2f3f4f5f6f7")
        counter = 0xF8F9FAFBFCFDFEFF
        ct = bytes.fromhex(
            "874d6191b620e3261bef6864990db6ce"
            "9806f66b7970fdff8617187bb9fffdff"
            "5ae4df3edbd5d35e5b4f09020db03eab"
            "1e031dda2fbe03d1792170a0f3009cee"
        )
        pt = bytes.fromhex(
            "6bc1bee22e409f96e93d7e117393172a"
            "ae2d8a571e03ac9c9eb76fac45af8e51"
            "30c81c46a35ce411e5fbc1191a0a52ef"
            "f69f2445df4f9b17ad2b417be66c3710"
        )

        cbc = AESCipher(
            AESCipher.MODE_CTR,
            key,
            nonce=nonce,
            counter=counter,
            counter_byteorder="big",
        )

        result = cbc.decrypt(ct)

        assert result == pt, "The result does not match the expected value"


class TestSHA1:
    def test_sha1_one_block(self):
        msg = b"abc"
        result = "a9993e364706816aba3e25717850c26c9cd0d89d"

        assert sha1(msg).hex() == result, "The result does not match the expected value"

    def test_sha1_two_block(self):
        msg = b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"
        result = "84983e441c3bd26ebaae4aa1f95129e5e54670f1"

        assert sha1(msg).hex() == result, "The result does not match the expected value"


class TestDH:
    def test_dh(self):
        p = int.from_bytes(
            bytes.fromhex(
                "ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024"
                "e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd"
                "3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec"
                "6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f"
                "24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361"
                "c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552"
                "bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff"
                "fffffffffffff"
            ),
            "big",
        )
        g = 2

        msg = b"test"

        a = DHClient(p, g)
        b = DHClient(p, g)

        a.gen_session_key(b.public_key)
        b.gen_session_key(a.public_key)

        encrypted_msg = a.encrypt_msg(msg)

        decrypted_msg = b.decrypt_msg(*encrypted_msg)

        assert decrypted_msg == msg, "The result does not match the expected value"
