#!/usr/bin/env python3

import pathlib


class TestSet1:
    def test_challenge01(self):
        from cryptopals.set1.challenge01 import challenge01, BYTES, RESULT

        res = challenge01(BYTES)

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge02(self):
        from cryptopals.set1.challenge02 import challenge02, BYTES_A, BYTES_B, RESULT

        res = challenge02(BYTES_A, BYTES_B)

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge03(self):
        from cryptopals.set1.challenge03 import challenge03, CIPHER_TEXT, RESULT

        res = challenge03(CIPHER_TEXT)

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge04(self):
        from cryptopals.set1.challenge04 import challenge04, RESULT

        res = challenge04(
            pathlib.Path(__file__).absolute().parent.parent / "data" / "4.txt"
        )

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge05(self):
        from cryptopals.set1.challenge05 import challenge05, TEXT, KEY, RESULT

        res = challenge05(TEXT, KEY)

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge06(self):
        from cryptopals.set1.challenge06 import challenge06, RESULT

        res = challenge06(
            pathlib.Path(__file__).absolute().parent.parent / "data" / "6.txt"
        )

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge07(self):
        from cryptopals.set1.challenge07 import challenge07, RESULT

        res = challenge07(
            pathlib.Path(__file__).absolute().parent.parent / "data" / "7.txt"
        )

        assert res == RESULT, "The result does not match the expected value"

    def test_challenge08(self):
        from cryptopals.set1.challenge08 import challenge08, RESULT

        res = challenge08(
            pathlib.Path(__file__).absolute().parent.parent / "data" / "8.txt"
        )

        assert res == RESULT, "The result does not match the expected value"
