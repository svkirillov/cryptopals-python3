#!/usr/bin/env python3

import pathlib


class TestSet4:
    def test_challenge25(self):
        from cryptopals.set4.challenge25 import challenge25

        assert challenge25(
            pathlib.Path(__file__).absolute().parent.parent / "data" / "25.txt"
        ), "The result does not match the expected value"

    def test_challenge26(self):
        from cryptopals.set4.challenge26 import challenge26

        assert challenge26(), "The result does not match the expected value"

    def test_challenge27(self):
        from cryptopals.set4.challenge27 import challenge27

        assert challenge27(), "The result does not match the expected value"

    def test_challenge28(self):
        from cryptopals.set4.challenge28 import challenge28

        assert challenge28(), "The result does not match the expected value"

    def test_challenge29(self):
        from cryptopals.set4.challenge29 import challenge29

        assert challenge29(), "The result does not match the expected value"
