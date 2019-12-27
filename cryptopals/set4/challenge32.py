#!/usr/bin/env python3

from threading import Thread

import requests

from functions.server import start_flask_app


def challenge32(filename: str) -> bool:
    alphabet = "0123456789abcdef"
    url = "http://localhost:9000/test/fast?file={filename}&signature={signature}"

    response_time = {}
    sign = ""
    sign_size = 40

    for i in range(1, sign_size + 1):
        response_time = {c: 0 for c in alphabet}

        for c in alphabet:
            for _ in range(50):
                current_sign = sign + c + "0" * (sign_size - i)

                resp = requests.get(
                    url.format(filename=filename, signature=current_sign)
                )
                response_time[c] += resp.elapsed.total_seconds()

                if "Signature correct" in resp.text:
                    return True

        char_time_rank = [
            k
            for k, v in sorted(
                response_time.items(), key=lambda item: item[1], reverse=True
            )
        ]

        sign += char_time_rank[0]

    return False


if __name__ == "__main__":
    thread = Thread(target=start_flask_app, daemon=True)
    thread.start()

    assert challenge32("foo"), "The result does not match the expected value"

    print("Ok")
