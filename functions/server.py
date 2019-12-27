#!/usr/bin/env python3

from time import sleep

from flask import Flask
from flask import request

from functions.sha1 import HMACSHA1


app = Flask(__name__)

host = "127.0.0.1"
port = "9000"


KEY = b"YELLOW SUBMARINE"

# http://localhost:9000/test?file=foo&signature=274b7c4d98605fcf739a0bf9237551623f415fb8
@app.route("/test/<string:mode>", methods=["GET"])
def test(mode: str) -> str:
    hmac = HMACSHA1(KEY)

    data = request.args["file"].encode()
    signature = request.args["signature"]
    time = 0.05 if mode == "slow" else 0.005

    data_hmac = hmac.hmac(data).hex()

    if len(signature) != len(data_hmac):
        return "Invalid signature size"

    result = insecure_compare(signature, data_hmac, time)

    if result:
        return "Signature is correct"

    # return {"sign": signature, "data_hmac": data_hmac.hex()}
    return "Signature is incorrect"


def insecure_compare(s1: str, s2: str, time: float) -> bool:
    for c1, c2 in zip(s1, s2):
        if c1 != c2:
            return False
        sleep(time)
        # TODO 0.005
    return True


def start_flask_app() -> None:
    app.run(host, port)


if __name__ == "__main__":
    start_flask_app()
