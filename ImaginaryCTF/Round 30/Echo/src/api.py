from flask import Flask, request
import os

app = Flask(__name__)


@app.post("/echo")
def echo():
    return request.stream.read()


@app.route("/flag", methods=["FLAG_PLEASE"])
def flag():
    return os.environ.get("FLAG", "flag{test_flag}")

# gunicorn -k gevent --keep-alive 1 --bind 0.0.0.0:7777 api:app
