from flask import Flask, request, make_response
from socket import socket, AF_INET, SOCK_STREAM
import os
import re
import time

API_HOST = os.environ.get("API_HOST", "localhost")
API_PORT = int(os.environ.get("API_PORT", 7777))
MESSAGE_REGEX = re.compile(r"[A-Za-z0-9_+\-.:/?= ]+")  # some ASCII chars

# requests is bloat :(
def parse_http_response_body(data):
    header, body = data.split(b"\r\n\r\n", 1)
    if b"transfer-encoding: chunked" in header.lower():
        body = b"".join(body.split(b"\r\n")[1::2])
    return body


def build_http(host, port, method, path, body):
    return f"""{method} {path} HTTP/1.1\r
Host: {host}:{port}\r
Content-Length: {len(body)}\r
\r
{body}""".encode()


def make_http_request(host, port, method, path, body, chunk_size=1024):
    payload = build_http(host, port, method, path, body)
    s = socket(AF_INET, SOCK_STREAM)
    s.connect((host, port))
    for i in range(0, len(payload), chunk_size):
        s.send(payload[i : i + chunk_size])
        time.sleep(0.1)
    data = b""
    while True:
        r = s.recv(chunk_size)
        if not r:
            break
        data += r
    return parse_http_response_body(data)


app = Flask(__name__)


@app.get("/")
def index():
    return """
<form action=/echo method=POST>
    <p>
        <label>Message: </label>
        <input name=msg>
    </p>
    <button type=submit>Echo</button
</form>
"""


@app.post("/echo")
def echo():
    msg = request.form.get("msg", "")
    if not MESSAGE_REGEX.match(msg):
        return "Invalid message", 400
    resp = make_response(make_http_request(API_HOST, API_PORT, "POST", "/echo", msg))
    resp.content_type = "text/plain; charset=utf-8"
    return resp

# gunicorn -k gevent --keep-alive 1 --bind 0.0.0.0:8888 app:app
