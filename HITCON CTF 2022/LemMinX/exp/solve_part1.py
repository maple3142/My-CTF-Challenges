from pwn import *
from pprint import pp
import json
import sys

# context.log_level = 'debug'

# io = process(
#     ["./lemminx-linux"],
#     env={"LEMMINX_DEBUG": "true"},
# )
host = sys.argv[1]
port = int(sys.argv[2])
io = remote(host, port)

def rpc(io, obj):
    s = json.dumps(obj)
    io.send(f"Content-Length: {len(s)}\r\n\r\n{s}".encode())


def recv(io):
    io.recvuntil(b"Content-Length: ")
    n = int(io.recvlineS().strip())
    io.recvn(2)  # \r\n\r\n
    r = io.recvn(n).decode()
    return json.loads(r)


rpc(
    io,
    {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": json.loads(open("init.json").read()),
        "id": 1,
    },
)
print("init")
pp(recv(io))  # initialize response
rpc(
    io,
    {
        "jsonrpc": "2.0",
        "method": "initialized",
        "params": {},
        "id": 1,
    },
)

rpc(
    io,
    {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": "file:///home/maple3142/tmp/hello.xml",
                "languageId": "xml",
                "version": 1,
                "text": open("hello.xml").read(),
            }
        },
    },
)
print("didOpen hello.xml")
pp(resp := recv(io))  # client/registerCapability
rpc(
    io,
    {
        "jsonrpc": "2.0",
        "id": resp["id"],
        "result": None,
    },
)
pp(recv(io))  # textDocument/publishDiagnostics

rpc(
    io,
    {
        "jsonrpc": "2.0",
        "method": "textDocument/hover",
        "params": {
            "textDocument": {"uri": "file:///home/maple3142/tmp/hello.xml"},
            "position": {"line": 4, "character": 6}
        },
        'id': 487
    },
)
print('hovered')
pp(recv(io))

print("interactive")
io.interactive()
