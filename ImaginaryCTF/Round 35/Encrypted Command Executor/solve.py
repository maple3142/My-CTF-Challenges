from pwn import *
from base64 import b64decode, b64encode
from shlex import quote
import string
from tqdm import tqdm

io = process(["python", "server.py"])
# io = remote("localhost", 9999)


def blocks(x, n):
    return [x[i : i + n] for i in range(0, len(x), n)]


def get_enc_block(pt):
    if len(pt) != 16:
        return
    cmd = "echo %s" % quote(pt)
    if pt not in cmd:
        return
    pad = ""
    while cmd.index(pt) % 16 != 0:
        pad = "x" + pad
        cmd = "echo %s" % quote(pad + pt)
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Message: ", (pad + pt).encode())
    io.recvuntil(b"result: ")
    ct = b64decode(io.recvline().strip())
    return blocks(ct, 16)[1]


def get_last_padding():
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Message: ", b"x" * 11)
    io.recvuntil(b"result: ")
    ct = b64decode(io.recvline().strip())
    return blocks(ct, 16)[-1]


LAST_PADDING = get_last_padding()


def gen_command(cmd):
    pad = 16 - len(cmd) % 16
    ct = b""
    for blk in blocks(cmd + " " * pad, 16):
        ct += get_enc_block(blk)
    ct += LAST_PADDING
    return ct


PREFIX = "y" * 15


def get_flag_idx(n: int):
    ct = gen_command(f"printf {PREFIX};cat /flag | cut -c{n}")
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Encrypted command: ", b64encode(ct))
    io.recvuntil(b"result: ")
    return b64decode(io.recvline().strip())


chrs = string.ascii_lowercase + string.ascii_uppercase + string.digits + "{_}"
tbl = {get_enc_block(PREFIX + c): c for c in tqdm(chrs, desc="Building table")}
flag = ""
for i in range(1, 100):
    blk0 = blocks(get_flag_idx(i), 16)[0]
    flag += tbl[blk0]
    print(flag)
    if flag[-1] == "}":
        break
