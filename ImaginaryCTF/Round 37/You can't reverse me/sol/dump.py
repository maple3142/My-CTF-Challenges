from pwn import *
from base64 import b64encode, b64decode

with open("./hook.so", "rb") as f:
    bin_data = f.read()


def chunks(l, n):
    for i in range(0, len(l), n):
        yield l[i : i + n]


io = remote("ictf2.maple3142.net", 9898)

target_file = "/tmp/hook.so"

for chunk in chunks(bin_data, 1024):
    b = b64encode(chunk).decode()
    cmd = f"echo {b} | base64 -d >> {target_file}"
    io.sendline(cmd.encode())
io.sendline(f"chmod +x {target_file}".encode())
io.sendline(b"cd /tmp; echo done")
io.sendline(b"LD_PRELOAD=./hook.so /app/checker")
io.sendline(b"printf 'START'; cat dump.bin; printf 'END'")
io.recvuntil(b"START")
bn = io.recvuntil(b"END", drop=True)
with open("dump.bin", "wb") as f:
    f.write(bn)
io.sendline(b"echo binary dumped to dump.bin")
io.interactive()
