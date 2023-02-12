from pwn import *

# context.log_level = 'debug'

# io = process(["python", "challenge.py"])
io = remote("jp.zoolab.org", 10011)
io.recvuntil(b"n = ")
n = int(io.recvlineS())
e = 65537
io.recvuntil(b"c = ")
c = int(io.recvlineS())


def oracle(c):
    io.sendlineafter(b"c = ", str(c).encode())
    return int(io.recvlineS())


def crack(c, n, e, oracle):
    a = pow(7, -1, n)
    cm2 = pow(a, e, n)
    bits = [oracle(c)]
    for _ in range(31):
        c = (c * cm2) % n
        r = oracle(c)
        k = sum((pow(a, i + 1, n) * b) % n for i, b in enumerate(bits[::-1])) % n
        bits.append((r - k) % 7)
    return int("".join(map(str, bits[::-1])), 7)


m = crack(c, n, e, oracle)
io.sendlineafter(b"m = ", str(m).encode())
print(io.recvlineS().strip())
