from pwn import process, remote
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Util.Padding import pad


def get_data():
    # io = process(["python", "server.py"])
    io = remote("ictf.maple3142.net", 1337)
    io.recvuntil(b"p = ")
    p = int(io.recvline().strip())
    io.recvuntil(b"g = ")
    g = int(io.recvline().strip())
    io.recvuntil(b"y = ")
    y = int(io.recvline().strip())
    io.close()
    return p, g, y


aa = []
mm = []
while True:
    p, g, y = get_data()
    F = GF(p)
    for q, _ in factor(p - 1, limit=2 ^ 25):
        # ignore the exponent to simplify it
        cf = (p - 1) // q
        if not is_prime(q) or q.bit_length() >= 25 or pow(g, cf, p) == 1 or q in mm:
            continue
        x = discrete_log(F(y) ^ cf, F(g) ^ cf, ord=q)
        print(f"flag = {x} (mod {q})")
        aa.append(x)
        mm.append(q)
    for i in range(1, 128):
        # we don't know the padding, so just guess it
        a = bytes_to_long(pad(b"\x00" * i, 256))
        m = 1 << ((256 - i) * 8)
        try:
            x = crt(aa + [a], mm + [m])
            flag = long_to_bytes(x)
            if flag.startswith(b"ictf{"):
                print(flag)
                exit()
        except ValueError:
            pass
