from sage.all import *
from chall import LF3R, MASK, n
from output import stream
import random

m = 2048
out = stream[:m]
flag_enc = stream[m:]

M2 = []
for i in range(n):
    lf = LF3R(n, 1 << i, MASK)
    M2.append([(lf.state & 1, lf())[0] for _ in range(m)])
M2 = matrix(GF(2), M2)
# vector(key_bits) * M2 == vector(lfsr_lsb_stream)

M3 = matrix(GF(3), m, m - n + 1)
pow_vec = vector([2**i for i in range(n)])
for i in range(m - n + 1):
    M3[i : i + n, i] = pow_vec
# vector(lfsr_lsb_stream) * M3 == vector(out[: m - n + 1])

print("solve system", M3.dimensions())
sol = M3.solve_left(vector(out[: m - n + 1]))
lk = M3.left_kernel_matrix()
# vector(lfsr_lsb_stream) = sol + t * lk (mod 3)

# a stupid randomized algorithm to find the solution
print("monte carlo")
while True:
    ss = sol
    for v in lk:
        if random.randint(0, 1):
            ss += v
    for _ in range(1000):
        two_idx = [i for i, v in enumerate(ss) if v == 2]
        if len(two_idx) == 0:
            break
        idx = random.choice(two_idx)
        ss += next(v for v in lk if v[idx])
    try:
        kv = M2.solve_left(ss.change_ring(ZZ))
        print("found", kv)
        break
    except ValueError:
        print("failed", ss)
        continue

key = int(sum([x * 2**i for i, x in enumerate(kv.change_ring(ZZ))]))
lf3r = LF3R(n, key, MASK)
for i in range(m):
    assert lf3r() == out[i]
flag_digits = []
for x in flag_enc:
    flag_digits.append((x - lf3r()) % 3)
flag_int = sum([x * 3**i for i, x in enumerate(flag_digits)])
flag = int(flag_int).to_bytes((flag_int.bit_length() + 7) // 8, "big")
print(flag)
