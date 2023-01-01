from Crypto.Util.number import getStrongPrime, bytes_to_long
from Crypto.Util.Padding import pad
import os

flag = os.environb.get(b"FLAG", b"ictf{test_flag}")
assert len(flag) < 128
x = bytes_to_long(pad(flag, 256))

# getPrime is not good :(
p = getStrongPrime(1024)
g = 2
y = pow(g, x, p)
print(f"{p = }")
print(f"{g = }")
print(f"{y = }")
