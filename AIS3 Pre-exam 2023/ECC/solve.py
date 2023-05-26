import ast
import string
from collections import Counter
from fastecdsa.curve import secp256k1
from fastecdsa.point import Point
from fastecdsa.util import mod_sqrt


def lift_x(x, curve):
    y_squared = (x * x * x + curve.a * x + curve.b) % curve.p
    y1, y2 = mod_sqrt(y_squared, curve.p)
    R1, R2 = Point(x, y1, curve=curve), Point(x, y2, curve=curve)
    return R1, R2


p = secp256k1.p
ciphertext = ast.literal_eval(open("output.txt").read())

c1s = [c1 for c1, _, _ in ciphertext]

for k0P in lift_x(pow(ord("A"), -1, p) * c1s[0] % p, secp256k1):
    for k1P in lift_x(pow(ord("I"), -1, p) * c1s[1] % p, secp256k1):
        dP = k1P - k0P
        k2P_cand = k1P + dP
        if pow(k2P_cand.x, -1, p) * c1s[2] % p < 256:
            break

s = k0P
for c in c1s:
    print(chr(pow(s.x, -1, p) * c % p), end="")
    s += dP
