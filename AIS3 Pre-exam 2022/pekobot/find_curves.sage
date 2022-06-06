proof.arithmetic(False)
p = 2**256 - 2**224 + 2**192 + 2**96 - 1
F = GF(p)
a = -3
n = 115792089210356248762697446949407573529996955224135760342422259061068512044369
prod = 1
ar = []
for b in range(1, 15):
    if b in [-2, 2]:
        # singular
        continue
    E = EllipticCurve(F, [a, b])
    G = E.gen(0)
    od = G.order()
    fac = od.factor()
    subgroups = [
        f ^ e for f, e in fac if gcd(f ^ e, prod) == 1 and f ^ e < 2 ^ 32
    ]  # very small
    ar.append((b, G.xy(), od, subgroups))
    prod = lcm(prod, product(subgroups))
    print(prod)
    if prod > n:
        break


print(ar)
