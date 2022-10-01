from Crypto.Util.number import *

exec(open("output.txt").read())

L = matrix(es).T.augment(matrix.identity(len(es)))
L[:, 0] *= 2 ^ 2048
L = L.LLL()
print(L[0][1:])
print(L[1][1:])
xx = product([ZZ(y) ^ x for x, y in zip(L[0][1:], cs)])
yy = product([ZZ(y) ^ x for x, y in zip(L[1][1:], cs)])
n = gcd(xx.numer() - xx.denom(), yy.numer() - yy.denom())
print(n)

g, x, y = xgcd(es[0], es[1])
m = ZZ(pow(cs[0], x, n) * pow(cs[1], y, n)) % n
print(long_to_bytes(m))
