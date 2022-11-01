exec(open("output.txt").read())

LEN = 2048 // 8
blks = [iv] + [ct[i : i + LEN] for i in range(0, len(ct), LEN)]
blks = [int.from_bytes(x, "big") for x in blks]

P = PolynomialRing(Zmod(n), "x")
x = P.gen()
for prv, cur in zip(blks, blks[1:]):
    f = (prv + x) ** 9 - cur
    m = f.small_roots(X=2**128, epsilon=0.055)[0]
    print(int(m).to_bytes(16, "big").decode(), end="", flush=True)
