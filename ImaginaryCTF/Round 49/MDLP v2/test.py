from sage.all import *
from Crypto.Util.number import sieve_base
import re, math, string
from lll_cvp import flatter

with open("flag.txt", "rb") as f:
    flag = f.read().strip()
assert re.fullmatch(r"ictf\{[a-zA-Z0-9_]{23}\}", flag.decode())
secret = flag[5:-1]

p = 16772840378381243842066048784688853957423046860638774659798751363803587745626801644318311555716492505211797256362777839879035568112648021357575189005942639992451427473134669625140202260399749619120960708132141636534797458638157387694646733301916665038271994700044932407416439883675026706679040221556491794719771476834979296493099969411147296731792715449629105727787022814345378634690038383348758558254912695438400827004525431080873196634565104529212324504485921380380999261999944310601941742297981272042622308964121378662555829776023082112631490889049991032811467272985431102946180316750594939614734989949107285600303
yr = math.prod(g**x for g, x in zip(sieve_base, secret))
y = yr % p


def small_roots(self, X=None, beta=1.0, epsilon=None, **kwds):
    from sage.misc.verbose import verbose
    from sage.matrix.constructor import Matrix
    from sage.rings.real_mpfr import RR

    N = self.parent().characteristic()

    if not self.is_monic():
        raise ArithmeticError("Polynomial must be monic.")

    beta = RR(beta)
    if beta <= 0.0 or beta > 1.0:
        raise ValueError("0.0 < beta <= 1.0 not satisfied.")

    f = self.change_ring(ZZ)

    P, (x,) = f.parent().objgens()

    delta = f.degree()

    if epsilon is None:
        epsilon = beta / 8
    verbose("epsilon = %f" % epsilon, level=2)

    m = max(beta**2 / (delta * epsilon), 7 * beta / delta).ceil()
    verbose("m = %d" % m, level=2)

    t = int((delta * m * (1 / beta - 1)).floor())
    verbose("t = %d" % t, level=2)

    if X is None:
        X = (0.5 * N ** (beta**2 / delta - epsilon)).ceil()
    verbose("X = %s" % X, level=2)

    # we could do this much faster, but this is a cheap step
    # compared to LLL
    g = [x**j * N ** (m - i) * f**i for i in range(m) for j in range(delta)]
    g.extend([x**i * f**m for i in range(t)])  # h

    B = Matrix(ZZ, len(g), delta * m + max(delta, t))
    for i in range(B.nrows()):
        for j in range(g[i].degree() + 1):
            B[i, j] = g[i][j] * X**j

    print("dim", B.dimensions())
    B = flatter(B)

    f = sum([ZZ(B[0, i] // X**i) * x**i for i in range(B.ncols())])
    R = f.roots()

    ZmodN = self.base_ring()
    return [r for r, m in R]
    roots = set([ZmodN(r) for r, m in R if abs(r) <= X])
    Nbeta = N**beta
    return [root for root in roots if N.gcd(ZZ(self(root))) >= Nbeta]


bs = (string.ascii_letters + string.digits).encode()
mn = min(bs)
mx = max(bs)

# yr: prod(g**x) without modulo
# so y = yr (mod p)
T = math.prod(sieve_base[:23])
# note: yr % (T**mn) == 0
y = y * pow(T, -mn, p) % p
yrt = yr // T**mn

M = T ** (mx - mn)  # yrt is a unknown divisor of M
k = polygen(Zmod(M))
f = y + k * p  # k is yrt // p
# beta is log(yrt) / log(M)
# since yr isn't known, you have to guess try some fake flags locally and guess X and beta
rs = small_roots(f.monic(), X=2**3600, beta=0.65, epsilon=0.02)
print(rs)
print(factor(ZZ(f(rs[0])), limit=2**10))
