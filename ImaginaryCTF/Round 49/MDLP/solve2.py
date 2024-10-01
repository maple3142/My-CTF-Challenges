from sage.all import *
import subprocess
from Crypto.Util.number import sieve_base
from tqdm import tqdm
from lll_cvp import solve_underconstrained_equations_general

p = 60136177367560631039092956703653203338217286978701852857028839528525260293087
q = (p - 1) // 2
y = 36460313315646730969501498120968068746377445179920045296321232935228480996523
ps = sieve_base[:23]

# for convenience, we force everything into the q-torsion subgroup
y = pow(y, 2, p)
ps = [pow(x, 2, p) for x in ps]


def solve_dlp(ts):
    targets = ",".join(map(str, ts))
    out = (
        subprocess.check_output(
            ["cado-nfs.py", "-dlp", "-ell", str(q), f"target={targets}", str(p)]
        )
        .strip()
        .decode()
    )
    return list(map(int, out.split(",")))


*dlps, dy = solve_dlp(ps + [y])
print(
    dy
)  # 26538796780882712233621757626223610680134248177802750559887935637756806753369

xs = PolynomialRing(GF(q), "x", 23).gens()
f = vector(xs) * vector(dlps) - dy
print(f)
bounds = {x: 128 for x in xs}
for _, sol in solve_underconstrained_equations_general(q, [f], bounds):
    print(bytes(sol[:-1]))
    break
