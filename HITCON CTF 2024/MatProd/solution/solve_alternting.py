from sage.all import *
import sys
from chall import alternating as cry
from lll_cvp import flatter
from tqdm import trange
import random

output_file = sys.argv[1] if len(sys.argv) > 1 else "output.sobj"

pub, M = load(output_file)["challenges"][1]


ABars = pub
n, k, a, p = (cry.n, cry.k, cry.a, cry.p)
F = GF(p)


def apply_bits(As, bits):
    if len(bits) == 0:
        return matrix.identity(F, n)
    M = As[0][bits[0]]
    for i in range(1, len(bits)):
        M = M * As[i][bits[i]]
    return M


def mp(x):
    if x >= p // 2:
        return int(x) - p
    return int(x)


rand = random.SystemRandom()
recovered = [None] * k
front_i = 0
back_i = k
curM = M
curABars = ABars[:]
while None in recovered:
    fsel = 7
    bsel = 7
    nonecnt = recovered.count(None)
    if fsel + bsel > nonecnt:
        fsel = nonecnt // 2
        bsel = nonecnt - fsel
    Mbase = []
    frontM = []
    backM = []
    for i in range(1 << fsel):
        bf = [int(x) for x in f"{i:0{fsel}b}"]
        frontM.append(~apply_bits(curABars, bf))
    for j in range(1 << bsel):
        bb = [int(x) for x in f"{j:0{bsel}b}"]
        backM.append(~apply_bits(curABars[-bsel:], bb))
    for i in trange(1 << fsel):
        for j in range(1 << bsel):
            Mbase.append(frontM[i] * curM * backM[j])
    print("Mbase prepared")

    # check for edge case (I present in Mbase)
    done = False
    for i, mb in enumerate(Mbase):
        if mb == 1:
            rec_bs = [int(x) for x in f"{i:0{fsel + bsel}b}"]
            front = rec_bs[:fsel]
            back = rec_bs[-bsel:]
            recovered[front_i : front_i + fsel] = rec_bs[:fsel]
            recovered[back_i - bsel : back_i] = rec_bs[-bsel:]
            front_i += fsel
            back_i -= bsel
            print(recovered)
            done = True
    if done:
        break

    # some shitty heuristic parameters tuning...
    n_samples = 0
    if k == 64:
        n_samples = 200
        if nonecnt <= 50:
            n_samples = 128
    if k == 128:
        n_samples = 350
        if nonecnt <= 120:
            n_samples = 256
        if nonecnt <= 80:
            n_samples = 150
        if nonecnt <= 50:
            n_samples = 128
    kersize = n_samples - n * n
    used = set()
    Mrs = []
    while len(Mrs) < n_samples:
        bb = tuple(cry.encode(rand.getrandbits(k))[front_i:back_i][fsel:-bsel])
        if bb in used:
            continue
        Mr = apply_bits(curABars[fsel:], bb)
        Mrs.append(Mr)
    print("Same rank Mrs prepared")
    Mrmat = matrix(F, [M.list() for M in Mrs])
    MRE = Mrmat.T.echelon_form()
    extra = MRE.ncols() - n * n
    QQLLL = block_matrix(
        ZZ, [[MRE], [matrix.zero(extra, n * n).augment(matrix.identity(extra) * p)]]
    )
    if QQLLL.rank() != QQLLL.nrows():
        print("not full rank, echelonize")
        QQLLL = QQLLL.echelon_form(algorithm="pari0", include_zero_rows=False)
    print("LLL", QQLLL.dimensions())
    RES = flatter(QQLLL)
    print("LLL done")
    v = next(v for v in RES if v != 0)  # first non-zero vector
    t = Mrmat.T.solve_left(v)
    print("t computed")

    ar = [(abs(mp(t * vector(mb.list()))), i) for i, mb in enumerate(Mbase)]
    ar.sort()
    for tr, i in ar[:10]:
        print(i, tr)
    tr, idx = ar[0]
    print(idx, f"{idx:0{fsel + bsel}b}")
    print(tr)

    # idx = int(input("choose idx: ").strip())
    # if idx < 0:
    #     print("abort")
    #     break

    rec_bs = [int(x) for x in f"{idx:0{fsel + bsel}b}"]
    front = rec_bs[:fsel]
    back = rec_bs[-bsel:]
    recovered[front_i : front_i + fsel] = rec_bs[:fsel]
    recovered[back_i - bsel : back_i] = rec_bs[-bsel:]
    front_i += fsel
    back_i -= bsel
    print(recovered)

    curM = (
        ~apply_bits(curABars[:fsel], front) * curM * ~apply_bits(curABars[-bsel:], back)
    )
    curABars = curABars[fsel:-bsel]

print(recovered)
msg = cry.decode(recovered)
assert cry.encrypt(pub, msg) == M
print(msg)
